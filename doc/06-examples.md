# 06 · 从零开始的完整示例

三个互相独立、可照抄运行的例子，覆盖 eBPF 三大主干用法：

1. **XDP 包计数器**——加载 + 挂载 + 读 map（入门骨架）；
2. **TC 端口改写 + 校验和更新**——改包 + 双向挂载 + netlink（ruport 核心技术的最小化版本）；
3. **ringbuf 事件上报**——tracepoint + 内核→用户事件流（观测类骨架）。

每个例子都给出：目录结构、全部源码、Makefile、运行与验证步骤。
环境要求见 doc/README.md（Ubuntu/Debian、root、clang、Go ≥ 1.24）。

---

## 示例 1：XDP 包计数器

### 1.1 目录结构

```
xdpcount/
├── Makefile
├── bpf/
│   └── count.bpf.c
└── main.go
```

### 1.2 bpf/count.bpf.c

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// 计数器：按协议号（IP protocol）分桶，0 号桶为总数
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);   // per-CPU，高频写无锁
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} pkt_cnt SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 教科书式边界检查：先证明 eth 头完整（见 doc/01 §4.3）
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 idx = 0;                 // 0 号桶：总包数
    __u64 *cnt = bpf_map_lookup_elem(&pkt_cnt, &idx);
    if (cnt)                       // lookup 可能失败，必须判空
        *cnt += 1;                 // map_value 指针原地自增

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) <= data_end) {
            idx = iph->protocol;   // 6=TCP 17=UDP 1=ICMP
            cnt = bpf_map_lookup_elem(&pkt_cnt, &idx);
            if (cnt)
                *cnt += 1;
        }
    }

    return XDP_PASS;               // 只观察，不拦截
}

char _license[] SEC("license") = "GPL";
```

### 1.3 main.go

```go
//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"golang.org/x/sys/unix"
)

// bpf2go 生成的类型（make generate 后存在；此处手写等价形状便于阅读）
type countObjects struct {
	CountPackets *ebpf.Program `ebpf:"count_packets"`
	PktCnt       *ebpf.Map     `ebpf:"pkt_cnt"`
}

func main() {
	iface := "eth0"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	// 权限与 memlock（<5.11 内核必需，5.11+ 无害）
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("memlock: %v", err)
	}

	// 加载（.o 由 make generate 产出并内嵌；此处演示手动 LoadCollectionSpec）
	spec, err := ebpf.LoadCollectionSpec("count_bpfel.o")
	if err != nil {
		log.Fatalf("parse ELF: %v", err)
	}
	var objs countObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("load(含 verifier): %v", err)
	}
	defer objs.Close()

	// 解析网卡
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("iface: %v", err)
	}

	// 挂载 XDP（SKB/generic 模式，任何网卡可用）
	lk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: ifc.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("attach xdp: %v", err)
	}
	defer lk.Close()
	log.Printf("counting packets on %s (ifindex %d), Ctrl-C 退出", iface, ifc.Index)

	// 周期性读取 per-CPU map 并聚合（见 doc/04 §5）
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			total := readCounter(objs.PktCnt, 0)
			tcp := readCounter(objs.PktCnt, unix.IPPROTO_TCP)
			udp := readCounter(objs.PktCnt, unix.IPPROTO_UDP)
			icmp := readCounter(objs.PktCnt, unix.IPPROTO_ICMP)
			fmt.Printf("\rtotal=%d tcp=%d udp=%d icmp=%d   ",
				total, tcp, udp, icmp)
		}
	}
}

// per-CPU map 读取：value 参数是 []uint64（每 CPU 一份）
func readCounter(m *ebpf.Map, key uint32) uint64 {
	var perCPU []uint64
	if err := m.Lookup(key, &perCPU); err != nil {
		return 0
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum
}
```

### 1.4 Makefile

```make
GO ?= go
CLANG ?= clang
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{s| \(/.*\)|-idirafter \1|p}')

all: build

generate:
	$(GO) run github.com/cilium/ebpf/cmd/bpf2go -cc $(CLANG) \
		-cflags "-O2 -g -Wall -Werror $(CLANG_BPF_SYS_INCLUDES)" \
		-go-package main count bpf/count.bpf.c

build: generate
	$(GO) build -o xdpcount .

clean:
	rm -f xdpcount count_bpfel.* count_bpfeb.*
```

（`-go-package main`：在仓库根目录运行，包是 main；详见 doc/03 §2。）

### 1.5 运行与验证

```bash
sudo make
sudo ./xdpcount eth0
# 另一个终端：
ping -c 3 1.1.1.1        # icmp +1/包
curl -s http://1.1.1.1   # tcp 增长

# 内核侧对照：
sudo bpftool prog show           # 看到刚加载的 xdp 程序
sudo bpftool net show            # eth0 上有 xdpgeneric
sudo bpftool map dump name pkt_cnt
```

## 示例 2：TC 端口改写（ruport 核心机制的最小版）

场景：外部访问 `本机:8080`，TC ingress 把目的端口改成 `80`，
本机 80 端口的 Web 服务“以为”自己监听在 8080；egress 再把源端口
改回 8080，客户端完全无感。这是 ruport 端口复用的最小可运行演绎。

### 2.1 目录结构

```
tcrewrite/
├── Makefile          # 同示例 1，ident 换成 rewrite，-type 不需要
├── bpf/
│   └── rewrite.bpf.c
└── main.go
```

### 2.2 bpf/rewrite.bpf.c

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <stddef.h>

#define FAKE_PORT 8080   // 对外（伪装）端口
#define REAL_PORT 80     // 本地服务真实端口

SEC("tc") // rx：把发往 8080 的包改投递给 80
int tc_ingress(struct __sk_buff *skb)
{
    const int l3_off = ETH_HLEN;
    const int l4_off = l3_off + 20;          // 固定 20B IP 头（与 ruport 一致）
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data_end < data + l4_off + sizeof(struct tcphdr))
        return TC_ACT_OK;

    struct iphdr  *ip4  = (void *)(data + l3_off);
    struct tcphdr *tcph = (void *)(data + l4_off);
    if (ip4->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    if (tcph->dest == bpf_htons(FAKE_PORT)) {
        __be16 real = bpf_htons(REAL_PORT);

        // 增量校验和：从旧值算差值，写新端口，再修 TCP checksum
        __wsum sum = bpf_csum_diff(&tcph->dest, 2, &real, 2, 0);
        bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, dest),
                            &real, 2, 0);
        bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
                            0, sum, BPF_F_PSEUDO_HDR | 0);
    }
    return TC_ACT_OK;
}

SEC("tc") // tx：把来自 80 的回包源端口改回 8080
int tc_egress(struct __sk_buff *skb)
{
    const int l3_off = ETH_HLEN;
    const int l4_off = l3_off + 20;
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data_end < data + l4_off + sizeof(struct tcphdr))
        return TC_ACT_OK;

    struct iphdr  *ip4  = (void *)(data + l3_off);
    struct tcphdr *tcph = (void *)(data + l4_off);
    if (ip4->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    if (tcph->source == bpf_htons(REAL_PORT)) {
        __be16 fake = bpf_htons(FAKE_PORT);

        __wsum sum = bpf_csum_diff(&tcph->source, 2, &fake, 2, 0);
        bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, source),
                            &fake, 2, 0);
        bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check),
                            0, sum, BPF_F_PSEUDO_HDR | 0);
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

**校验和原理**（ruport 同款，务必理解）：TCP checksum 覆盖伪头（含
源/目的 IP）+ TCP 段。改了端口后重算整个 checksum 太贵，标准做法是
**增量更新**：`new_sum = old_sum + ~old_field + new_field`。helper
`bpf_csum_diff(from, from_size, to, to_size, seed)` 算的就是
`~from + to` 的累加（16 位反码和），`BPF_F_PSEUDO_HDR` 告诉内核这次
修改会经由伪头影响校验和。IP 头 checksum 不用管——改端口不涉及 IP 头。

### 2.3 main.go（netlink 挂载部分；加载同示例 1，从略）

```go
//go:build linux

package main

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type tcAttach struct {
	filters []*netlink.BpfFilter
	clsact  *netlink.Clsact
}

func attachTC(ifindex int, ingress, egress *ebpf.Program) (*tcAttach, error) {
	// ① clsact qdisc（存在则复用）
	clsact := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := netlink.QdiscAdd(clsact); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("clsact: %w", err)
	}

	// ② filter
	mk := func(parent uint32, prog *ebpf.Program) *netlink.BpfFilter {
		return &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: ifindex,
				Parent:    parent,
				Handle:    netlink.MakeHandle(0, 1),
				Priority:  1,
				Protocol:  unix.ETH_P_ALL,
			},
			Fd: prog.FD(),
		}
	}
	fEgr := mk(netlink.HANDLE_MIN_EGRESS, egress)
	if err := netlink.FilterAdd(fEgr); err != nil {
		return nil, fmt.Errorf("egress: %w", err)
	}
	fIng := mk(netlink.HANDLE_MIN_INGRESS, ingress)
	if err := netlink.FilterAdd(fIng); err != nil {
		_ = netlink.FilterDel(fEgr)
		return nil, fmt.Errorf("ingress: %w", err)
	}
	return &tcAttach{filters: []*netlink.BpfFilter{fEgr, fIng}, clsact: clsact}, nil
}

func (t *tcAttach) release() {
	for _, f := range t.filters {
		_ = netlink.FilterDel(f)
	}
	_ = netlink.QdiscDel(t.clsact)
}
```

main 的骨架：加载两个程序 → `attachTC` → 阻塞等信号 →
`release()` → `objs.Close()`（顺序不能反，见 doc/05 §3.2）。

### 2.4 运行与验证

```bash
# 起一个只在 80 监听的服务
sudo python3 -m http.server 80 &

sudo make && sudo ./tcrewrite eth0
sudo tc qdisc show dev eth0            # clsact 出现
sudo tc filter show dev eth0 ingress   # bpf filter prio 1

curl -v http://<本机IP>:8080/          # ← 注意是 8080！能通就是改写生效
# 停止程序（信号路径）后再 curl :8080 应失败、:80 正常
```

## 示例 3：ringbuf 事件（tracepoint 捕获 openat）

### 3.1 bpf/opens.bpf.c

```c
#include "vmlinux.h"        // bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define NAME_MAX 256

struct event {
    u32 pid;
    u32 uid;
    char comm[16];
    char fname[NAME_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);       // 64KB
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;                       // 缓冲满，丢弃本条

    u64 id = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();
    e->pid = id >> 32;
    e->uid = (u32)uid_gid;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // 从用户态指针安全读文件名（tracepoint ctx->args[1] 是 const char __user *）
    bpf_probe_read_user_str(e->fname, sizeof(e->fname), (const void *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

### 3.2 main.go 的事件消费循环

```go
//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// 与 C 侧 struct event 逐字节一致（也可用 bpf2go -type event 生成）
type openEvent struct {
	PID   uint32
	UID   uint32
	Comm  [16]byte
	Fname [256]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpec("opens_bpfel.o")
	if err != nil {
		log.Fatal(err)
	}
	var objs struct {
		TpOpenat *ebpf.Program `ebpf:"tp_openat"`
		Events   *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// 挂载 tracepoint（分组, 事件名）
	lk, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TpOpenat, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer lk.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		_ = rd.Close()      // 触发 ErrClosed，唤醒下面的阻塞 Read
	}()

	fmt.Println("tracing openat() ... Ctrl-C 退出")
	for {
		rec, err := rd.Read()           // 阻塞
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf: %v", err)
			continue
		}

		var e openEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample),
			binary.LittleEndian, &e); err != nil {
			continue
		}
		fmt.Printf("pid=%-6d uid=%-4d comm=%-12s file=%s\n",
			e.PID, e.UID, cstr(e.Comm[:]), cstr(e.Fname[:]))
	}
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
```

### 3.3 运行与验证

```bash
sudo make
sudo ./opens
# 另一终端随便 cat/vim/ls 大目录，观察事件流出
cat /etc/hostname

# 对照：
sudo bpftool prog show
sudo cat /sys/kernel/debug/tracing/trace_pipe   # 若 C 里加了 bpf_printk
```

注意 Makefile 需为 clang 加 `-Ibpf`（vmlinux.h 所在目录）；
vmlinux.h 的生成命令见 doc/01 §8.2。

---

## 三个例子的共性与迁移方向

| | 例1 计数器 | 例2 端口改写 | 例3 事件 |
|---|---|---|---|
| 程序类型 | XDP | SCHED_CLS ×2 | TRACEPOINT |
| map | perCPU array | 无 | ringbuf |
| 挂载 | link.AttachXDP | netlink clsact | link.Tracepoint |
| 生命周期 | link 自动卸载 | **必须手动 FilterDel** | link 自动卸载 |
| ruport 对应 | — | `ruport_tc.bpf.c` 的极简版 | pidhide 的事件通道 |

把例 2 的“固定端口”换成“查 router_map 决定目标端口”，把例 1 的
XDP 加上魔术包解析写进 message_map——就是 ruport-go 本身。
逐行对照见下一章。
