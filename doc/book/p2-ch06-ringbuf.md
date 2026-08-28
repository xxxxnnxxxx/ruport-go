# 第 6 章 别再轮询了：事件驱动

> 到目前为止，用户态都是"定时去拉"（每秒读一次计数）。拉模式的
> 三宗罪：延迟（最坏一个周期）、空转（没事件也耗 CPU）、粒度
> 两难（频率高则浪费、低则迟钝）。本章换成"内核主动推"——
> 先看两代事件通道的更替史（perf→ringbuf），再完整实现一个
> openat 文件访问监控系统，最后讨论"不丢事件"的工程艺术。
> 这个 openat 监控也正是第 1 章那个工单的另一半答案。

## 6.1 从轮询到推送：两代事件通道

### 6.1.1 为什么轮询撑不住

把第 4 章的 Top 统计改成"每次 openat() 都上报"，需求立刻变形：

```
 轮询（拉模式）
 ┌────────┐  每秒 N 次      ┌────────┐
 │ 用户态 │◀───────────────│  map   │  事件与事件之间没有边界：
 └────────┘   读全表+对账    └────────┘  只能看"存量"，看不见"过程"
   延迟≥轮询间隔；空转耗CPU；高频事件互相覆盖
```

事件的本义是"**发生即送达、每条独立、有序**"。map 的 key-value
模型天生不是干这个的——需要专门的**环形缓冲**容器。

### 6.1.2 第一代：perf event array（4.1+）的遗产

2015 年起，事件走 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`：每个 CPU 一条
独立环形缓冲，内核侧 `bpf_perf_event_output()` 写入，用户态 mmap
轮询各区。它的历史贡献巨大，但三个结构性缺陷随规模暴露：

```
 perf event array（每核一个环）
 CPU0 ▶ ┌─░░░░░░─┐   时间
 CPU1 ▶ ┌─░░░░░░─┐   ▼   ① 跨核乱序：先发生在CPU1的事件
 CPU2 ▶ ┌─░░░░░░─┐       可能后被读到
        （每环独立）      ② 用户态要为每核建 reader、聚合复杂
                          ③ 尺寸按核数×buffer 预算，浪费
```

### 6.1.3 第二代：ringbuf（5.8+）的革新

`BPF_MAP_TYPE_RINGBUF` 用**一个全局环**取代每核一环，配合
reserve/submit 两段式写入实现零拷贝与有序：

```
 ringbuf（单环多生产者）
                ┥ reserve：在环上预定一段长度，拿到可直接写的指针
  内核程序 ──▶  ┃   struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
                ┃   e->pid = ...;          ← 直接写进环内存（零拷贝）
                ┥ submit：发布；用户态 ringbuf.Reader 立即可读
 ┌────────────────────单 一 环 形 缓 冲────────────────────┐
 │ …已消费│…可读事件×3│…生产者预留中│…空闲…               │
 └──────────────────────────────────────────────────────────┘
   保序（全局时钟推进）· 用户态一个 reader 搞定 · mmap 共享零拷贝
```

选型一句话：**新内核（5.8+）一律 ringbuf；要兼容老内核才用 perf
event array**。两者的 Go 侧 API（`ringbuf.NewReader` vs
`perf.NewReader`）形状接近，迁移成本低。

## 6.2 动手：openat 监控系统（完整项目）

需求（第 1 章工单的正式解法）：**记录系统上所有进程打开的文件**，
实时打印"谁、打开了什么"。三步走：C 侧事件生产者、Go 侧消费者、
运行验证。

### 6.2.1 C 侧：tracepoint + ringbuf

```c
// openat.bpf.c
#include "vmlinux.h"          // bpftool btf dump file /sys/kernel/btf/vmlinux \
                               //   format c > vmlinux.h（第 12 章详解）
#include <bpf/bpf_helpers.h>

#define NAME_MAX 256

struct event {                 // ← 跨边界契约：pack 语义由 BTF 保证
    __u32 pid;
    __u32 uid;
    char comm[16];             // 进程名
    char fname[NAME_MAX];      // 打开的文件路径
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);   // 64KB，必须是 2 的幂
} events SEC(".maps");

// 挂到 openat 系统调用的"入口 tracepoint"（稳定接口，第 10 章展开）
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    // ① 预订：缓冲满时返回 NULL——主动丢弃，绝不能阻塞内核路径
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // ② 填充（写的就是环内存本身，零拷贝）
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // 第 2 个参数是 const char __user *filename（用户态指针！）
    // 用专用 helper 安全拷入（第 10 章 kprobe 章会再遇到它）
    bpf_probe_read_user_str(e->fname, sizeof(e->fname),
                            (const void *)ctx->args[1]);

    // ③ 发布：此瞬间用户态即可读到
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

三个新面孔点评：

- **tracepoint**：`syscalls:sys_enter_openat` 是内核**静态埋点**，
  参数布局稳定（`ctx->args[]`），跨版本安全——选它而不是 kprobe
  的理由第 10 章系统讲；
- **reserve/submit 两段式**：先占坑再填数据再发布——相比
  `bpf_ringbuf_output`（一次拷贝入环），省一次内存拷贝；且"占坑
  失败（满）"时我们**主动丢弃本条**，内核路径永不被拖住；
- **`bpf_probe_read_user_str`**：用户态指针不能直接解引用（第 3 章
  验证器规则），必须用 helper 安全拷贝。

### 6.2.2 Go 侧：加载、挂载、消费循环

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

// 与 C 侧 struct event 逐字节一致（生产代码用 bpf2go -type 生成）
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

	spec, err := ebpf.LoadCollectionSpec("openat.bpf.o")
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

	// 挂载 tracepoint：分组 "syscalls"，事件 "sys_enter_openat"
	// （名字即 /sys/kernel/tracing/events 下的目录路径）
	lk, err := link.Tracepoint("syscalls", "sys_enter_openat",
		objs.TpOpenat, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer lk.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	// Ctrl-C 时先关 reader：唤醒阻塞中的 Read，让 goroutine 退出
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		_ = rd.Close()
	}()

	fmt.Println("tracing openat() ... Ctrl-C 退出")
	for {
		rec, err := rd.Read()     // 阻塞等待下一个事件
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return          // 被 Close 唤醒 = 正常退出
			}
			log.Printf("ringbuf: %v", err)
			continue
		}

		// rec.RawSample 就是 C 侧 bpf_ringbuf_submit 的那块字节
		var e openEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample),
			binary.LittleEndian, &e); err != nil {
			continue
		}
		fmt.Printf("pid=%-6d uid=%-5d %-12s %s\n",
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

### 6.2.3 编译运行

```bash
# 生成 vmlinux.h（一次性）+ 编译
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -Wall -target bpf -c openat.bpf.c -o openat.bpf.o
go run .

# 另一个终端
cat /etc/hostname          # 立即看到一条事件
vim /tmp/test.txt          # 每次打开都有一条
```

预期输出：

```
tracing openat() ... Ctrl-C 退出
pid=512    uid=0    cat          /etc/hostname
pid=520    uid=1000 vim          /tmp/test.txt
pid=521    uid=1000 vim          /etc/passwd
```

**回头看第 1 章的工单**："谁在读 /etc/passwd"——把 `e->fname` 的
拷贝换成"比较后命中才上报"，十几行 C 就是完整答案。ruport 的
message_map（拉模式）与此处的 ringbuf（推模式）是同一内核程序里
并存的两条通道：**事件用推、状态用拉**（第 17 章会看到它们如何
分工）。

## 6.3 不丢事件的艺术

ringbuf 是环形缓冲——**消费跟不上生产时，旧事件会被覆盖**。
工程上三层防御：

1. **容量预算**：`max_entries` 按"峰值速率 × 可容忍的离线时间"
   定，且必须是 2 的幂。例：1 万事件/秒、允许程序卡 5 秒 →
   5 万事件余量 → 取 64KB~128KB 起步，事件大则相应放大；
2. **观测拥塞**：`Record.Remaining` 字段反映"读完这条后环里还压着
   多少字节"——它持续走高就是消费跟不上的先兆；同时可以做一个
   per-CPU 计数器统计 `bpf_ringbuf_reserve` 失败次数（丢弃率）；
3. **消费侧纪律**：读循环里**不做慢操作**（写库/发网络都丢给
   channel + 独立 goroutine）；必要时多进程/多 reader 分摊。

```
 生产过快的三种结局（取决于你的设计）
 ┌────────────┬────────────────────────────────────────┐
 │ reserve失败 │ 内核侧拿到NULL → 你选择丢弃并计数 ✅可控 │
 │ 环覆盖      │ 用户态还没读就被新事件碾过 → 无声丢失 ⚠ │
 │ 背压        │ ringbuf 没有背压！内核路径绝不能等用户态 │
 └────────────┴────────────────────────────────────────┘
 结论：容量靠预算、丢失靠观测、消费靠纪律
```

顺带一句 queue（第 5 章）与 ringbuf 的最终分工：queue 逐条独立、
满则报错（适合"每条都不能丢、速率可控"的管理面消息）；ringbuf
高吞吐、可覆盖（适合"尽力而为、洪峰可弃"的观测面事件流）。

## 6.4 小结与练习

**小结**：事件三属性（即达/独立/有序）决定必须用专用通道；perf
array（每核一环、跨核乱序）→ ringbuf（单环、reserve/submit 零拷贝、
保序）是 5.8 的关键换代；消费侧标准循环 = 阻塞 Read + ErrClosed
优雅退出 + RawSample 解码；不丢事件靠容量预算、Remaining 观测与
消费纪律——ringbuf 没有背压，内核侧永远"丢弃而不等待"。

**练习**：
1. 给 6.2 加过滤：只上报 `uid==0` 的事件（在 C 侧 reserve **之前**
   判断——想想为什么必须在之前）；
2. 增加丢弃计数：per-CPU 计数器记录 `bpf_ringbuf_reserve==NULL`
   的次数，Go 侧每秒打印丢弃率；用 `dd if=/dev/zero of=/dev/null
   bs=1 count=1000000` 之类的高频 open 制造压力；
3. 把 `max_entries` 故意调成 4KB，复现覆盖丢失，观察 Remaining
   与解码异常（乱包）——感受容量预算的意义；
4. 思考题：为什么 `bpf_ringbuf_reserve` 失败时程序选择"丢弃"而
   不是"重试"？（提示：回忆第 1 章的 LKM 风险模型与第 3 章
   "验证器不做运行时假设"——内核路径里允许什么？）

---

第二篇完结：数据能漂亮地出来了。第三篇回到 eBPF 的主战场——
把整条网络栈重新走一遍，在你想要的任何一刀的位置下刀。
