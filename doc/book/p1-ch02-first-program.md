# 第 2 章 第一个程序：从零跑起来

> 本章目标只有一个：**让你亲手完成一次完整的闭环**——写 C、编译、
> 用 Go 加载进内核、挂到网卡、看到数字、干净收场。沿途每一步
> "背后发生了什么"都会给出图解；深入的部分（验证器细节、bpf2go、
> 生命周期责任）留了路标指向后续章节。
>
> 动手环境：Ubuntu 22.04/24.04，root 权限（见序言 0.3）。

## 2.1 目标：数一数网卡收到多少包

我们给自己定的需求非常小：

> 统计 eth0 收到的包数量，按 IP 协议号分桶（TCP 多少、UDP 多少…），
> 每秒在屏幕上刷新一次。

选这个需求不是因为它有用，而是因为它是一个**最小完整闭环**：
会用到 map（数据出来）、程序类型（XDP）、加载器（Go）、挂载
（attach）、用户态读数——往后任何 eBPF 应用都是这五件事的变奏。

架构上它长这样（也是本书反复出现的"标准三段式"）：

```
      用户态 (Go)                      内核态
  ┌─────────────────┐            ┌──────────────────────┐
  │  main.go        │            │  count.bpf.c          │
  │  ├ 加载 .o      │──bpf()──▶ │   SEC("xdp")          │
  │  ├ 挂载 XDP     │──netlink▶ │   count_packets()     │
  │  └ 每秒读 map ──┼──bpf()──▶ │        │              │
  │                 │            │        ▼ 每个包+1     │
  │                 │            │  map: pkt_cnt[256]    │
  └─────────────────┘            └──────────────────────┘
        控制面                          数据面（热路径）
```

记住这个图上的分界线：**Go 侧是控制面（冷路径，启动时干完活）；
C 侧是数据面（热路径，每个包都执行）**。整个 eBPF 工程的核心纪律
就是把尽量多的逻辑留在控制面。

## 2.2 写代码：XDP 计数器逐行讲解

建一个练习目录（建议就在本仓库下，方便复用 go.mod）：

```
playground/xdpcount/
├── count.bpf.c     ← 内核态程序（本节）
└── main.go         ← 用户态加载器（2.4 节）
```

完整内核侧代码——总共不到 40 行，我们逐块拆：

```c
// count.bpf.c —— XDP 包计数器
#include <linux/bpf.h>        // BPFMAP类型/助手声明所需的核心定义
#include <bpf/bpf_helpers.h>  // SEC()/map定义宏/bpf_map_lookup_elem 等
#include <linux/if_ether.h>   // struct ethhdr
#include <linux/ip.h>         // struct iphdr

// ---------- ① map 定义 ----------
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);  // 数组：key 即下标
    __type(key, __u32);                // 协议号 0~255 恰好当下标
    __type(value, __u64);              // 计数器
    __uint(max_entries, 256);          // IP 协议号空间
} pkt_cnt SEC(".maps");

// ---------- ② 程序 ----------
SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;      // ③ 包起始地址
    void *data_end = (void *)(long)ctx->data_end;  //    包结束地址

    // ④ 先证明"以太网头完整"，再访问（第 3 章详解为什么）
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;               // 不完整就放行，别逞强

    // ⑤ 总计数：0 号桶
    __u32 idx = 0;
    __u64 *cnt = bpf_map_lookup_elem(&pkt_cnt, &idx);
    if (cnt)                           // lookup 可能失败，必须判空
        *cnt += 1;                     // ⑥ 直接改内核内存（原地写！）

    // ⑦ 协议分桶：只有 IPv4 才有"协议号"可看
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) <= data_end) {       // 再证明 IP 头完整
            idx = iph->protocol;      // 6=TCP 17=UDP 1=ICMP ...
            cnt = bpf_map_lookup_elem(&pkt_cnt, &idx);
            if (cnt)
                *cnt += 1;
        }
    }

    return XDP_PASS;                   // ⑧ 我们只观察，永远放行
}

// ---------- ⑨ 许可证 ----------
char _license[] SEC("license") = "GPL";
```

九个要点逐个说透：

**① BTF 风格的 map 定义**。`SEC(".maps")` 告诉加载器"这是一个
map 描述"，字段用 `__uint/__type` 宏声明。它是现代写法（老式
`bpf_map_def` 平铺结构已弃用），加载器读 `.o` 里的 BTF 信息就能
建表——**map 不是 C 变量，它只是一份"建表说明书"**，真正的表
在加载时由内核创建（见 2.7 图解）。

**② `SEC("xdp")`**：section 名是程序与加载器之间的契约——
加载器靠它判断"这段代码是什么类型的程序、能挂到哪"（完整对照表
在附录 A）。函数名 `count_packets` 会成为内核里这条程序的正式名字
（`bpftool prog show` 可见）。

**③ 参数 `struct xdp_md *ctx`**：XDP 程序的**唯一输入**，本质是
两个地址（包首/包尾）加上网卡元信息。注意 `data` 是"包的第一个
字节"，**XDP 时连 skb 都没有**，你看到的就是驱动刚收进内存的裸包
——这正是 XDP 快的原因（第 7 章展开）。

**④⑥ 两条铁律初照面**：读包内容前必须有"紧邻的边界检查"（第 3
章会用验证器状态推演解释为什么这是强制的）；`bpf_map_lookup_elem`
返回的是**指向内核里那份 value 的指针**，`*cnt += 1` 是原地修改
内核内存——没有任何拷贝。这两个特征是 eBPF 程序最不同于普通 C 的
地方。

**⑨ license**：部分 helper 是 GPL-only，网络程序无脑写 GPL 即可，
省得排查"为什么这个 helper 不让用"。

> 顺带埋个伏笔：这个计数器在多核机器上**有轻微计数丢失**
> （多个 CPU 同时 `+= 1` 竞争同一格）。这是刻意保留的缺陷——
> 第 5 章用 per-CPU map 修复它，让"问题驱动"落地。

## 2.3 编译：clang 到底产出了什么

一条命令编译：

```bash
clang -O2 -g -Wall -target bpf -c count.bpf.c -o count.bpf.o
```

- `-target bpf`：目标不是 x86 而是 BPF 虚拟机（产物是 BPF 指令集
  的 ELF，不是本机可执行文件）；
- `-g`：保留**调试与类型信息（BTF）**——CO-RE 和后面很多工具的
  依赖，别省；
- `-O2`：没有优化时验证器面对的指令会又臭又长。

> 若报 `fatal error: 'linux/bpf.h' file not found`：BPF 目标不
> 搜索发行版多架构头文件目录，需要追加 `-idirafter` 系统路径
> （一行 shell 可自动推导，命令与原因详见第 14 章 14.4.5）。

产物 `count.bpf.o` 是一个**普通 ELF 文件**，用 `llvm-readelf -S`
看它的段（输出裁剪）：

```
  [Nr] Name              Type
  [ 1] .text             PROGBITS    ← count_packets 的 BPF 指令
  [ 4] .BTF              PROGBITS    ← 类型信息：map 定义、函数签名
  [ 5] .BTF.ext          PROGBITS    ← 行号/重定位附属信息
  [10] license           PROGBITS    ← "GPL\0"
```

`.o` 的内部结构和"谁消费哪个段"，一张图说清：

```
              count.bpf.o（ELF）                消费者
  ┌─────────────────────────────────┐
  │ .text   BPF 字节码               │──▶ 内核：验证→JIT→执行
  │ .BTF    map 定义/类型/函数信息    │──▶ 加载器：据此建 map、
  │         （我们写的 struct{}）     │     生成 Go 侧类型
  │ license "GPL"                    │──▶ 内核：GPL-only helper 准入
  └─────────────────────────────────┘
  注意：map 本身不在 .o 里！里面只有"建表说明书"。
```

**用 30 秒看一眼字节码**（值得养成习惯，第 3 章读验证器日志的
基础）：

```bash
llvm-objdump -d --no-show-raw-insn count.bpf.o
```

输出里每行形如 `r1 = *(u32 *)(r1 + 0)`——BPF 汇编。现在看不懂
没关系，第 3 章推演验证器时会逐行回来。

## 2.4 加载与挂载：Go 程序把它送进内核

写加载器之前，先明确它要替我们干**四件事**：

```
   main.go 的职责（本节依次实现）
   ┌────────────────────────────────────────────────┐
   │ 1. 读 .o 并解析（CollectionSpec）               │
   │ 2. 让内核创建 map + 加载并验证程序（LoadAndAssign）│
   │ 3. 挂载到 eth0（AttachXDP）                     │
   │ 4. 周期读 map / 退出时清理                       │
   └────────────────────────────────────────────────┘
```

完整 `main.go`（教学版，手写加载路径；bpf2go 的生产做法 2.4.5 预告）：

```go
//go:build linux

package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// 告诉库"把 .o 里叫这些名字的对象绑定到我的字段上"
type countObjects struct {
	CountPackets *ebpf.Program `ebpf:"count_packets"` // 程序
	PktCnt       *ebpf.Map     `ebpf:"pkt_cnt"`       // map
}

func main() {
	// 0) <5.11 内核需要解除 memlock；5.11+ 此调用无害
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 1) 读入并解析 ELF
	spec, err := ebpf.LoadCollectionSpec("count.bpf.o")
	if err != nil {
		log.Fatalf("parse ELF: %v", err)
	}

	// 2) 加载：内核此刻创建 map + 验证 + JIT 程序
	var objs countObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("load: %v", err) // ← 程序有问题时会在这里被拒（第3章）
	}
	defer objs.Close()

	// 3) 挂载到网卡（generic/SKB 模式：任何网卡可用）
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}
	lk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer lk.Close()

	// 4) 每秒读一次 map
	tick := time.NewTicker(time.Second)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	log.Printf("counting on %s (ifindex=%d), Ctrl-C 退出", iface.Name, iface.Index)
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			var total, tcp, udp uint64
			readCounter(objs.PktCnt, 0, &total)
			readCounter(objs.PktCnt, 6, &tcp)   // IPPROTO_TCP
			readCounter(objs.PktCnt, 17, &udp)  // IPPROTO_UDP
			log.Printf("total=%-8d tcp=%-8d udp=%-8d", total, tcp, udp)
		}
	}
}

func readCounter(m *ebpf.Map, key uint32, out *uint64) {
	if err := m.Lookup(key, out); err != nil {
		*out = 0 // ARRAY 读不到只可能是 key 越界，兜底置 0
	}
}
```

几个关键点展开：

**struct tag 绑定**：`ebpf:"count_packets"` 是"按名取货"——
`LoadAndAssign` 只把被引用的对象加载进内核，`.o` 里没人引用的
东西根本不会创建（第 14 章会讲 bpf2go 如何把这层手写消除）。

**AttachXDP 之后发生了什么**：数据面与控制面从此分家——Go 程序
哪怕睡死，计数照跑不误；它只负责"读数展示"。**link 对象代表挂载
关系本身**，`lk.Close()` 即卸载（`defer` 保证退出干净）。

**为什么不直接说 bpf2go**：手写一遍，你才能看清"加载器"这个
角色的本职；生产代码当然是生成器代劳——**2.4.5 预告**：仓库根目录
`make` 跑的就是 bpf2go 流程：C 侧相同，Go 侧的
`LoadCollectionSpec + struct` 被生成的 `LoadXxxObjects` 取代，
`.o` 还被 `go:embed` 进二进制（单文件分发）。完整工作流第 14 章。

## 2.5 跑起来，看见结果

```bash
# 编译 C（在 xdpcount 目录）
clang -O2 -g -Wall -target bpf -c count.bpf.c -o count.bpf.o
# 编译并运行 Go
go mod init xdpcount && go get github.com/cilium/ebpf@v0.22.0
go run . 

# 另一个终端制造流量
ping -c 3 1.1.1.1          # icmp+1×3, total+1×3
curl -s https://example.com  # tcp 明显增长
```

预期输出：

```
2026/08/28 10:00:01 counting on eth0 (ifindex=2), Ctrl-C 退出
2026/08/28 10:00:02 total=57       tcp=12       udp=4
2026/08/28 10:00:03 total=104      tcp=41       udp=6
```

**内核侧对照**（信任但要验证）：

```bash
sudo bpftool prog show            # 看到名字 count_packets、类型 xdp
sudo bpftool map show name pkt_cnt
sudo bpftool map dump name pkt_cnt   # 0/6/17 号桶的原始值
```

`bpftool map dump` 显示的数字与 Go 读到的**逐位一致**——因为读的
是同一份内核内存。这种"两处对照"是以后排障的基本功。

## 2.6 收摊：卸载与清理

Ctrl-C 触发 return → `defer` 链依次执行：

```
 lk.Close()   ──▶ 摘除 XDP 挂载（网卡回到无程序状态）
 objs.Close() ──▶ 关闭 map 与程序的 FD
                  └▶ 内核引用计数归零 → map（含全部计数）与程序销毁
```

验证真的干净了：

```bash
sudo bpftool prog show   # count_packets 消失
sudo bpftool map show    # pkt_cnt 消失
```

一个重要的推论藏在最后一步：**map 的生命周期绑定 FD 而非数据**。
进程退出、FD 关闭、数据就没了——想让数据"活过进程"，需要 pin
（第 14 章 14.4）；反过来，**tc 挂载的经典 filter 不遵循这个规则、
会残留**，是新手大坑（第 8/11 章）。

## 2.7 鸟瞰：刚才每一步在内核里发生了什么

把全章动作串成一张大图——**它就是全书的总地图**，后续章节都在
放大其中某一块：

```
 你（写代码）                clang                    内核                    事件
 ─────────────────────────────────────────────────────────────────────────────────
 count.bpf.c ─compile─▶ count.bpf.o
                            │
              main.go 读 .o │ (解析ELF/BTF)
                            ▼
                     bpf(BPF_MAP_CREATE) ───▶ [map pkt_cnt 创建]        ┐
                     bpf(BPF_PROG_LOAD)  ───▶ [验证器审查] ──拒绝──▶ 报错│
                            │                 │通过                     │ 第3章
                            │                 ▼                        │ 放大
                            │              [JIT 编译为本机码]            │
                     netlink(IFLA_XDP) ──▶ [eth0 挂上程序]              ┘
                            │                                            ┐
                            │              每个包到达网卡                 │
                            │                 ──▶ [执行 JIT 代码]        │ 第7章
                            │                 ──▶ map 原子格 +1          │ 放大
                            │                                            ┘
                     bpf(MAP_LOOKUP)  ◀──── 读出计数                    ┐
                     （每秒一次，Go 侧）                                 │ 第4章
                                                                              │ 放大
 lk.Close()/objs.Close() ──▶ 摘挂载/销毁对象                            ┘
```

对号入座：第 2 章跑通了**整条线**；第 3 章钻进"验证器审查"；
第 4 章钻进 map 与读写语义；第 7 章钻进 XDP 与包路径；第 14 章把
左边的 main.go 换成生产姿势。

## 2.8 小结与练习

**小结**：eBPF 应用的标准三段式 = C 侧数据面（SEC/map/helper/
边界检查/license）+ Go 侧控制面（解析/加载/挂载/读数/清理）+
两者之间的 map。内核侧拿到的 map 指针可**原地写**、读包前必须
**先证明后访问**、退出时 **link 管挂载、Close 管生命周期**——
这三条手感比任何 API 都重要。

**练习**：
1. 只统计 TCP：把总计数桶去掉，只留协议分桶，观察 6 号桶；
2. 把 `return XDP_PASS` 改成 `return XDP_DROP`（只对 TCP 包），
   重新加载后用 `curl` 验证"防火墙"生效——注意 ssh 会不会断，
   想清楚再动手；
3. 用 `sudo bpftool prog dump xlated name count_packets` 看你的
   程序被编译成的 BPF 指令，找到边界检查对应的那几条（为第 3 章
   热身）；
4. 思考题：把 `max_entries` 改成 16 会发生什么？动手验证你的预测。
