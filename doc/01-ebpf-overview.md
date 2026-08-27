# 01 · eBPF 技术背景

目标：读完本章，你能回答——eBPF 程序在内核里到底是怎么跑起来的、验证器
为什么老是拒绝我的程序、map 和程序类型分别是什么、CO-RE/vmlinux.h 解决
什么问题、以及 cilium/ebpf 与 libbpf 的分工。本章是后面所有章节的地基。

---

## 1. eBPF 是什么

eBPF（extended Berkeley Packet Filter）是 Linux 内核提供的**可编程沙箱**：
让你把一小段经过静态验证的字节码安全地注入内核，在特定事件（收到一个包、
触发一次系统调用、执行一个内核函数……）发生时由内核执行它，而不需要
写内核模块、不需要修改内核源码、不需要重启。

演化脉络（理解定位用）：

- 1992：cBPF，经典 BSD 包过滤器，`tcpdump` 的表达式就是编译成 cBPF。
- 2014：Linux 3.18 合入 eBPF 初版（Alexei Starovoitov），把 32 位过滤器
  虚拟机扩展成 64 位、通用化的内核虚拟机。
- 2018 前后：XDP/TC 等网络挂载点、BPF Type Format（BTF）、libbpf 逐步成熟，
  eBPF 从“网络过滤”变成“内核可编程平台”（观测、安全、网络、调度）。
- 现在：Cilium（数据面）、Falco/Tracee（安全观测）、systemd、各类
  性能分析器都在其上构建。

eBPF 的安全模型是两段式的：**加载前静态验证 + 运行时受限执行**。

1. 静态验证：字节码在进入内核前被 *verifier*（验证器）逐指令模拟执行，
   证明它一定会安全终止、不会越界访问内存、不会把内核指针泄露给用户态。
2. 受制执行：验证通过后由 JIT 编译成本机指令执行；程序不能随意调用内核
   函数（只能调用白名单 helper）、不能睡眠/阻塞、栈固定 512 字节、
   指令数有上限。

## 2. 执行流程全景

一条 eBPF 程序从源码到生效的完整链路：

```
 ruport_xdp.bpf.c (C 源码)
      │  clang -target bpf -O2 -c
      ▼
 ruport_xdp.bpf.o (ELF：字节码 + map 定义 + BTF + 重定位信息 + license)
      │  用户态加载器解析 ELF（libbpf 或 cilium/ebpf）
      ▼
 bpf(BPF_PROG_LOAD) 系统调用（字节码、license、程序类型、日志缓冲区）
      │  内核：验证器模拟执行 → JIT 生成本机码
      ▼
 Program FD（一个指向内核中已加载程序的文件描述符）
      │  挂载：bpf(BPF_PROG_ATTACH) / netlink(tc) / perf_event(kprobe)...
      ▼
 事件驱动执行（每个到达网卡的包 / 每次 tracepoint 命中）
```

用户态的“加载器”要做的事：编译 C、解析 ELF 段、创建 map、重定位 map
引用、执行 CO-RE 重定位、发起 `BPF_PROG_LOAD`、挂载。libbpf 是 C 加载器，
**cilium/ebpf 是纯 Go 的等价物**——它自己解析 ELF、自己发 `bpf()` 系统调用，
不依赖 libbpf、不依赖 cgo。

与 `bpf()` 系统调用相关的子命令（cilium/ebpf 内部都在用，排障时
`strace` 能看到）：`BPF_MAP_CREATE`、`BPF_MAP_UPDATE_ELEM`、
`BPF_MAP_LOOKUP_ELEM`、`BPF_MAP_LOOKUP_AND_DELETE_ELEM`、
`BPF_PROG_LOAD`、`BPF_PROG_ATTACH`/`DETACH`、`BPF_LINK_CREATE`、
`BPF_OBJ_PIN`/`BPF_OBJ_GET`、`BPF_BTF_LOAD`、`BPF_RAW_TRACEPOINT_OPEN`。

## 3. eBPF 虚拟机

### 3.1 寄存器与指令

eBPF 是寄存器机（cBPF 是栈机）：

- **11 个 64 位寄存器** `R0`–`R10`：
  - `R0`：存放 helper 调用返回值与**程序返回值**（如 XDP 的动作码）。
  - `R1`–`R5`：函数调用参数（调用 helper 时依次传参），调用后失效。
  - `R6`–`R9`：被调用方保存（callee-saved），跨 helper 调用仍有效。
  - `R10`：只读栈帧指针，指向 512 字节栈顶。
- 定长 8 字节指令，结构 `{op:8, dst_reg:4, src_reg:4, off:16, imm:32}`。
  指令类别：`BPF_LD/LDX`（load）、`BPF_ST/STX`（store）、`BPF_ALU`（32 位
  运算）、`BPF_ALU64`（64 位运算）、`BPF_JMP/JMP32`（跳转）、`BPF_CALL`
  （调 helper）、`BPF_EXIT`（返回）。
- 64 位运算显式后缀（`BPF_MOV` vs `BPF_MOV32` 等），C 里写 `x = y` 还是
  `x = (u32)y` 会生成不同指令——这是验证器报“类型不匹配”的常见来源。

### 3.2 程序的输入：context

每个程序类型的入口第一个参数（`R1`）是内核准备的 **context** 结构，
内容随程序类型而异：

| 程序类型 | context | 你能用它做什么 |
|---|---|---|
| XDP | `struct xdp_md *` | `data`/`data_end` 包边界、调整包头（`bpf_xdp_adjust_head`）、返回动作 |
| TC (`SCHED_CLS`) | `struct __sk_buff *` | 抽象后的 skb 视图：读写包字节、`mark`、优先级、queue mapping |
| tracepoint | `struct trace_event_raw_*` | 该 tracepoint 的参数现场 |
| kprobe | `struct pt_regs *`（按寄存器取参） | 探测函数的寄存器状态 |
| fentry/fexit | 直接是目标函数原型 | 类型安全的参数/返回值访问 |

在 XDP/TC 里取包内容，都必须先做边界检查，见 §4.3。

### 3.3 调用与尾调用

- **helper 调用**：`BPF_CALL` + imm 为 helper 编号。helper 集合按程序类型
  白名单开放（`bpf_helper_defs.h` 中 200 个左右）。例如 TC 可用
  `bpf_skb_store_bytes`/`bpf_l4_csum_replace`，XDP 可用
  `bpf_xdp_adjust_head`，两者都可用 `bpf_map_update_elem`。
- **BPF-to-BPF 调用**（kernel 4.16+）：C 函数直接调用，验证器内联或生
  成内核内函数调用，深度上限 8。
- **尾调用** `bpf_tail_call(ctx, prog_array, index)`：跳转到另一个程序，
  **不复用栈**，深度上限 33。原 ruport 的 pidhide 就用它实现“分段循环扫描”
  getdents64 缓冲区。
- **有界循环**：kernel 5.3+ 才允许循环，且验证器必须能证明循环变量有界。
  老内核上的惯用法是 `#pragma unroll` 或尾调用自跳。

### 3.4 栈与数据存放

- 栈 512 字节，编译器分配局部变量；放不下的大缓冲必须放 map 或
  per-CPU 区域。
- `map_value`、`ctx`、`pkt`（包指针）在验证器里都是带类型的指针，
  对它们做算术运算有严格规则（见 §4.3）。

## 4. 验证器（verifier）——理解它就理解了一半的 eBPF 报错

### 4.1 工作方式

验证器对字节码做**符号执行**：

1. 从入口开始按控制流图（CFG）探索所有路径（DFS），每条边到达时计算
   寄存器/栈的抽象状态（类型 + 取值区间）。
2. **状态剪枝（state pruning）**：若某指令再次到达时寄存器状态与已记录
   状态等价，停止探索该分支——这是能处理循环和分支爆炸的关键。
3. 复杂度上限：默认最多 100 万个验证状态（`BPF_COMPLEXITY_LIMIT`），
   指令数上限 100 万条（kernel 5.2 前 4096 条）。

### 4.2 它要证明的性质

- 所有寄存器在使用前已初始化（读未初始化寄存器 → `invalid read from stack`）。
- 所有指针解引用都在合法范围内（越界 → `R1 offset is outside of the packet`）。
- 指针不会被当成整数返回给用户态或存进可被用户态读取的地方
  （→ `R0 leaks addr into map`）。
- 程序必然终止：无环（≤5.2）或循环可证明有界（5.3+）。
- 访问 helper 的参数个数/类型与该 helper 的原型匹配。
- 对 *直接包访问*（`data`/`data_end` 派生的指针）：每一次读取之前，验证器
  都必须能看到一条**显式的比较**，形如
  `if (ptr + len > data_end) return X;`。

### 4.3 为什么包解析代码长那样

以 ruport XDP 中的典型段落为例：

```c
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)   // 先证明 eth+sizeof(*eth) 在包内
    return XDP_PASS;                 // 不在就直接放行，别让验证器猜

struct iphdr *iph = (struct iphdr *)(eth + 1);
if ((void *)(iph + 1) > data_end)    // 再证明 IP 头完整
    return XDP_PASS;
```

验证器**不做代数推理**：它不知道 `eth + 1 > data_end` 为假时
`iph + 1` 是否越界，除非比较就写在解引用紧邻之前。变长字段（IP 选项、
TCP 头长）必须重新用 `iph->ihl * 4` 这类动态偏移再检查一次，ruport 中
`pdata`（TCP payload 起点）之后的每次读取前都有对应的长度判断，包括
`(data_end - (void*)pdata) < 12 + sizeof(struct Message)` 这种“一次证明
剩余全部长度”的写法。

经验法则：**读完 verifier 报错的那条指令，往上找最近一次边界检查**，
十有八九是检查缺失、长度算错、或检查与读取之间插入了会破坏状态追踪的
操作（如把指针存进了栈又被覆盖）。

### 4.4 读懂一份 verifier 日志

加载失败时内核回吐逐指令日志（cilium/ebpf 会原样放进错误信息，
`ProgramOptions.LogLevel` 可控制细度，见 02 章）：

```
0: (61) r2 = *(u32 *)(r1 +0)        ; 从 ctx 偏移 0 加载 —— r1 是 xdp_md*
1: (61) r3 = *(u32 *)(r1 +4)        ; data_end
2: (bf) r1 = r2                     ; r1 = data
3: (07) r1 += 14                    ; r1 += sizeof(ethhdr)
4: (2d) if r1 > r3 goto pc+10       ; 边界检查点
 R1=inv(id=0) R2=pkt(id=2,...) ...  ; 各分支到达时的寄存器状态
...
invalid access to packet, off 14 size 14, R2(id=2, off=14, r=0)
```

要点：`R2=pkt(off=14, r=0)` 表示“这是一个包指针，允许的读窗口从偏移 14
开始、可用字节数 0”——`r=0` 时再读就是越界。修法就是补检查。

## 5. JIT 与性能

验证通过后，JIT 把字节码翻成 x86-64/ARM64 本机码（现代内核默认开启，
`/proc/sys/net/core/bpf_jit_enable`）。执行成本接近手写内核代码，比
解释执行（`CONFIG_BPF_JIT_ALWAYS_ON` 之前的回退路径）快一个数量级。
对网络路径（XDP）来说，性能敏感点通常在：包解析的分支数、map 访问次数、
是否使用 per-CPU map（避免跨 CPU 争用）。用 `bpftool prog show` 的
`run_time_ns/run_cnt`（需开启 `bpf_stats_enabled`）可量化。

## 6. 程序类型与挂载点

完整列表见内核 `include/uapi/linux/bpf.h` 的 `bpf_prog_type`。与本项目
关系最密的：

| 类型 | 用途 | 挂载方式 | 典型 context/返回值 |
|---|---|---|---|
| `BPF_PROG_TYPE_XDP` | 最早收到包的位置（驱动层） | XDP attach（netlink/ifindex） | `xdp_md`；返回 `XDP_PASS/DROP/TX/ABORTED/REDIRECT` |
| `BPF_PROG_TYPE_SCHED_CLS` | TC 分类器，收发两个方向 | clsact qdisc + filter（netlink）或 tcx（6.6+） | `__sk_buff`；返回 `TC_ACT_OK/SHOT/REDIRECT...` |
| `BPF_PROG_TYPE_TRACEPOINT` | tracepoint 探针 | perf_event 打开 | tracepoint 参数结构 |
| `BPF_PROG_TYPE_KPROBE` | 内核函数探针 | perf_event/kprobe 注册 | `pt_regs` |
| `BPF_PROG_TYPE_TRACING` | fentry/fexit/freplace，BTF 化的安全探针 | `BPF_LINK_CREATE`（attach_btf_id） | 目标函数原型 |
| `BPF_PROG_TYPE_LSM` | Linux 安全模块钩子 | `BPF_LINK_CREATE`（lsm hook） | 各钩子原型 |
| `BPF_PROG_TYPE_SOCKET_FILTER` | socket 级过滤 | `SO_ATTACH_BPF` | `__sk_buff` |
| `BPF_PROG_TYPE_CGROUP_SKB/...` | cgroup 网络控制 | cgroup v2 attach | 视类型 |

**section 名与类型的映射**：libbpf/cilium-ebpf 都按 ELF section 名推断
程序类型（`"xdp"` → XDP，`"tc"`/`"classifier"` → SCHED_CLS，
`"tracepoint/..."`、`"kprobe/..."` 等）。ruport 的 C 代码用 `SEC("xdp")`
与 `SEC("tc")`，cilium/ebpf 加载时据此设定 `ProgramSpec.Type`；也可以在
Go 侧显式改写 `ProgramSpec.Type`/`AttachTo` 后再加载。

**license**：使用 GPL-only helper（如 `bpf_probe_write_user`、多数 tracing
helper）的程序必须声明 `char _license[] SEC("license") = "GPL";`，否则加载
报 `EINVAL`。网络类程序一般也照抄 GPL，避免踩到隐藏的 GPL-only helper。

## 7. map：内核态与用户态的共享数据面

map 是 eBPF 的键值存储，由内核分配与管理，**内核态程序和用户态进程
通过同一份 map 交换数据**；map 也是很多高级机制的载体（prog array 存
尾调用目标、ringbuf 传事件、devmap/sockmap 做转发）。

常用类型（完整见 04 章）：

| 类型 | 特点 | 典型用途 |
|---|---|---|
| `HASH` | 任意 key，动态增删 | 路由表/会话表（ruport 的 `message_map`、`router_map`） |
| `ARRAY` | key 为下标，预分配，访问最快 | 计数器、配置下发 |
| `PERCPU_HASH/ARRAY` | 每 CPU 一份值，无锁 | 高频计数器 |
| `LRU_HASH` | 容量满淘汰最久未用 | 会话缓存 |
| `RINGBUF`（5.8+） | 内核→用户事件环形缓冲 | 日志/事件上报（首选） |
| `PERF_EVENT_ARRAY` | 旧的事件通道，per-CPU | 兼容老内核 |
| `PROG_ARRAY` | 存程序 FD | 尾调用跳转表 |
| `BLOOM_FILTER`(5.16+)/`STACK`/`QUEUE`(4.20+) | 概率/队列语义 | 去重、异步传递 |

定义方式：现代写法是 **BTF map 定义**（ruport 采用），在 C 里用
`struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __be64); ... } name SEC(".maps");`，
加载器解析 `.maps` 段自动建表。老式 `bpf_map_def` 结构已不推荐。

map 的并发语义：内核侧 `bpf_map_update_elem` 对 hash map 按 bucket 加
自旋锁；用户态与内核态可同时访问同一 map（ruport 的用户态线程每秒
`lookup_and_delete`，XDP 侧同时 `update`，互不破坏，单条操作原子）。

## 8. BTF 与 CO-RE

### 8.1 问题：内核结构体不统一

tracing 类程序要读**内核内部结构**（如 `task_struct`）。不同内核版本/
编译配置下字段偏移不同，过去只能“针对每个内核编译一版”（BCC 运行时
编译）或放弃兼容。

### 8.2 BTF

BTF（BPF Type Format）是 DWARF 的极简替代，描述类型布局。kernel 5.4+
在 `CONFIG_DEBUG_INFO_BTF=y` 时把全量类型信息暴露在
`/sys/kernel/btf/vmlinux`（一行命令即可展开成 C 头）：

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

`vmlinux.h` 包含所有内核类型（UAPI + 内部结构 + 常量），tracing 程序
include 它即可，不再 include 系统头。（ruport 的 pidhide 原版就是这么
编的；xdp/tc 只用 UAPI 头，无需 vmlinux.h。）

### 8.3 CO-RE

CO-RE（Compile Once, Run Everywhere）三件套：

1. **编译期**：clang 对 `bpf_core_read(&x, ...)`/带
   `__builtin_preserve_access_index` 的访问记录**重定位**（“我要读
   `task_struct->real_parent->tgid`”）进 ELF 的 `.BTF.ext`。
2. **加载期**：加载器对比程序 BTF 与**当前内核 BTF**，按字段名（必要时
   按字段存在性/大小）算出实际偏移，改写字节码。
3. **运行期**：按改写后的偏移安全读取（等价 `bpf_probe_read_kernel`）。

因此 cilium/ebpf 加载时会读取 `/sys/kernel/btf/vmlinux`（可用
`ProgramOptions.KernelTypes` 注入自定义 BTF，容器等场景有用）。
网络程序用 UAPI 稳定结构（`iphdr`、`tcphdr`）时不涉及 CO-RE 重定位。

### 8.4 libbpf 与 cilium/ebpf 的关系

| 能力 | libbpf（C） | cilium/ebpf（Go） |
|---|---|---|
| 解析 ELF、建 map、重定位 | ✔ | ✔（纯 Go 实现） |
| CO-RE 重定位 | ✔ | ✔ |
| 生成加载骨架 | `bpftool gen skeleton` | **bpf2go**（见 03 章） |
| XDP/TC/tracing 挂载 | `bpf_xdp_attach`/`bpf_tc_*` 等 | `link` 包 + netlink |
| ringbuf/perf 读取 | C API | `ringbuf`/`perf` 包 |
| 部署形态 | 需链接 libbpf 或随二进制发布 .so | 静态单二进制、可交叉编译 |
| 代价 | 与 C 用户态绑定 | Go 内存模型下需注意 FD 生命周期 |

选择 cilium/ebpf 的核心理由与 ruport-go 一致：用户态逻辑用 Go 写、
发布单文件、无 cgo。经典 TC 的 clsact 挂载在 link 包中没有等价 API
（tcx 除外），需要借助 `vishvananda/netlink`——这正是本仓库
`cmd/ruport/main.go` 的做法，详见 05 章。

## 9. 内核版本速查（本仓库相关特性）

| 特性 | 主线版本 |
|---|---|
| eBPF 基础 / XDP（含 generic/SKB 模式） | 4.8 |
| clsact qdisc、`bpf_skb_store_bytes` 等 TC helper | 4.5 前后（现代用法按 4.9+ 保守） |
| BPF-to-BPF 调用 | 4.16 |
| 有界循环 | 5.3 |
| BTF（/sys/kernel/btf/vmlinux）、CO-RE | 5.4 |
| map batch 操作 | 5.6 |
| `BPF_MAP_TYPE_RINGBUF`、BTF link | 5.8 |
| memlock 解除（memcg 计费，`RLIMIT_MEMLOCK` 不再管 BPF） | 5.11 |
| `CAP_BPF` 等细分 capability | 5.8 |
| tcx 链接（TC 新挂载方式） | 6.6 |

ruport-go 只依赖 XDP + 经典 TC + hash map，按 4.8+ 设计；实际建议
Ubuntu 24.04（6.8）这类现代环境，与原项目测试环境一致。

## 10. 最小可对照示例

内核侧（`minimal.bpf.c`）：

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_cnt SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&pkt_cnt, &key);
    if (cnt)
        *cnt += 1;                 // map_value 指针可直接写
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

用户侧（Go，加载细节见 02/03 章）：

```go
objs := ...                                   // bpf2go 生成，见 03 章
lk, _ := link.AttachXDP(link.XDPOptions{      // 挂到 eth0（SKB 模式）
    Program: objs.CountPackets, Interface: ifidx, Flags: link.XDPGenericMode,
})
defer lk.Close()

var v uint64
_ = objs.PktCnt.Lookup(uint32(0), &v)         // 用户态直接读同一份 map
log.Printf("packets=%d", v)
```

三个动作——**定义 map、写程序、用户态读写 map**——就是一切 eBPF 应用的
骨架；ruport-go 只是把这三件事做得更复杂（双程序 + 双 map + 改包）。

---

下一章：[02-cilium-ebpf-core.md](02-cilium-ebpf-core.md)——把上面的
“加载器”职责拆开，讲 cilium/ebpf 的每个核心对象与 API。
