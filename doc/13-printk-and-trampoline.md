# 13 · printk 内幕与 BPF trampoline

> 整理自 ArthurChiao's Blog《BPF 进阶笔记（四）：调试 BPF 程序》
> （2022，基于内核 5.10），原文见 https://arthurchiao.art。
> [10 章](10-debugging.md)讲“调试工具怎么用”；本章讲两个进阶内幕：
> **printk 家族为什么有那些怪限制**（栈、5 参上限、.rodata），以及
> **用 fentry/fexit trace 另一个 BPF 程序**（trampoline 机制）——后者
> 是调试 ruport 这类网络程序的利器。

---

## 1. trace 输出：读懂那一行日志

`bpf_printk`/`bpf_trace_printk` 最终都写进
`/sys/kernel/debug/tracing/trace`（快照）与 `trace_pipe`（流式）：

```
             进程名-pid   CPU   选项位    时间戳        fake ip        内容
telnetd-470   [001]       .N..  419421.045894:  0x00000001:  <formatted msg>
```

逐字段：

| 字段 | 含义 |
|---|---|
| `telnetd-470` | 触发进程与 PID（BPF 侧是被动执行，非你自己的进程） |
| `[001]` | 所在 CPU——多核输出交织时靠它对齐 |
| `.N..` | 4 个选项字符：中断状态/调度标志（N=TIF_NEED_RESCHED 等）/硬软中断/抢占深度 |
| `419421.045894` | 单调时钟时间戳（秒.微秒） |
| `0x00000001` | **BPF 伪造的指令指针**（trace 基础设施要求有 ip 列，BPF 没有真的 ip，填 1） |
| `<formatted msg>` | 你的格式化内容 |

定制列：`/sys/kernel/debug/tracing/trace_options`；完整说明读同目录
`README`。**一个实用坑**：`trace` 文件正被打开时新日志会被丢弃，持续
观察用 `trace_pipe`（[10 章 §4.2](10-debugging.md)）。

## 2. bpf_printk()：宏、5.2 分水岭与 .rodata

libbpf 的 `bpf_printk` 只是 `bpf_trace_printk` 的宏封装：

```c
// tools/lib/bpf/bpf_helpers.h
#define bpf_printk(fmt, ...)                    \
    ({ char ____fmt[] = fmt;                    \
       bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })
```

**为什么建议 5.2+ 才用**：老内核上 `char ____fmt[] = fmt` 把格式串
**放栈上**，而 BPF 栈只有 512 字节，又慢又挤。5.2 引入全局变量
（BTF DATASEC）后，clang 把字符串放进 `.rodata` 段，加载器转成只读
map，运行时一次 map lookup 取地址。在 <5.2 内核上加载用了该特性的
程序会得到一条**乍看莫名其妙**的报错：

```
map .rodata: map create: read- and write-only maps not supported (requires >= v5.2)
```

——现在你知道它在说什么了（09 章：全局变量 5.1+，此处按原文 5.2+
的保守口径）。ruport 的 `bpfprint` 宏等价于这个封装。

## 3. bpf_trace_printk()：限制的根源

helper 原型：

```c
long bpf_trace_printk(const char *fmt, u32 fmt_size, ...);
// kernel/trace/bpf_trace.c
BPF_CALL_5(bpf_trace_printk, char *, fmt, u32, fmt_size,
           u64, arg1, u64, arg2, u64, arg3) { ... }
```

一切怪限制都从 `BPF_CALL_5` 来——**eBPF helper 最多 5 个参数**
（R1–R5 传参的调用约定，[01 章 §3](01-ebpf-overview.md)），fmt 和
fmt_size 已占两席，**所以可变参数最多 3 个**。`BPF_CALL_x` 宏负责
BPF 调用约定与内核 C 调用约定的互转（64 位机上是 nop，32 位机上是
真实转换）。

格式符支持（5.10 实测口径）：

| 支持 | 不支持 |
|---|---|
| `%d %i %u %x`、`%ld %li %lu %lx`、`%lld %lli %llu %llx`、`%p %s` | 宽度/精度修饰（`%5d`、`%.2f` 等）→ 直接 `-EINVAL` 且什么都不打 |

版本演进（原文所述）：

- **<5.9**：不自动换行，fmt 要自己带 `\n`；
- **5.9+**：默认补换行（改用专用事件，不再与内核 `printk` 混流）；
- **5.13 起**进一步增强打印能力；超过 3 参的完整 `printf` 语义要等
  `bpf_trace_vprintk`（5.16~，09 章）——或现在就用 `bpf_snprintf`
  （5.9~）先格式化到 buffer 再输出。

其他：`%s` 需内核可读指针（用户态指针先 `bpf_probe_read_user_str`）；
GPL-only；helper 本身慢（全局缓冲 + 锁），生产环境换 ringbuf。

## 4. 用 BPF trace BPF：fentry/fexit 挂到另一个程序

### 4.1 场景

传统上 XDP/TC 程序是“黑盒”：挂上之后包在里面经历了什么看不见。
kernel 5.5 起可以**向任何网络类 BPF 程序 attach fentry/fexit 程序**，
于是能用一个 tracing 程序观察 ruport 的 `tc_ingress` 里每个包的进出
（入口参数、出口返回值），而完全不影响被观测程序的执行——对端口
复用这种“改包后行为对不对”的排障是降维打击。

libbpf/cilium 侧：被 trace 的程序正常加载，tracing 程序以
`fentry/fexit` section + `AttachTo` 指向目标程序名，内核通过
**BPF trampoline** 建立跳板（cilium 对应 `link.AttachTracing`，把
目标从“内核函数”换成“另一个 BPF 程序”）。需要 root。

### 4.2 BPF trampoline 原理（双向）

trampoline（蹦床）= 两种调用约定之间的“适配 + 跳转”代码：

```
BPF 程序 ──调用──▶ [BPF-to-kernel trampoline] ──▶ 内核函数(helper)
内核函数 ──进入/返回──▶ [kernel-to-BPF trampoline] ──▶ fentry/fexit 程序
```

- **BPF→内核（静态）**：即 `BPF_CALL_x` 宏（§3），编译期生成；
- **内核→BPF（静态）**：`CAST_TO_U64` + `__bpf_trace_##call()` 垫片
  （`include/trace/bpf_probe.h`），把内核函数参数压成 u64 数组，指针
  放 R1 传给 BPF 程序——tracepoint 的实现基础；
- **内核→BPF（动态，5.5）**：任意约 2.2 万个全局内核函数都可用 nop
  槽 attach；`btf_distill_func_proto()` 从 BTF 提取函数原型生成
  “函数模型”，架构相关生成器再产汇编。例：`eth_type_trans()` 两个
  指针参数 → x86-64 上 trampoline 占 16 字节栈存 `%rdi/%rsi` → 指针
  给 R1。**验证器**保证 BPF 程序只能只读访问这些参数、且指针类型
  不可强转——fentry 安全性的来源。

### 4.3 fentry/fexit 相比 kprobe/kretprobe 的优势

| 维度 | 说明 |
|---|---|
| 性能 | 近零开销。关键函数（如 `tcp_retransmit_skb`）常年多个探针并存；trampoline 在每次 attach/detach 时**重新生成**保证最优，且 detach 设计为不会失败 |
| 信息量 | fentry 拿**参数**；fexit 拿**参数 + 返回值**——kretprobe 只有返回值。传统“kprobe 存参数进 map + kretprobe 取出合并”的模式被 fexit 一步替代 |
| 可用性 | 参数指针**直接解引用**，不再需要 `bpf_probe_read*` 全家桶（BTF 已告诉验证器类型） |
| 代价 | 需要 5.5+ 且内核带 BTF（5.4+，09 章） |

（单步断点调试：`bpf_dbg` 仅适用于 cBPF，现代 eBPF 无此工具，
以 test_run + printk/tracing 为主，见 [10 章](10-debugging.md)。）

## 5. ruport-go 视角

- ruport 的 `bpfprint(":insert a message into the map.")` 走的就是
  本章 §1–§3 的链路：`cat /sys/kernel/debug/tracing/trace_pipe` 验证
  XDP 是否命中魔术包，是最快的第一步（10 章 §4.2）；
- 单参数、无格式符的写法刻意避开了 3 参限制；要打印 IP/端口时记得
  `%s` 不能直接吃网络序整数——先在程序里拼或传多个参数；
- 排查 `tc_ingress` 改写是否命中，可以临时写一个 fexit 程序 attach
  到 `tc_ingress`（§4.1），打印每次调用的返回值与改写后的端口，
  观察完卸载即可，不触碰 ruport 本体。

---

关联阅读：[10 调试完全指南](10-debugging.md) ·
[11 程序类型参考](11-progtype-signatures.md) ·
[返回索引](README.md)
