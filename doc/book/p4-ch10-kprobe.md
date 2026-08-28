# 第四篇 · 观测的艺术

> 前三篇的钩子都围着"包"转；本篇把同样的能力投向"看见内核"：
> 第 6 章已经用 tracepoint 做过 openat 监控，本篇把观测的两大
> 体系讲透——动态探针的旧王朝 kprobe（第 10 章）与新王朝
> fentry/trampoline（第 11 章）。ruport 的 pidhide 原型正属于
> 这个家族，而"测一个函数的耗时"这个贯穿两章的实验，会让你
> 亲手完成一次技术换代。

---

# 第 10 章 看见内核：tracepoint 与 kprobe

> 观测类程序的问题模型与网络完全不同："当内核执行到 X 时，告诉我
> 当时的一切"。本章按稳定性光谱展开：最稳的静态埋点 tracepoint、
> 最灵活的动态断点 kprobe、它们各自的机制与代价，并以经典的
> "函数耗时统计"完成 kprobe 系的完整实战。

## 10.1 换个视角：eBPF 不只服务网络

第 1 章的四大领域里，观测（tracing）是渗透率最高的一个——原因
在于它对 eBPF 的需求恰好是"最小公约数"：一个钩子 + 一个事件通道
（ringbuf，第 6 章）+ 若干读取 helper。你已经掌握了全部积木：
第 6 章的 openat 监控就是一个完整观测工具。本篇要补的是**钩子
本身**的系统知识：

```
 稳定性光谱（选择探针的第一维度）
 稳 ◀────────────────────────────────────────────────▶ 灵活
 tracepoint        uprobe/USDT        kprobe/fentry
 内核显式埋点        用户态函数          任意内核函数
 参数格式稳定        随二进制漂移        随内核版本漂移
 覆盖有限           覆盖任意应用        覆盖 ~2万个函数
```

## 10.2 稳定埋点 tracepoint：深入

第 6 章我们**用过**它，现在讲**透**它。

**它是什么**：内核开发者显式写在代码里的埋点
（`trace_netif_rx(skb)` 这样的调用），编译期就固定了位置与参数
布局。BPF 程序挂上后，埋点触发时被执行。

**为什么稳**：埋点是内核 API 的一部分，参数格式
（`struct trace_event_raw_*`）跨版本兼容——你的程序不会因为内核
升级而读错字段。代价是**只有内核作者埋过的地方才有**。

**机制走读**（谁调用了你的程序）：

```
 内核代码执行到 trace_netif_rx(skb)
   │
   ▼
 perf_trace_<event_class>()          ← tracefs 框架入口
   │  组装 trace_entry（公共头：类型/标志/pid...）
   ▼
 perf_trace_run_bpf_submit()
   │  trace_call_bpf()
   ▼
 ┌─ 你的 BPF 程序（ctx = trace_event_raw_net_netif_rx）─┐
 │  字段访问按 format 文件的偏移直读，无需 probe_read     │
 └──────────────────────────────┬───────────────────────┘
                                ▼
                    bpf_perf_event_output / ringbuf 上报
```

**每个 tracepoint 的"说明书"**——format 文件，写观测程序前必读：

```bash
ls /sys/kernel/tracing/events/          # 全部可用事件（目录树）
cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
# field:long id;        offset:8;  size:8  ← 参数区从此开始
# field:const char * filename? —— 实际为 args 数组（第6章已用）
#  format 定义即 C 侧 trace_event_raw_sys_enter 的字段表
```

C 侧写法三要素（第 6 章已示范）：section 用
`SEC("tracepoint/<组>/<事件>")`（或 libbpf 风格
`SEC("tp/syscalls/sys_enter_openat")`）；ctx 类型在 vmlinux.h 里
按事件名找 `trace_event_raw_*`；Go 挂载
`link.Tracepoint(组, 事件, prog, nil)`。

## 10.3 动态探针 kprobe：断点机制走读

**它是什么**：不依赖埋点，运行时把钩子挂到**几乎任意内核函数**
的入口（kprobe）或返回处（kretprobe）。灵活性的来源，也是不稳定
的来源——它挂在"地址"上，函数一改名/被内联，探针就静默失效。

### 10.3.1 断点时序（x86_64）

```
 加载期（注册 kprobe）：
   ① 备份目标函数第一条指令
   ② 原地改写为 int3（0xCC）断点指令

 运行期（每次执行到该地址）：
   ③ CPU 触发 #BP 异常 → do_int3() → kprobe 框架
   ④ 保存寄存器现场到 struct pt_regs
   ⑤ 执行 pre-handler ──────────▶ 你的 BPF 程序（拿到 pt_regs）
   ⑥ 单步执行被备份的那条原指令（临时恢复+TF 标志）
   ⑦ 单步再次陷入 → 重新插入 int3、清标志
   ⑧ 沿原路径继续执行
```

由时序直接推出三个属性（第 11 章对比的伏笔）：

1. **每命中一次 = 两次异常 + 一次单步**——百纳秒级开销，高频函数
   上可测量；
2. **参数以寄存器现场的形式交付**（`pt_regs`）——不是类型安全的
   函数参数，要按调用约定自己取（10.4）；
3. **探测不到的函数**：标注 `__kprobes`/`notrace` 的（防递归）、
   以及**被编译器内联的函数**（没有独立地址）。

### 10.3.2 C 侧两种写法

```c
// 写法一：裸 pt_regs（直白，平台相关）
#include <bpf/bpf_tracing.h>           // PT_REGS_* 宏
SEC("kprobe/vfs_read")
int kp_raw(struct pt_regs *ctx)
{
    // x86_64 调用约定：第1/2/3 参数 = rdi/rsi/rdx
    struct file *file = (void *)PT_REGS_PARM1(ctx);
    size_t count      = (size_t)PT_REGS_PARM3(ctx);

    // ★ 指针不能解引用！kprobe 上下文必须用 helper 读
    u32 f_mode;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), &file->f_mode);
    return 0;
}

// 写法二：BPF_KPROBE 宏（现代，按名声明）
SEC("kprobe/vfs_read")
int BPF_KPROBE(kp_vfs_read, struct file *file, char __user *buf,
               size_t count)
{
    // 宏把参数列表翻译成对 pt_regs 的按位取值——但注意：
    // 这只是"取值方便"，指针依旧不能直接解引用
    return 0;
}
```

### 10.3.3 探测目标怎么找

```bash
grep -w vfs_read /proc/kallsyms        # 符号存在且为 t/T（函数）
cat /proc/sys/kernel/kptr_restrict     # 地址可见性（root 一般没问题）
```

挂载（Go）：`link.Kprobe("vfs_read", prog, nil)`；内联展开点可用
`KprobeOptions.Offset` 按函数内偏移挂（偏移随内核漂移，维护成本
高，慎用）。

## 10.4 kretprobe 与配对 map：函数耗时统计（版本一）

经典需求："**统计每次 vfs_read 的耗时**"。kprobe 只能看到入口，
耗时必须"入口记时间、出口算差值"——kprobe + kretprobe + 一张
配对 map 的三件套。

### 10.4.1 kretprobe 机制速览

```
 ① 入口 kprobe handler：把栈上的真实返回地址替换为内核
    trampoline 地址，原地址存入本任务专属"实例槽"
 ② 函数正常执行、执行 ret → 跳进 trampoline
 ③ trampoline 执行 post-handler ──▶ 你的 BPF 程序
    （此刻 PT_REGS_RC = 返回值；但参数早已无踪影！）
 ④ 恢复原返回地址，回到真实调用者
```

**MaxActive 的由来**：同一函数可能同时有多个"在飞"实例（多线程/
中断），每个实例占一个 trampoline 槽，槽池有上限——**耗尽后新命中
被丢弃**（事件丢失而非崩溃）。观测长阻塞函数（vfs_read 正是）要
留意，Go 侧可用 `KprobeOptions.RetprobeMaxActive` 调大。

### 10.4.2 完整实现

```c
// vfs_lat_kp.bpf.c —— 版本一：kprobe + kretprobe + 配对 map
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {    // 配对 map：入口时间戳（事件型？不，状态型——正常读写）
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);        // pid_tgid：同一任务出口对上入口
    __type(value, __u64);      // 入口时刻
    __uint(max_entries, 10240);
} start SEC(".maps");

SEC("kprobe/vfs_read")
int BPF_KPROBE(kp_vfs_read)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &id, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/vfs_read")
int BPF_KPROBE(kr_vfs_read)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *ts = bpf_map_lookup_elem(&start, &id);
    if (!ts)
        return 0;                        // 没配上对（池被挤/中途加载）
    bpf_map_delete_elem(&start, &id);
    __u64 us = (bpf_ktime_get_ns() - *ts) / 1000;
    bpf_printk("vfs_read pid=%d took %llu us", (__u32)id, us);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

Go 挂载：

```go
kp, err := link.Kprobe("vfs_read", objs.KpVfsRead, nil)
if err != nil { log.Fatal(err) }
defer kp.Close()

kr, err := link.Kretprobe("vfs_read", objs.KrVfsRead, nil)
if err != nil { log.Fatal(err) }
defer kr.Close()
// 输出：sudo cat /sys/kernel/debug/tracing/trace_pipe
```

运行输出（`trace_pipe`）：

```
cat-4821   [003] d..1  8123.456789: 0x00000001: vfs_read pid=4821 took 3 us
grep-4822  [001] d..1  8123.456912: 0x00000001: vfs_read pid=4822 took 17 us
```

**清点这个方案的账单**：两个探针（双份断点开销）、一张 map（每次
调用两次 map 操作）、只能得到"耗时"（拿不到参数/返回值——想加
就得再动两处）。第 11 章会用一个 fexit 程序把这张账单撕掉。

## 10.5 探测用户态：uprobe/USDT

同一套思想落到用户态二进制：挂 `SEC("uprobe//bin/cat:main")`，
Go 用 `link.Uprobe(link.UprobeOptions{Path, Symbol/Address, Program,
Pid...})`。两个注意点：被 strip 的二进制没有符号名可用（改用
`nm -D`/`readelf -s` 找动态符号或按地址）；应用若预埋了 USDT 探针
（`dtrace` 风格），优先挂 USDT——它随应用版本稳定。

## 10.6 小结与练习

**小结**：选探针先看稳定性光谱（tracepoint 稳而少、kprobe 灵而
脆）；tracepoint 的 format 文件即参数说明书；kprobe=断点+两次
异常+单步，参数以 pt_regs 交付且必须用 helper 读内存；kretprobe
靠"偷换返回地址+trampoline 池"，只保返回值不保参数；耗时统计的
配对 map 模式是 kprobe 系的经典拼装。

**练习**：
1. 把 10.4 的打印换成 ringbuf 事件（融合第 6 章），在 Go 侧打印
   而非 trace_pipe；
2. 用 `BPF_KPROBE` 宏给 kp_vfs_read 加上 `count` 参数并打印——
   验证"宏只是取值方便"，试着直接 `file->f_mode` 看验证器怎么拒；
3. `grep -w some_inlined_fn /proc/kallsyms` 找一个不存在的（比如
   某个 static inline 函数），体验"探测不到的函数"；
4. 思考题：为什么配对 map 的 key 用 pid_tgid 而不是 pid？
   （提示：多线程共享 pid——tgid 才是"任务"粒度）

---

kprobe 系用四十年前的断点技术换来了"到处能挂"的灵活性。下一章
见识 5.5 之后的答案：不用断点，用"翻译官"。
