# 14 · 动态探针完全指南：kprobe 与 fentry

> 目标：把"往任意内核函数上挂钩子"这件事讲透——kprobe 家族的断点
> 机制、fentry 家族的 trampoline 机制、C 侧两套写法（宏/裸寄存器）、
> Go 侧挂载 API、一个经典需求的两种实现对照，以及**kprobe 与
> fentry 的全面对比与选型决策**。
> 关联：挂载 API 速查见 [05 §4](05-links.md)；程序类型定位见
> [11 §5](11-progtype-signatures.md)；trampoline 的底层原理论证见
> [13 §4](13-printk-and-trampoline.md)（本章用其结论，不重复推导）。

---

## 1. 动态探针家族全景

与 tracepoint（内核**显式埋点**、参数格式稳定）相对，"动态探针"=
**运行时往任意函数上挂钩**，两条技术路线：

```
 动态探针
 ├── kprobe 族 —— "断点陷阱"路线（4.1+，最通用）
 │    ├─ kprobe             进入内核函数时触发
 │    ├─ kretprobe          离开（返回）时触发
 │    ├─ uprobe/uretprobe   同机制，挂在用户态二进制的函数上
 │    └─ multi 变体          一次挂几百个点（kprobe multi，5.18+）
 │
 └── fentry 族 —— "trampoline 直调"路线（5.5+，需内核 BTF）
      ├─ fentry             进入：拿参数
      ├─ fexit              离开：参数 + 返回值一次拿全
      ├─ fmod_ret           修改返回值（仅白名单函数）
      └─ freplace(EXT)      挂到/替换另一个 BPF 程序
```

## 2. kprobe 机制走读：断点是怎么工作的

加载 kprobe 时内核做的事（x86_64 为例）：

```
① 注册：把目标函数第一条指令备份，原地改写为 int3（0xCC）断点
        （arm64 为 brk 指令，原理相同）

运行期，CPU 执行到该地址：
② int3 触发异常 → do_int3() → kprobe 处理框架
③ 保存寄存器现场到 struct pt_regs
④ 执行 pre-handler            ←—— 你的 BPF 程序在这里被调用
⑤ 单步执行那条被备份的原指令
   （临时把指令恢复回去、设 TF 单步标志）
⑥ 单步又触发一次异常 → 恢复断点、清标志
⑦ （kretprobe：处理返回挂钩，见 §3）
⑧ 沿原路径继续执行
```

由此推出 kprobe 的三个固有属性：

1. **每命中一次 = 两次异常 + 一次单步**——单次开销在百纳秒量级，
   对高频函数（每秒百万级调用）是可观测的负担；
2. **探测目标是"地址"而非"函数语义"**——内核函数一旦被内联、改名、
   删除，探针就静默失效或挂错位置，这是 kprobe 跨版本脆弱的根源；
3. 什么探测不了：标注 `__kprobes`/`NOKPROBE_SYMBOL` 的函数（探测
   框架自身，防递归）、`notrace` 函数、以及**被内联的函数**（没有
   独立地址）。例外技巧：`KprobeOptions.Offset` 可以按"函数内偏移"
   挂到内联展开点（配合 `perf probe`/`gdb` 找偏移），维护成本高，
   慎用。

符号从哪来：`/proc/kallsyms`（受 `kptr_restrict` 影响地址可能为 0，
root 可见）。写代码前先 `grep -w vfs_read /proc/kallsyms` 确认目标
存在且是函数（`t/T` 类型）。

## 3. kretprobe：返回值探针的机制与 MaxActive

kretprobe 建立在 kprobe 之上，多一步"偷换返回地址"：

```
① 在函数入口的 kprobe handler 里：把栈上的真实返回地址
   换成一个内核提供的 trampoline 地址，并把原返回地址存入
   该任务专属的实例槽
② 函数正常执行完毕、执行 ret 时，跳进 trampoline
③ trampoline 里执行 post-handler    ←—— BPF 程序在这里拿到
                                        PT_REGS_RC（返回值）
④ 恢复原返回地址，回到真实调用者
```

**MaxActive 的由来**：同一函数可能同时有多个"在飞"的实例（多进程/
多线程/中断嵌套都在里面），每个实例都要一个独立的 trampoline 槽。
内核按函数特征分配一个池子（`RetprobeMaxActive`），**池子耗尽时后续
命中会被丢弃（事件丢失，不是崩溃）**。观测长驻函数（如带阻塞 IO 的）
要留意，cilium 的 `KprobeOptions.RetprobeMaxActive` 可调大（该选项
会退回旧 API，跨版本可移植性差，文档原话警告）。

**取不到参数**是 kretprobe 的天然限制：post-handler 执行时寄存器早
就变了，只有返回值可靠。想要"参数 + 返回值"，经典做法是
**kprobe + kretprobe + 配对 map**（§7 主示例版本一），代价是两次
探针开销和 map 维护。

## 4. C 侧写法：两套风格

### 4.1 裸 `pt_regs`（老派但直白）

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>      // PT_REGS_* 宏

SEC("kprobe/vfs_read")
int kp_raw(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    // 按目标函数的调用约定取寄存器：x86_64 第1/2/3个参数 = di/si/dx
    struct file *file = (void *)PT_REGS_PARM1(ctx);
    size_t count      = (size_t)PT_REGS_PARM3(ctx);

    // 指针内容必须用 helper 读（验证器不允许直接解引用内核指针）
    unsigned char f_op_first;
    bpf_probe_read_kernel(&f_op_first, 1, &file->f_mode);

    bpf_printk("pid=%d count=%lu", pid, count);
    return 0;
}

SEC("kretprobe/vfs_read")
int kr_raw(struct pt_regs *ctx)
{
    long ret = PT_REGS_RC(ctx);        // 返回值
    bpf_printk("vfs_read returned %ld", ret);
    return 0;
}
```

要点：`PT_REGS_PARM1..5` 与平台调用约定绑定（移植性差）；读参数指向
的内存必须 `bpf_probe_read_kernel`（kprobe 上下文里验证器不认裸内核
指针——与 fentry 的关键差异，见 §6）。

### 4.2 `BPF_KPROBE` 宏（现代写法，bpf_tracing.h）

```c
SEC("kprobe/vfs_read")
int BPF_KPROBE(kp_vfs_read, struct file *file, char __user *buf,
               size_t count)
{
    // 参数按函数原型"按名"声明，宏负责从 pt_regs 取出
    bpf_printk("count=%lu", count);
    return 0;
}
```

宏的展开思路（简化示意）：按你声明的参数列表生成一个
`{ u64 arg1; u64 arg2; ... }` 结构，把 `ctx` 指针强转成它，于是
`file/buf/count` 就是按名字访问的寄存器值。**注意：这只是取值方便，
参数指针仍不能直接解引用**，还是要 `bpf_probe_read_*`。挂系统调用
入口另有 `BPF_KPROBE_SYSCALL` 变体（封装了 syscall 的参数布局）。

### 4.3 uprobe（用户态版本，对照记）

`SEC("uprobe//bin/cat:main")` / `uretprobe`——同一套断点机制落在
用户态二进制上；符号表被 strip 的二进制要靠 `nm/readelf` 找地址。
USDT 是应用**主动**预埋的稳定探针点，优先用之。cilium 侧
`link.Uprobe(...)`（05 章速查表）。

## 5. fentry 族：trampoline 直调的四种形态

前提（缺一不可）：内核 ≥5.5、带 BTF（`ls /sys/kernel/btf/vmlinux`）、
目标函数在 BTF 里（可 `bpftool btf dump file /sys/kernel/btf/vmlinux
| grep vfs_read` 验证）。底层机制（BTF 提取原型 → 动态生成调用约定
转换代码 → 参数以 u64 数组给 R1）在 13 章 §4.2 已推导，这里讲用法：

### 5.1 fentry：进入拿参数

```c
SEC("fentry/vfs_read")
int BPF_PROG(fe_vfs_read, struct file *file, char __user *buf,
             size_t count)
{
    // 参数按名直读；且指针【可以直接解引用】——验证器从 BTF 知道类型
    bpf_printk("count=%lu f_mode=%u", count, file->f_mode);
    return 0;
}
```

### 5.2 fexit：参数 + 返回值一次拿全

```c
SEC("fexit/vfs_read")
int BPF_PROG(fx_vfs_read, struct file *file, char __user *buf,
             size_t count, ssize_t ret)      // ← 最后一个参数=返回值
{
    bpf_printk("vfs_read(buf_size=%lu) = %ld", count, ret);
    return 0;
}
```

原理：trampoline 把**整个函数调用包了一层**——入口回调一次、返回
路径再回调一次，用的是同一份参数快照，所以 fexit 天然同时拥有
"输入 + 输出"。这直接替代了 kprobe+kretprobe+配对 map 的三件套。

### 5.3 fmod_ret：改返回值

挂法同 fexit（attach type `AttachModifyReturn`），返回非 0 即改写
返回值。**仅限内核标注了 error-injection 的白名单函数**（如部分
`security_*`），白名单外加载即拒。这是 BPF 实现"干预内核行为"的
少数入口之一。

### 5.4 freplace(EXT)：挂到另一个 BPF 程序

目标不是内核函数而是**另一个 BPF 程序**（XDP/TC 等）：观察它的每次
调用与返回（trace BPF，排障利器，13 章 §4.1），或经
`link.AttachFreplace` 实现**程序热替换**（挂载关系不变换实现）。

## 6. kprobe 与 fentry 全面对比（重点）

| 维度 | kprobe / kretprobe | fentry / fexit |
|---|---|---|
| 底层机制 | 断点陷阱（int3 + 单步，两次异常/命中） | trampoline 直调（调用约定转换，无异常） |
| 每命中开销 | 高（百 ns 级，高频函数可测出） | **近零**（13 章实测论证） |
| 内核版本 | 4.1+（几乎无处不在） | **5.5+ 且内核带 BTF**（5.4+ 编译开启） |
| 参数获取 | `PT_REGS_PARMx`/`BPF_KPROBE` 宏取**值** | `BPF_PROG` 宏按名取，且**指针可直接解引用** |
| 读参数指向的内存 | 必须 `bpf_probe_read_kernel` | 直接 `file->f_mode`（验证器认 BTF 类型） |
| 返回值 | 仅 kretprobe 的 `PT_REGS_RC`，**拿不到参数** | fexit **参数+返回值同时拿** |
| "参数+返回值"成本 | 两个程序 + 配对 map + 双倍探针开销 | **一个 fexit 程序** |
| 改返回值 | 不能 | fmod_ret 可以（白名单函数） |
| 目标耦合性 | kallsyms 符号名（内核小改版即可能漂移；挂错**静默**） | BTF 函数签名（类型不匹配**加载时就失败**，提前暴露） |
| 可探测范围 | 几乎所有 kallsyms 函数 | BTF 中存在的函数（面略窄但覆盖绝大多数） |
| 内联函数 | 不行（可用 Offset 探内联点，维护差） | 不行（同样需要函数实体） |
| 挂另一个 BPF 程序 | 不能 | freplace 可以 |
| 用户态对应物 | uprobe/uretprobe | —（无） |
| 生态成熟度 | 最老最通用，BCC/bpftrace 脚本存量巨大 | 新，内核与 Cilium 的演进方向 |

**选型口诀**：

- 内核 ≥5.5 且有 BTF → **默认 fentry/fexit**（更快、更安全、代码更少）；
- 老内核 / 无 BTF / 目标函数不在 BTF / 需要挂用户态 → kprobe 族；
- 只要返回值、函数低频 → kretprobe 也够；
- 高频热路径（每秒百万次以上）→ 必须避开 kprobe 的双异常开销；
- 复用存量 BCC/bpftrace 脚本 → kprobe 系（迁移成本优先）。

一句话：**kprobe 是"到处都能用的瑞士军刀"，fentry 是"新内核上的
正确答案"**——能用 fentry 就用 fentry，kprobe 的存在感来自兼容性。

## 7. 主示例：测 `vfs_read` 耗时（双版本对照）

需求：统计每次 `vfs_read()`（所有文件读取的必经之路）耗时并打印。
同一需求写两遍，差异一目了然。

### 7.1 版本一：kprobe + kretprobe + 配对 map（4.1+ 通用）

```c
// vfs_lat_kp.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {    // 配对 map：进函数记时间戳
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);        // pid_tgid
    __type(value, __u64);      // 入口时间戳
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
        return 0;                          // 没有配对记录（池被挤掉等）
    bpf_map_delete_elem(&start, &id);
    __u64 delta_us = (bpf_ktime_get_ns() - *ts) / 1000;
    bpf_printk("vfs_read pid=%d took %llu us", (__u32)id, delta_us);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

Go 挂载（加载部分同 doc/06 各例，此处只列挂载差异）：

```go
kp, err := link.Kprobe("vfs_read", objs.KpVfsRead, nil)
if err != nil { log.Fatal(err) }
defer kp.Close()

kr, err := link.Kretprobe("vfs_read", objs.KrVfsRead, nil)
if err != nil { log.Fatal(err) }
defer kr.Close()
// sudo cat /sys/kernel/debug/tracing/trace_pipe 看输出
```

输出样例（trace_pipe）：

```
cat-4821   [003] d..1  8123.456789: 0x00000001: vfs_read pid=4821 took 3 us
grep-4822  [001] d..1  8123.456912: 0x00000001: vfs_read pid=4822 took 17 us
```

### 7.2 版本二：fentry + fexit（5.5+，推荐）

计时需求仍需两个程序（fexit 拿不到"入口时刻"），但同样的配对 map
模式；而"记录读取了多少字节"这类**参数+返回值**需求一个 fexit 即可：

```c
// vfs_lat_fe.bpf.c
SEC("fentry/vfs_read")
int BPF_PROG(fe_vfs_read)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &id, &ts, BPF_ANY);
    return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(fx_vfs_read, struct file *file, char __user *buf,
             size_t count, ssize_t ret)     // ← 参数+返回值同场
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *ts = bpf_map_lookup_elem(&start, &id);
    if (!ts) return 0;
    bpf_map_delete_elem(&start, &id);
    __u64 delta_us = (bpf_ktime_get_ns() - *ts) / 1000;
    // kprobe 版做不到的事：一条日志同时有输入(count)和输出(ret)
    bpf_printk("vfs_read(%lu bytes) = %ld, took %llu us",
               count, ret, delta_us);
    return 0;
}
```

```go
fe, err := link.AttachTracing(link.TracingOptions{Program: objs.FeVfsRead})
fx, err := link.AttachTracing(link.TracingOptions{Program: objs.FxVfsRead})
defer fe.Close(); defer fx.Close()
```

（`TracingOptions.AttachType` 可显式指定 `AttachTraceFEntry/FExit`，
留空则由程序的 attach 信息推断。）

### 7.3 对照结论

| | kprobe 版 | fentry 版 |
|---|---|---|
| 程序数 | 2（kprobe+kretprobe） | 2（fentry+fexit）；只要参数+返回值时 1 个 |
| 每命中探针开销 | 双断点路径 | 近零 |
| 拿到信息 | 只有耗时（参数取值麻烦） | 耗时 + count + ret 一条日志 |
| 兼容内核 | 4.1+ | 5.5+ + BTF |
| 部署 | 老环境唯一选择 | 新环境默认选择 |

## 8. Go API 全貌（v0.22.0 实测）

```go
// 基础两件套
link.Kprobe(symbol string, prog *ebpf.Program, opts *link.KprobeOptions) (Link, error)
link.Kretprobe(symbol string, prog *ebpf.Program, opts *link.KprobeOptions) (Link, error)

// fentry/fexit/fmod_ret/raw_tp
link.AttachTracing(link.TracingOptions{
    Program:    prog,                    // 必填
    AttachType: ebpf.AttachTraceFEntry,  // 可选；留空按程序推断
    Cookie:     0,                       // bpf_get_attach_cookie()（5.15+）
})

// 一次挂多点（5.18+，先探测）
if err := features.HaveBPFLinkKprobeMulti(); err == nil {
    lk, err := link.KprobeMulti(prog, link.KprobeMultiOptions{
        Symbols: []string{"tcp_v4_connect", "tcp_v6_connect"},
    })
}
```

`KprobeOptions` 字段逐个（源码注释口径）：

| 字段 | 作用 | 注意 |
|---|---|---|
| `Cookie` | 程序内 `bpf_get_attach_cookie()` 取回，多点共用一程序时区分挂点 | 5.15+ |
| `Offset` | 按符号内偏移挂载（内联展开点） | 偏移随内核变，维护成本高 |
| `RetprobeMaxActive` | 调大 kretprobe 并发实例池 | 强制走旧 API，跨版本可移植性差 |
| `TraceFSPrefix` | 退回 tracefs 注册时的探针组名前缀 | 默认 "ebpf" |

## 9. 报错速查（动态探针专属）

| 症状 | 根因 | 处理 |
|---|---|---|
| attach: `symbol ... not found`（kprobe） | 函数被内联/改名/不存在 | `grep -w xx /proc/kallsyms` 确认；换相邻函数、用 Offset、或 fentry |
| attach/load 失败提示 BTF（fentry） | 内核 <5.5 或未编 BTF | `ls /sys/kernel/btf/vmlinux`；退回 kprobe |
| load 失败：`invalid mem access`（kprobe 里解引用参数指针） | kprobe 上下文不允许裸解引用 | 参数指针只取值；读内存用 `bpf_probe_read_kernel` |
| kretprobe 高并发下丢事件 | MaxActive 池耗尽 | `RetprobeMaxActive` 调大；或改 fexit |
| uprobe 挂不上 | 二进制被 strip / 符号是动态符号 | `nm -D`/`readelf -s` 查可用符号；改 USDT |

---

关联阅读：[05 挂载速查](05-links.md) · [11 程序类型](11-progtype-signatures.md) ·
[13 trampoline 原理](13-printk-and-trampoline.md) ·
[10 调试指南](10-debugging.md) · [返回索引](README.md)
