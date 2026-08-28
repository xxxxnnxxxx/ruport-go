# 第五篇 · 精通之路

> 会写程序、会挂钩子、会读数据，是"能用"；这一篇回答"为什么"
> 与"怎么稳"：类型系统如何支撑一次编译到处运行（第 12 章）、
> map 在内核源码里长什么样（第 13 章）、Go 侧如何工程化与管好
> 生命周期（第 14 章）、以及一套完整的版本兼容与调试方法论
> （第 15 章）。本篇结束，你将具备读懂 ruport 每一行代码、并且
> 能独立扩展它的全部前置知识。

---

# 第 12 章 BTF 与 CO-RE：一次编译，到处运行

> 第 1 章讲过这段历史的开头：BCC 每台机器现场编译，痛不欲生。
> 本章把它讲到底：为什么分发 tracing 程序这么难、BTF 这个
> "极简类型信息"如何成为解药、CO-RE 三件套的精确原理，以及
> vmlinux.h 的取舍。最后动手写一个真正依赖内核结构体的程序。

## 12.1 分发困境：BCC 时代的痛

回顾问题的结构性根源。tracing 程序要读**内核内部结构体**：

```c
// 读"当前进程的可执行文件名"——task_struct 是内核私有结构！
struct task_struct *task = (void *)bpf_get_current_task();
char comm[16];
bpf_probe_read_kernel_str(&comm, sizeof(comm), task->comm);
//                                              ▲ 这个偏移，每个内核都可能不同
```

`task_struct::comm` 的偏移量取决于内核版本与编译配置。三种老办法
全部不可接受：

```
 办法一：目标机上装内核源码头 + 现场编译（BCC 路线）
   → 每台机器数百 MB 依赖、秒级启动延迟、内存占用
 办法二：为每个内核版本预编译一堆 .o
   → 组合爆炸（版本×配置），分发噩梦
 办法三：硬编码偏移量
   → 换个内核就读错内存，比 LKM 还危险
```

破局需要两样东西：一份**紧凑的内核类型信息**（让程序自己知道
字段在哪），和一套**加载时按实际内核校正偏移**的机制。前者是
BTF，后者是 CO-RE。

## 12.2 BTF：类型信息的极简主义

内核早已有一份类型信息——DWARF 调试数据。为什么不用它？**体积**：
完整 DWARF 动辄数 GB；BPF 场景只需要"类型布局"（结构体有哪些
字段、在什么偏移），不需要变量位置、行号表这些调试细节。

BTF（BPF Type Format）就是砍到只剩布局的格式，体积约为 DWARF 的
百分之一量级。5.4 起，内核开启 `CONFIG_DEBUG_INFO_BTF` 时把**自身
的 BTF** 暴露成一个文件：

```bash
ls -l /sys/kernel/btf/vmlinux     # 通常仅几 MB
bpftool btf dump file /sys/kernel/btf/vmlinux format c | head -50
```

dump 出来的就是 C 类型声明——BTF 里只有几类"积木"（kind）：
INT/ PTR/ ARRAY/ STRUCT/ UNION/ FUNC（函数原型）/ FUNC_PROTO…，
所有内核结构都能用这几类拼出来。第 11 章的 trampoline 正是从
FUNC/FUNC_PROTO 里提取目标函数原型的。

## 12.3 CO-RE 三件套：精确原理

第 1 章给过三块拼图的速写图，现在把每一块的机制讲精确：

```
 ┌─────────────────── 编译期（你的机器）───────────────────┐
 │ clang 看到 bpf_core_read(&dst, ..., &task->comm) 或     │
 │ 带 __builtin_preserve_access_index 的访问：               │
 │   记录【重定位】"我要读 task_struct 的 comm 字段"        │
 │   写进 .o 的 .BTF.ext（不是写死偏移！）                   │
 └────────────────────────┬────────────────────────────────┘
                          ▼
 ┌─────────────────── 加载期（目标机器）────────────────────┐
 │ 加载器（libbpf/cilium）拿着两份 BTF 对账：                │
 │   程序 BTF："task_struct 里有 comm"                       │
 │   内核 BTF："task_struct 里 comm 在偏移 0x5d8"            │
 │   → 把字节码里的占位偏移改写为真实偏移                     │
 │   → 字段消失/类型不符？加载失败，明确报错                 │
 └────────────────────────┬────────────────────────────────┘
                          ▼
 ┌─────────────────── 运行期（热路径）──────────────────────┐
 │ 改写后的指令执行 bpf_probe_read_kernel(dst,16,task+0x5d8) │
 │ 安全读取（处理缺页），开销与硬编码版完全相同               │
 └──────────────────────────────────────────────────────────┘
```

三个关键认知：

1. **重定位是"按字段名"而非"按偏移"**——所以目标内核字段顺序
   变了也能对上（同名匹配；字段改名/删除则失败，这是**正确**的
   失败）；
2. **代价只在加载期**，运行期与硬编码偏移零差别——这就是 CO-RE
   敢宣称"无性能损耗"的原因；
3. C 侧的两种写法：

```c
// 写法一：显式（推荐，意图清晰）
bpf_core_read(&comm, sizeof(comm), &task->comm);

// 写法二：整块编译单元开启（libbpf 头提供）
#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
// 程序里普通访问自动重定位（经由 preserve_access_index 编译选项）
```

## 12.4 vmlinux.h：工作流与取舍

把内核 BTF 展开成 C 头文件（第 6 章已用过一次）：

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

从此 tracing 程序不再 include 系统内核头，类型全部来自这一个
文件——**编译机不需要目标内核的头文件**，这正是"一次编译"的
工作流基石。

取舍表（决定你项目要不要它）：

| | 用 vmlinux.h + CO-RE | 不用（直接 include UAPI 头） |
|---|---|---|
| 适用 | 读内核内部结构（tracing 系） | 只碰稳定 UAPI（`iphdr/tcphdr` 等网络程序） |
| 编译机要求 | 无需内核头 | 需要内核头（clang -target bpf 的 include 问题，14.3） |
| 体积/编译速度 | 头文件巨大（几万类型），编译变慢 | 轻快 |
| 跨内核兼容 | 字段级自动适配 | UAPI 本身稳定，无需适配 |

**ruport 的选择**是右列：XDP/TC 只碰 UAPI 稳定结构，不需要
vmlinux.h——这也解释了它为什么可以在 4.8 内核设计目标下工作。
而 pidhide 原型（读 `task_struct`）必须走左列。

## 12.5 动手：写一个依赖内核结构体的观测程序

目标：fentry 挂 `vfs_read`，打印**进程名 + 打开的文件路径**
（路径藏在 `file->f_path.dentry`，纯内核内部结构，非 CO-RE 不可）：

```c
// fpath.bpf.c —— CO-RE 实战（需 vmlinux.h）
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define NAME_MAX 256

struct event {
    u32  pid;
    char comm[16];
    char path[NAME_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

SEC("fentry/vfs_read")
int BPF_PROG(trace_vfs_read, struct file *file, char __user *buf,
             size_t count)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // ★ CO-RE 读链：file → f_path.dentry → d_name.name → 字符串
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(e->path, sizeof(e->path), name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

`BPF_CORE_READ(a, b, c)` 是"沿指针链逐跳 CO-RE 读取"的宏——每一
跳的字段偏移都经 12.3 的三件套处理。把这段程序拷到另一台内核
小版本不同的机器上直接加载（**不重新编译**），照样工作——这就是
BCC 做不到、CO-RE 做到的事。Go 侧消费端与第 6 章 openat 项目
同构（ringbuf + binary.Read），不再重复。

## 12.6 小结与练习

**小结**：分发困境的根源是"内核私有结构体的偏移因内核而异"；
BTF 用极简格式（布局-only）让内核自带类型说明书；CO-RE 三件套
= 编译期记字段名重定位 + 加载期对账改偏移 + 运行期安全读，代价
只付一次（加载时）；vmlinux.h 是 tracing 工作流的基石，纯网络
程序（UAPI 稳定）可不用——ruport 即是。

**练习**：
1. 跑通 12.5，然后用 `bpftool btf dump file fpath.bpf.o` 找到
   .o 里记录的重定位信息（CO-RE relocation 段）；
2. 把 `BPF_CORE_READ(file, f_path.dentry)` 改成直接
   `file->f_path.dentry` 解引用——观察两种写法在 fentry 上下文里
   验证器的不同态度（提示：fentry 的 BTF 直读 vs CO-RE 显式读）；
3. 思考题：为什么 ruport 的 XDP/TC 程序读 `iphdr` 不需要 CO-RE，
   而 pidhide 读 `task_struct` 必须 CO-RE？（用 12.4 的取舍表
   回答，并指出这两类结构体在内核里的身份差别。）

---

类型系统讲完了。下一章钻进 `kernel/bpf/hashtab.c`——你在第 4、5
章观察到的每一个 map 行为，都将在源码里找到出处。
