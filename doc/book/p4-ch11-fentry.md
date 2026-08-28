# 第 11 章 fentry 与 trampoline：新一代观测

> 上一章结尾的账单：测一个函数耗时，kprobe 系要两个探针、一张
> map、只换来一个数字。2019 年内核 5.5 合入的 BPF trampoline
> 改变了游戏规则。本章讲清"翻译官"的原理、fentry/fexit/fmod_ret/
> freplace 四兄弟的分工，重写耗时统计（版本二），最后给出两代
> 探针的全面对比与选型口诀。

## 11.1 kprobe 的三宗罪

第 10 章埋的伏笔在此结算：

```
 ┌─────────┬──────────────────────────────────────────────┐
 │ ① 慢    │ 每命中 = 两次异常 + 单步恢复（百ns级）         │
 │         │ 高频函数（每秒百万次）上开销可观               │
 ├─────────┼──────────────────────────────────────────────┤
 │ ② 脆    │ 挂在"符号地址"上：函数改名/内联 → 探针静默失效  │
 │         │ 内核小版本升级就可能翻车，且无任何告警           │
 ├─────────┼──────────────────────────────────────────────┤
 │ ③ 取参难 │ 交付的是寄存器现场(pt_regs)：要懂调用约定、     │
 │         │ 用 PT_REGS 宏取值、用 probe_read 读内存——      │
 │         │ 类型安全为零，写错字段名编译器不吭声            │
 └─────────┴──────────────────────────────────────────────┘
```

理想的探针应该：像正常函数调用一样被**直接调用**（无异常）、参数
**按原型以类型安全方式**交付（编译期查错）、签名不匹配**加载时就
报错**（而不是静默失效）。这正是 fentry 家族的样子——背后是
trampoline。

## 11.2 trampoline：调用约定的翻译官

问题的本质是**两套调用约定**：

```
 C/内核函数调用约定（x86_64）          eBPF 调用约定
 ┌────────────────────────┐          ┌────────────────────┐
 │ 前6个参数走 rdi,rsi,rdx,│          │ 参数走 R1~R5        │
 │ rcx,r8,r9，多余的走栈    │    vs    │ 程序入口 ctx 指针=R1 │
 │ 返回值在 rax            │          │ 返回值在 R0          │
 └────────────────────────┘          └────────────────────┘
```

trampoline（蹦床）就是**编译期生成的一段转换代码**：把一边的
约定"翻译"成另一边。方向有两个：

**内核→BPF**（fentry 家族的基础）：在目标函数入口插一个 nop 槽，
attach 时把 nop 替换为跳向 trampoline 的指令。trampoline 从
**BTF 里提取函数原型**（`btf_distill_func_proto` 生成"函数模型"），
按模型生成汇编：把 `rdi/rsi/...` 摆进一块栈上区域，把区域指针
放进 R1，然后调用你的 BPF 程序——**全程无异常，近似一次普通
函数调用**：

```
        内核函数 vfs_read(file, buf, count)
                  │ 入口 nop 槽被替换为 jmp
                  ▼
        ┌───────────────────────────────┐
        │ trampoline（按 BTF 原型生成）  │
        │  ① 把 rdi/rsi/rdx 存成 u64[]  │
        │  ② R1 = &u64[]                │
        │  ③ 调用 BPF 程序               │
        └──────────────┬────────────────┘
                       ▼
        你的程序：参数类型安全直读，指针可直接解引用
        （验证器从 BTF 知道每个参数的类型！）
```

**BPF→内核**（helper 的实现原理）：`BPF_CALL_x` 宏在编译期把
helper 编译成这种静态 trampoline——第 15 章讲 printk 三参限制时
会再次用到这个事实。

fentry 的前提由此明确：**内核 ≥5.5 且带 BTF**（原型信息是翻译的
原料）、目标函数在 BTF 里（`bpftool btf dump file
/sys/kernel/btf/vmlinux | grep vfs_read` 验证）。

## 11.3 四兄弟：fentry / fexit / fmod_ret / freplace

**fentry（进入）**——参数按原型直读：

```c
SEC("fentry/vfs_read")
int BPF_PROG(fe_vfs_read, struct file *file, char __user *buf,
             size_t count)
{
    bpf_printk("count=%lu f_mode=%u", count, file->f_mode);
    //                      ▲ 注意：直接解引用！kprobe 下这是死刑
    return 0;
}
```

**fexit（离开）**——trampoline 把**整个函数调用包了一层**：入口
回调一次、返回路径再回调一次，同一份参数快照全程可用，于是
**参数 + 返回值同场**（宏的最后一个参数即返回值）：

```
 trampoline 包裹式调用（fexit 原理）
     调用者 ──▶ [trampoline: 保存参数快照]
                    │ 调用真实 vfs_read()，拿到返回值
                    ▼
                [trampoline: 带着参数快照+返回值，调用你的程序]
                    │
                    ▼ 返回调用者
```

```c
SEC("fexit/vfs_read")
int BPF_PROG(fx_vfs_read, struct file *file, char __user *buf,
             size_t count, ssize_t ret)      // ← ret=返回值
{
    bpf_printk("vfs_read(%lu bytes) = %ld", count, ret);
    return 0;
}
```

**fmod_ret（修改返回值）**——非 0 返回值会**改写**函数的返回值。
仅限内核标注了 error-injection 的白名单函数（多为 `security_*`），
是 BPF 干预内核行为的少数合法入口之一。

**freplace（EXT）**——目标不是内核函数而是**另一个 BPF 程序**：
观察它的每次调用与返回（trace BPF，网络程序排障利器），或经
`link.AttachFreplace` 做**程序热替换**（挂载关系不变、实现可换）。

## 11.4 动手：耗时统计版本二 + 两代对比

### 11.4.1 fentry/fexit 重写第 10 章实验

计时仍需两个程序（fexit 拿不到"入口时刻"），但配对 map 之外，
fexit 顺手把**这次读操作读了多少字节**也带上了——同一份日志
同时有输入与输出：

```c
// vfs_lat_fe.bpf.c —— 版本二
SEC("fentry/vfs_read")
int BPF_PROG(fe_vfs_read)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &id, &ts, BPF_ANY);   // 同一张配对 map
    return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(fx_vfs_read, struct file *file, char __user *buf,
             size_t count, ssize_t ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *ts = bpf_map_lookup_elem(&start, &id);
    if (!ts) return 0;
    bpf_map_delete_elem(&start, &id);
    __u64 us = (bpf_ktime_get_ns() - *ts) / 1000;
    // kprobe 版做不到：一条日志 = 耗时 + 输入 + 输出
    bpf_printk("vfs_read(%lu) = %ld, took %llu us", count, ret, us);
    return 0;
}
```

```go
// Go 挂载：AttachTracing（AttachType 可省略，按程序推断）
fe, err := link.AttachTracing(link.TracingOptions{Program: objs.FeVfsRead})
if err != nil { log.Fatal(err) }
defer fe.Close()

fx, err := link.AttachTracing(link.TracingOptions{Program: objs.FxVfsRead})
if err != nil { log.Fatal(err) }
defer fx.Close()
```

（`TracingOptions.AttachType` 可显式指定 `AttachTraceFEntry/FExit/
ModifyReturn/RawTp`；另有 `Cookie` 字段供 `bpf_get_attach_cookie`
区分多点挂载，5.15+。）

### 11.4.2 十四维全面对比与选型口诀

| 维度 | kprobe / kretprobe | fentry / fexit |
|---|---|---|
| 底层机制 | 断点陷阱（int3+单步，两次异常/命中） | trampoline 直调（无异常） |
| 每命中开销 | 高（百 ns 级） | **近零** |
| 内核版本 | 4.1+（几乎无处不在） | **5.5+ 且带 BTF** |
| 参数获取 | pt_regs 取**值**（PT_REGS 宏） | BTF 原型按名取，**指针可直接解引用** |
| 读参数指向的内存 | 必须 `bpf_probe_read_kernel` | 直接 `file->f_mode` |
| 返回值 | 仅 kretprobe 的 RC，**拿不到参数** | fexit **参数+返回值同时拿** |
| "参数+返回值"成本 | 两程序+配对 map+双探针 | 一个 fexit |
| 改返回值 | 不能 | fmod_ret（白名单） |
| 目标耦合性 | kallsyms 符号（漂移**静默失效**） | BTF 签名（不匹配**加载即失败**） |
| 可探测范围 | 几乎所有 kallsyms 函数 | BTF 中存在的函数 |
| 内联函数 | 不可（Offset hack 维护差） | 不可（同样需实体） |
| 挂另一个 BPF 程序 | 不能 | freplace |
| 用户态对应 | uprobe/uretprobe | — |
| 生态成熟度 | 最老最通用（BCC 存量巨大） | 新，演进方向 |

**选型口诀**：内核 ≥5.5 且有 BTF → 默认 fentry/fexit（快、安全、
代码少）；老内核/无 BTF/目标不在 BTF/挂用户态 → kprobe 族；只要
返回值且低频 → kretprobe 也够；高频热路径 → 必须避开断点开销。
一句话：**kprobe 是到处能用的瑞士军刀，fentry 是新内核上的正确
答案**。

## 11.5 LSM：把安全策略放进内核

fentry 机制还有一个重量级应用：**LSM 程序（5.7+）**。挂到内核
安全模块的钩子点（如 `security_file_open`、`security_bprm_check`），
返回非 0 即**阻断**操作——这就是 Falco/Tetragon 做"实时拦截容器
逃逸"的底座。要点三条：钩子列表即 LSM 框架的 hook 集合（`cat
/sys/kernel/security/lsm` 确认启用）；返回值语义是"允许/拒绝"
（与第 9 章 cgroup 同族）；挂载同样走 `link.AttachLSM`，link 化
生命周期。ruport 未涉及，但它是"观测→干预"的自然延伸，值得知道
边界在哪。

## 11.6 小结与练习

**小结**：trampoline 是两套调用约定之间的翻译官，按 BTF 原型生成
转换代码，让内核"直接调用"你的程序——近零开销、类型安全、签名
不符加载即败。四兄弟分工：fentry 拿参数、fexit 参数+返回值、
fmod_ret 改返回值（白名单）、freplace 挂/换另一个 BPF 程序。
耗时统计版本二用同样结构换来了翻倍的信息量。选型按内核与 BTF
可用性走，14 维对比表随查随用。

**练习**：
1. 跑通版本二，对比两版 trace_pipe 输出与 `bpftool prog show` 里
   的 run_time_ns（开启 bpf_stats，第 15 章有步骤）——亲手量化
   两代探针的开销差；
2. 把版本二的 printk 换成 ringbuf 事件（结构体带 count/ret/us
   三字段），Go 侧解码打印；
3. 用 freplace 挂到你第 7 章的 XDP 防火墙上，观察它的每次调用
   与返回值（排障网络程序的姿势）；
4. 思考题：为什么 fexit 能同时拿到参数与返回值，而 kretprobe
   不能？（从 11.3 的"包裹式调用"图推演——参数快照保存在哪、
   kretprobe 执行时寄存器里还剩什么。）

---

第四篇完结。观测的两大体系已经贯通。第五篇下到最底层——
类型系统、map 源码、工程化与调试，把"会用"变成"精通"。
