# 第 15 章 版本兼容与调试方法论

> 最后一章方法论。两个主题看似无关，实则同源：都关于"**你的
> 认知与内核现实的落差**"——版本兼容处理"我以为的特性内核有没有"，
> 调试体系处理"我以为的程序行为内核怎么看"。本章之后，全书
> 知识将收束到 ruport 实战。

## 15.1 版本号 ≠ 能力：backport 的世界

第 1 章的时间线给了"主线哪个版本有什么"。但落到生产你会遇到
两个反直觉现实：

1. **版本号高的可能没有**：厂商内核可能裁剪（kconfig 关闭 BTF、
   禁用某 attach）；
2. **版本号低的可能有**：RHEL/Ubuntu 会把新特性 backport 进老
   版本号内核（6.1 的机器带着 6.6 的 tcx 并不稀奇）。

所以判断只有一个黄金标准：**问目标内核本人**。三步自查：

```bash
uname -r                                            # ① 我在哪
ls -l /sys/kernel/btf/vmlinux                       # ② BTF 有没有（CO-RE/fentry前提）
sudo bpftool feature probe full | grep -i <特性名>   # ③ 这台机器到底会什么
```

单点探测的精确姿势：

```bash
sudo bpftool feature probe map_type  name ringbuf
sudo bpftool feature probe prog_type name xdp
sudo bpftool feature probe helper    name bpf_probe_read_kernel
```

## 15.2 能力探测与降级设计（features 包）

Go 侧的等价物是 `github.com/cilium/ebpf/features`（v0.22 实测
导出，结果进程内缓存）：

```go
err := features.HaveMapType(ebpf.RingBuf)
err = features.HaveProgramType(ebpf.Tracing)
err = features.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbStoreBytes)
err = features.HaveBatchAPI()
err = features.HaveBoundedLoops()
err = features.HaveBPFLinkKprobeMulti()   // 另有 UprobeMulti/KprobeSession
```

**错误语义必须用对**，这是降级逻辑不出 bug 的关键：

```
 err == nil              → 支持，走主路径
 err == ErrNotSupported  → 确定不支持，走降级路径
 其他 err                → 探测失败（常见权限不足）！≠ 不支持，
                           应当报错而非静默降级 ★新手大坑
```

标准降级骨架（ruport 若要兼容老内核就该长这样）：

```go
var opts ebpf.CollectionOptions

switch err := features.HaveMapType(ebpf.RingBuf); {
case nil:
    // 主路径：ringbuf 事件
case errors.Is(err, ebpf.ErrNotSupported):
    // 降级路径：perf event array（第 6 章两代通道）
default:
    return fmt.Errorf("probe ringbuf: %w", err)   // 探测失败别吞
}
```

版本矩阵的完整对照（程序类型/map/helper/挂载/子命令×内核版本）
见**附录 E**——正文不堆表，写作口径同样适用阅读：先探测，后查表。

## 15.3 分阶段调试体系

全书散落的调试手段，按"程序生命周期"收成一张总表。**出问题时
先定位阶段，再用该阶段的工具**——这是调试的排队分诊法：

```
 阶段         典型症状                 首选工具（详见附录D/F）
 ─────────────────────────────────────────────────────────────
 ① 编译期     clang 报错/生成失败       clang -E/-S、llvm-readelf、
                                       bpftool btf dump file xx.o
 ② 加载期     LoadAndAssign 返回错误    verifier 日志（第3章三层读法）、
                                       dmesg、strace -e bpf
 ③ 挂载期     挂上了但没生效            bpftool net/link、tc filter、
                                       ip link（第7/8章各命令）
 ④ 运行期     生效了但行为/数据不对     bpf_printk+trace_pipe、
                                       bpftool map dump（第4章三板斧）
 ⑤ 性能期     对但慢/丢事件            bpf_stats(run_time_ns)、
                                       dump xlated、Remaining（第6章）
```

分诊三连（对着内核问三个问题）：

```bash
sudo bpftool prog show     # 我的程序在吗？被调用几次？(开 bpf_stats)
sudo bpftool map show      # 我的 map 在吗？
sudo bpftool net show      # 挂载关系在吗？（xdp/tc 一览）
```

## 15.4 printk 家族内幕与 bpftool

### 15.4.1 bpf_printk 的三重限制，个个有来历

```c
bpf_printk("pid=%d name=%s", pid, comm);   // 最多 3 个参数——为什么？
```

1. **3 参上限**：底层 helper `bpf_trace_printk(fmt, fmt_size, a, b, c)`
   只有 5 个形参（`BPF_CALL_5` 宏，eBPF 调用约定 R1~R5），fmt 与
   fmt_size 已占两席——第 11 章 trampoline 原理的直接推论；
2. **5.2 门槛**：`bpf_printk` 宏把格式串放进 `.rodata` 全局区
   （省 512 字节栈），老内核报一条谜语：
   `map .rodata: ... requires >= v5.2`——现在你能一眼翻译它；
3. **格式符受限**：5.10 支持 `%d %u %x %ld %lu %lx %lld %llu
   %llx %p %s`，**不支持宽度/精度**（`%5d` 直接 -EINVAL 且无输出）。
   5.9 起自动换行；超 3 参用 `bpf_snprintf`（5.9）先格式化、
   或 `bpf_trace_vprintk`（5.16）。

输出去向与逐字段解读（排障基本功）：

```
telnetd-470  [001]  .N..  419421.045894:  0x00000001:  <你的内容>
   │          │      │         │               │           │
 进程-pid    CPU   选项位     单调时钟        BPF伪造的ip   printk产物
                   (中断/调度等)              （trace框架要求有ip列）
# cat /sys/kernel/debug/tracing/trace_pipe   ← 实时流（trace 文件被
#                                              打开时会丢日志，用 pipe）
```

`trace_marker` 是隐藏好物：用户态 `echo "marker" > .../trace_marker`
可往同一时间线打点——内核侧与用户侧事件对表专用。

### 15.4.2 bpftool：你的听诊器

子命令全景在附录 D，此处给最常用的五连（建议背下）：

```bash
sudo bpftool prog show                       # 全部程序
sudo bpftool prog dump xlated id <ID>        # 看验证后指令
sudo bpftool map dump name <MAP>             # map 裸字节（布局对账）
sudo bpftool link show                       # 挂载关系
sudo bpftool -j prog show | jq '.[] | select(.name=="xdp_parse")'
```

## 15.5 四条标准排障动线

全书案例浓缩成四条 checklist，照着走即可：

**动线 A：加载失败**

```
1 读 error 里的 verifier 日志（默认自带；或 LogLevel 全开）
2 日志为空 → 权限/配置（unprivileged_bpf_disabled、capability、
   memlock<5.11）
3 按报错行指令号回源码（objdump 对照），按第3章TOP5修复
```

**动线 B：挂了没生效**

```
1 bpftool net show / tc filter show —— 挂载在吗？
2 开 bpf_stats 看 run_cnt —— 被调用吗？不涨=条件不匹配/挂错方向
3 bpf_printk 打中间变量 + bpftool map dump 看状态（如路由表学习字段）
4 EEXIST/残留 → 清理重挂（tc qdisc del dev x clsact）
```

**动线 C：数据错乱**

```
1 bpftool map dump vs Go LookupBytes 十六进制对账（第4章三板斧）
2 对不上 → 布局（pack/padding）；对得上但值反 → 字节序三步口诀
3 时序（读到太早/被覆盖）→ trace_marker 打点对时间线
```

**动线 D：性能差/丢事件**

```
1 bpf_stats 定位耗时程序 → dump xlated 看指令
2 map 访问过频 → per-CPU/批量（第5章）
3 printk 调试残留删干净；ringbuf 看 Remaining 与丢弃计数（第6章）
```

## 15.6 小结与练习

**小结**：版本判断的唯一标准是问内核本人（feature probe/features
包），错误三态语义（支持/确定不支持/探测失败）决定降级还是报错；
调试先分诊五阶段再用对应工具；printk 三重限制全部可从已学原理
推导（5 参调用约定/全局变量 5.2/格式白名单）；四条动线覆盖加载、
生效、数据、性能四类问题，是全书方法论的总装。

**练习**：
1. 在你的机器跑 15.1 三步自查，写出"我的内核能力清单"；挑一个
   主线 5.8+ 的特性验证探测结果与 uname 版本的差异；
2. 给第 7 章防火墙加上 features 降级骨架（native XDP 失败退
   generic），故意用 `XDPDriverMode` 在不支持的网卡上触发降级；
3. 制造并走完动线 C：改坏一个结构体布局，用三板斧定位；
4. 思考题：为什么"探测失败"绝不能当"不支持"静默降级？
   （从安全/功能两个角度各给一个后果案例。）

---

方法论收束完毕。第六篇见：把全书的一切，装进 ruport-go。
