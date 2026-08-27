# ruport-go eBPF 开发文档（cilium/ebpf）

本目录是一套面向开发的 cilium/ebpf（Go）参考文档，不是概览式总结：
每个主题都包含技术背景（内核机制原理）、库 API 讲解、完整示例代码与
常见报错的排查方法。API 签名以本仓库锁定的 **cilium/ebpf v0.22.0** 为准
（写作时已逐一对照该版本源码核实）。

## 目录

| 文档 | 主题 | 适合谁 |
|---|---|---|
| [01-ebpf-overview.md](01-ebpf-overview.md) | eBPF 技术背景：内核架构、虚拟机与指令集、验证器、JIT、程序类型、map 类型、BTF/CO-RE、libbpf 与 cilium/ebpf 的关系 | 零基础入门 / 需要补内核侧原理 |
| [02-cilium-ebpf-core.md](02-cilium-ebpf-core.md) | 库核心对象：CollectionSpec/Collection、Program/Map、LoadAndAssign、能力探测、verifier 日志、全局变量重写、pin | 写 Go 加载端必读 |
| [03-bpf2go.md](03-bpf2go.md) | bpf2go 工作流：全部命令行参数、Makefile/go:generate 集成、生成文件解剖、`-type` 结构体生成规则（packed/对齐/字节序） | 维护本仓库 Makefile 必读 |
| [04-maps.md](04-maps.md) | Map 深入：全部常用 API、迭代与批量、per-CPU、ringbuf/perf 事件、共享结构体的布局/对齐/字节序陷阱 | 内核↔用户态交换数据必读 |
| [05-links.md](05-links.md) | 挂载与生命周期：XDP 三种模式、TC clsact（netlink）与 tcx、tracepoint/kprobe/fentry、Link 语义与 pin | 把程序挂进内核必读 |
| [06-examples.md](06-examples.md) | 三个从零可运行的完整例子：XDP 计数器、TC 端口改写、ringbuf 事件（C + Go + 编译运行步骤） | 照着敲一遍上手 |
| [07-ruport-go-notes.md](07-ruport-go-notes.md) | 本仓库实战解析：ruport-go 每个模块逐段讲解，与原 C/libbpf 版本的对应关系 | 维护本仓库必读 |
| [08-troubleshooting.md](08-troubleshooting.md) | 常见问题：verifier 报错样例与修复、权限/memlock、字节序与对齐 bug 症状、bpftool/trace_pipe 调试 | 卡住时查这里 |
| [09-kernel-versions.md](09-kernel-versions.md) | 内核版本-特性完全对照：程序类型全表、map 类型全表、常用 helper 分组表、挂载/link、syscall 子命令、能力探测 API、目标机自查手册 | 选型/兼容性判断 |
| [10-debugging.md](10-debugging.md) | 调试信息查看完全指南：按生命周期分阶段（编译/加载/挂载/运行/统计），bpftool 逐子命令手册，bpf_printk/trace_pipe/trace_marker，四条排障动线 | 出问题必读 |
| [11-progtype-signatures.md](11-progtype-signatures.md) | 程序类型参考手册：每种类型的 hook 内核函数位置、context 签名、返回值语义、挂载方式（整理自 ArthurChiao 进阶笔记一） | 查"这个类型怎么用" |
| [12-map-internals.md](12-map-internals.md) | map 内核实现：hashtab 数据结构与增删查改源码流程、array 家族、map_ops 映射表、cgroup storage、pinning（整理自进阶笔记二/三） | 想懂 map 行为边界 |
| [13-printk-and-trampoline.md](13-printk-and-trampoline.md) | printk 内幕（5 参限制根源、.rodata 原理、trace 输出格式逐字段）与 BPF trampoline、fentry/fexit trace 另一个 BPF 程序（整理自进阶笔记四） | 调试进阶 |

> 11–13 章整理自外部文章（ArthurChiao's Blog《BPF 进阶笔记》系列，
> 原文见 https://arthurchiao.art），各章开头有出处与校订说明。

## 推荐阅读路径

- **第一次接触 eBPF**：01 → 06（跟着敲）→ 07。
- **只用 Go、C 侧已有人维护**：02 → 03 → 04 → 05。
- **接手维护 ruport-go**：07 → 08 → 需要哪块补哪块。
- **程序加载被拒/行为诡异**：直接查 08，需要系统方法再看 10。
- **不确定目标内核支持某特性**：查 09（§9 有自查命令）。
- **想深入内核侧原理**：11（类型与钩子）→ 12（map 实现）→ 13（printk/trampoline）。

## 约定

- 文中 Go API 均来自 `github.com/cilium/ebpf`、`github.com/cilium/ebpf/link`、
  `github.com/cilium/ebpf/ringbuf`、`github.com/cilium/ebpf/perf`；
  netlink 相关来自 `github.com/vishvananda/netlink`。
- 内核版本要求统一写成 “kernel X.Y+”，指 `Kconfig` 功能合入的主线版本；
  发行版 backport 可能提前，以 `bpftool feature probe` 实测为准。
- 所有示例假设 Linux + root（或 `CAP_BPF`/`CAP_SYS_ADMIN` 等 capability）、
  clang ≥ 12、Go ≥ 1.24。
