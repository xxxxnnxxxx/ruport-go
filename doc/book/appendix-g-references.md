# 附录 G · 参考资料与致谢

## G.1 内核与规范文档（一手资料）

- **BPF & XDP Reference Guide**（Cilium 官方，最系统的 BPF 网络参考）
- **Kernel BPF Documentation**
  （`Documentation/bpf/`：概念、verifier、helper、ringbuf 设计文档）
- `include/uapi/linux/bpf.h`——程序/map/attach 枚举与 helper 原型的
  最终真源；`tools/include/uapi` 同步版
- **BPF Design Q&A**（内核文档，设计取舍的第一手解释）

## G.2 库与工具文档

- **cilium/ebpf**（Go）：`pkg.go.dev/github.com/cilium/ebpf`——本书
  所有 Go API 以 v0.22.0 为准（写作时逐一对照源码核实）
- **bpf2go**：`cmd/bpf2go/doc.go` 与 `-h` 输出
- **libbpf**（C 对照系）：`github.com/libbpf/libbpf` 与 Andrii
  Nakryiko 的 **BPF CO-RE 系列博客**（libbpf 时代的设计说明）
- **bpftool**：man bpftool + 子命令 `-h`
- **bpftrace** 一行语言参考（高层观测工具，BPF 的"胶水层"）

## G.3 经典系列文章（本书借鉴并已注明出处的素材）

- **ArthurChiao's Blog《BPF 进阶笔记》系列**（2021-2022，基于内核
  5.8/5.10）——本书第 10-13 章部分素材（断点机制、hashtab 源码走读、
  printk 内幕、trampoline 论证）整理自该系列，原文：
  https://arthurchiao.art（站内搜索"BPF 进阶笔记"）
- BPF: A Tour of Program Types（Gregg，程序类型经典综述）
- BPF Features by Linux Kernel Version（bcc 维护的版本矩阵）
- Facebook Katran、Cloudflare XDP DDoS 系列实践文（生产案例）
- Andrii Nakryiko: Improving bpf_printk()（printk 演进）

## G.4 书籍

- 《Learning eBPF》（Liz Rice, O'Reilly）——入门姊妹书（libbpf/C 视角）
- 《Systems Performance》（Brendan Gregg）——观测方法论背景
- 《Linux Kernel Development》——内核基础（LKM 对照章节的背景）

## G.5 本仓库相关

- ruport（C/libbpf 原版）：本项目移植来源
- ruport-go：本书实战底盘；`logs/` 目录保存了全部开发决策日志
  （含三次真实踩坑的完整记录，第 14 章引用）
- 旧专题文档 `doc/00~14`：成书前的资料沉淀，处置方案见提交记录

## G.6 致谢

感谢 eBPF 社区（内核开发者、libbpf/cilium 团队、bcc/bpftrace
生态）与上述资料的作者——本书站在它们的肩膀上完成重组与
本地化。感谢您读到这里；欢迎在仓库中提交 issue 与改进。
