// Package bpf 存放 bpf2go 生成的 eBPF 对象绑定。
//
// 该包的 Xdp*/Tc* 文件由 `make generate` 调用 cilium/ebpf 的 bpf2go
// 工具生成（对应原 ruport 项目的 bpftool gen skeleton），生成前仓库中
// 只有本说明文件。由于 Makefile 使用大写 ident（Xdp/Tc），bpf2go 生成
// 的加载函数 LoadXdpObjects/LoadTcObjects 本身就是导出的（填充式
// 签名 obj any + opts），外部直接调用即可，无需手写封装。
package bpf
