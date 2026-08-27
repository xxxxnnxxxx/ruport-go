// Package bpf 存放 bpf2go 生成的 eBPF 对象绑定。
//
// 该包的 Xdp*/Tc* 文件由 `make generate` 调用 cilium/ebpf 的 bpf2go
// 工具生成（对应原 ruport 项目的 bpftool gen skeleton），生成前仓库中
// 只有本说明文件与手写的加载封装 loader.go。
package bpf
