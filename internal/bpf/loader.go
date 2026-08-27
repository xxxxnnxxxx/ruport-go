//go:build linux

package bpf

import "github.com/cilium/ebpf"

// LoadXdpObjects 加载并验证 XDP eBpf 程序（xdp_parse + message_map）。
// 封装 bpf2go 生成的 loadXdpObjects，等价于原项目的
// ruport_xdp__open()/ruport_xdp__load()。
func LoadXdpObjects(opts *ebpf.CollectionOptions) (*XdpObjects, error) {
	return loadXdpObjects(opts)
}

// LoadTcObjects 加载并验证 TC eBPF 程序（tc_ingress/tc_egress + router_map）。
// 封装 bpf2go 生成的 loadTcObjects，等价于原项目的
// ruport_tc__open()/ruport_tc__load()。
func LoadTcObjects(opts *ebpf.CollectionOptions) (*TcObjects, error) {
	return loadTcObjects(opts)
}
