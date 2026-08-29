//go:build linux

// Package netnsx 提供 ruport netns 隐藏模式所需的网络命名空间管理：
// 创建 named netns、veth 对、地址/路由配置，并关闭 veth 的 TX 校验和
// 卸载（BPF 无法处理 CHECKSUM_PARTIAL 包，见 doc/design/01 与书第 8 章）。
// 全部纯 Go 实现，不依赖 ip/ethtool 等外部命令。
package netnsx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// NS 保存一次 Ensure 建立的命名空间信息。Fd 在运行期间保持打开，
// 否则 named netns 不会被内核销毁，但句柄泄漏；显式 Close 释放。
type NS struct {
	Name      string         // named netns 名（/var/run/netns/<name>）
	HostVeth  string         // 宿主侧 veth 名
	NsVeth    string         // ns 侧 veth 名
	IPNet     *net.IPNet     // ns 内网段
	GatewayIP net.IP         // 宿主侧网关地址（网段内 .1）
	ServiceIP net.IP         // ns 内服务地址（网段内 .2）
	Fd        netns.NsHandle // 命名空间句柄
}

// vethNames 由 netns 名派生设备名（内核 IFNAMSIZ 限制 15 字符，
// 只保留小写字母与数字，超长截断）。
func vethNames(name string) (host, peer string) {
	base := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, strings.ToLower(name))
	if len(base) > 9 {
		base = base[:9]
	}
	return base + "-host", base + "-ns"
}

// Ensure 幂等建立 netns 隐藏模式所需的全部网络设施：
// named netns、veth 对（宿主 .1 网关 / ns 内 .2 服务）、ns 内 lo 与
// 默认路由、关闭 veth 两端 TX 校验和卸载、打开 ip_forward。
// 重复调用安全（已存在则复用）。失败时调用方无需 Destroy（仅句柄需 Close）。
func Ensure(name string, subnet *net.IPNet) (*NS, error) {
	ns := &NS{Name: name, IPNet: subnet}
	ns.HostVeth, ns.NsVeth = vethNames(name)

	// 1) named netns：已存在则复用，否则按 ip netns add 的配方创建
	// （unshare + 将 /proc/self/ns/net 绑定挂载到 /var/run/netns/<name>，
	// vishvananda/netns v0.0.5 只提供随机名的 New()）
	fd, err := ensureNamedNS(name)
	if err != nil {
		return nil, fmt.Errorf("create netns %s: %w", name, err)
	}
	ns.Fd = fd

	// 2) veth 对：宿主侧不存在则创建，peer 若仍在宿主则移入 ns
	if _, err := netlink.LinkByName(ns.HostVeth); err != nil {
		if err := netlink.LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: ns.HostVeth},
			PeerName:  ns.NsVeth,
		}); err != nil {
			ns.Close()
			return nil, fmt.Errorf("create veth pair %s<->%s: %w", ns.HostVeth, ns.NsVeth, err)
		}
	}
	if peer, err := netlink.LinkByName(ns.NsVeth); err == nil {
		if err := netlink.LinkSetNsFd(peer, int(fd)); err != nil {
			ns.Close()
			return nil, fmt.Errorf("move %s into netns: %w", ns.NsVeth, err)
		}
	}

	// 网段内前两个地址作为网关(.1)与服务(.2)，按 /24 口径取最后一段
	network := subnet.IP.Mask(subnet.Mask)
	gw := net.IP(append([]byte(nil), network...))
	svc := net.IP(append([]byte(nil), network...))
	gw[3]++
	svc[3] += 2
	ns.GatewayIP, ns.ServiceIP = gw, svc

	// 3) 宿主侧：网关地址 + up
	hostLink, err := netlink.LinkByName(ns.HostVeth)
	if err != nil {
		ns.Close()
		return nil, fmt.Errorf("find %s: %w", ns.HostVeth, err)
	}
	if err := netlink.AddrAdd(hostLink, &netlink.Addr{IPNet: &net.IPNet{IP: gw, Mask: subnet.Mask}}); err != nil &&
		!errors.Is(err, syscall.EEXIST) {
		ns.Close()
		return nil, fmt.Errorf("addr on %s: %w", ns.HostVeth, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		ns.Close()
		return nil, fmt.Errorf("set %s up: %w", ns.HostVeth, err)
	}

	// 4) ns 侧：服务地址 + lo + 默认路由（ns 专属 handle，不切当前线程）
	h, err := netlink.NewHandleAt(fd)
	if err != nil {
		ns.Close()
		return nil, fmt.Errorf("open netlink handle in netns: %w", err)
	}
	defer h.Delete()
	nsLink, err := h.LinkByName(ns.NsVeth)
	if err != nil {
		ns.Close()
		return nil, fmt.Errorf("find %s in netns: %w", ns.NsVeth, err)
	}
	if err := h.AddrAdd(nsLink, &netlink.Addr{IPNet: &net.IPNet{IP: svc, Mask: subnet.Mask}}); err != nil &&
		!errors.Is(err, syscall.EEXIST) {
		ns.Close()
		return nil, fmt.Errorf("addr on %s: %w", ns.NsVeth, err)
	}
	if err := h.LinkSetUp(nsLink); err != nil {
		ns.Close()
		return nil, fmt.Errorf("set %s up: %w", ns.NsVeth, err)
	}
	if lo, err := h.LinkByName("lo"); err == nil {
		_ = h.LinkSetUp(lo)
	}
	if err := h.RouteAdd(&netlink.Route{LinkIndex: nsLink.Attrs().Index, Gw: gw}); err != nil &&
		!errors.Is(err, syscall.EEXIST) {
		ns.Close()
		return nil, fmt.Errorf("default route in netns: %w", err)
	}

	// 5) 关闭 veth 两端 TX 校验和卸载（本方案成立的关键前提）：
	// ns 侧操作需把套接字建在目标命名空间内
	if err := DisableTxChecksum(ns.HostVeth); err != nil {
		ns.Close()
		return nil, fmt.Errorf("disable tx checksum on %s: %w", ns.HostVeth, err)
	}
	if err := WithNetNS(fd, func() error { return DisableTxChecksum(ns.NsVeth) }); err != nil {
		ns.Close()
		return nil, fmt.Errorf("disable tx checksum on %s: %w", ns.NsVeth, err)
	}

	// 6) ip_forward：转发到 ns 依赖它；不自动还原（netns 持久存在）
	if v, err := readIPForward(); err == nil && v == 0 {
		_ = writeIPForward(1)
	}
	return ns, nil
}

// ensureNamedNS 打开既有的 named netns，不存在则创建（ip netns add 同款配方）。
func ensureNamedNS(name string) (netns.NsHandle, error) {
	if fd, err := netns.GetFromName(name); err == nil {
		return fd, nil
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return -1, err
	}
	defer orig.Close()
	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		return -1, err
	}
	defer netns.Set(orig)

	if err := os.MkdirAll("/var/run/netns", 0755); err != nil {
		return -1, err
	}
	path := "/var/run/netns/" + name
	f, err := os.Create(path)
	if err != nil {
		return -1, err
	}
	f.Close()
	if err := unix.Mount("/proc/self/ns/net", path, "bind", unix.MS_BIND, ""); err != nil {
		os.Remove(path)
		return -1, err
	}
	return netns.GetFromName(name)
}

// Destroy 彻底销毁 netns 与 veth 对（--ns-destroy 用）。
func Destroy(name string) error {
	host, _ := vethNames(name)
	if link, err := netlink.LinkByName(host); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("del %s: %w", host, err)
		}
	}
	path := "/var/run/netns/" + name
	if _, err := os.Stat(path); err == nil {
		if err := unix.Unmount(path, 0); err != nil && !errors.Is(err, syscall.EINVAL) {
			return fmt.Errorf("umount %s: %w", path, err)
		}
		os.Remove(path)
	}
	return nil
}

// WithNetNS 在指定 netns 内执行 fn（临时切换当前线程的命名空间，结束恢复）。
// 调用方不应在 fn 中做任何假设"仍在宿主"的操作。
func WithNetNS(fd netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer orig.Close()
	if err := netns.Set(fd); err != nil {
		return err
	}
	defer netns.Set(orig)
	return fn()
}

// StartInNS 在指定 netns 内启动子进程（继承切换后线程的命名空间）。
// argv 为已切分的参数，不走 shell、不支持引号语法。
func StartInNS(fd netns.NsHandle, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty argv")
	}
	var cmd *exec.Cmd
	err := WithNetNS(fd, func() error {
		cmd = exec.Command(argv[0], argv[1:]...)
		return cmd.Start()
	})
	if err != nil {
		return nil, err
	}
	return cmd, nil
}

// Close 释放命名空间句柄（不销毁 netns 本身，named netns 持续存在）。
func (n *NS) Close() {
	if n.Fd.IsOpen() {
		n.Fd.Close()
	}
}

func readIPForward() (int, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return -1, err
	}
	switch strings.TrimSpace(string(b)) {
	case "0":
		return 0, nil
	case "1":
		return 1, nil
	}
	return -1, fmt.Errorf("unexpected ip_forward value %q", string(b))
}

func writeIPForward(v int) error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward",
		[]byte(fmt.Sprintf("%d", v)), 0644)
}
