//go:build linux

package netnsx

import (
	"encoding/binary"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// ethtool UAPI（linux/ethtool.h）的最小子集：仅实现关闭指定网卡的
// tx-checksumming 特性，走 SIOCETHTOOL ioctl，避免依赖外部 ethtool 命令。
const (
	ethGSsetInfo  = 0x37 // ETHTOOL_GSSET_INFO
	ethGStrings   = 0x1b // ETHTOOL_GSTRINGS
	ethSFeatures  = 0x3b // ETHTOOL_SFEATURES
	ethSSFeatures = 4    // ETH_SS_FEATURES
	ethGStringLen = 32   // ETH_GSTRING_LEN
	siocEthtool   = 0x8946
)

type ifreq struct {
	Name [16]byte
	Data uintptr
}

// DisableTxChecksum 关闭指定网卡的 tx-checksumming 特性。
// 必须在目标网卡所在的命名空间内调用（ioctl 按套接字的 netns 解析网卡名）。
// 优先走 ioctl（零外部依赖）；失败时回退到系统 ethtool 命令。
func DisableTxChecksum(ifname string) error {
	if err := disableTxChecksumIoctl(ifname); err != nil {
		log.Printf("netnsx: ethtool ioctl failed on %s (%v), fallback to ethtool command", ifname, err)
		return disableTxChecksumCmd(ifname)
	}
	return nil
}

// disableTxChecksumCmd 回退路径：ethtool -K <if> tx off。
// 子进程继承当前线程的命名空间，ns 侧调用同样适用。
func disableTxChecksumCmd(ifname string) error {
	out, err := exec.Command("ethtool", "-K", ifname, "tx", "off").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ethtool -K %s tx off: %v: %s", ifname, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func disableTxChecksumIoctl(ifname string) error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(s)

	idx, err := featureIndex(s, ifname, "tx-checksumming")
	if err != nil {
		return err
	}

	// ETHTOOL_SFEATURES：features 数组每块 {valid, requested} 各 u32，
	// valid 置位 + requested 清位即"请求关闭"该特性
	blocks := idx/32 + 1
	buf := make([]byte, 8+blocks*8)
	binary.LittleEndian.PutUint32(buf[0:], ethSFeatures)
	binary.LittleEndian.PutUint32(buf[4:], uint32(blocks))
	off := 8 + (idx/32)*8
	binary.LittleEndian.PutUint32(buf[off:], 1<<(uint(idx)%32)) // valid
	binary.LittleEndian.PutUint32(buf[off+4:], 0)               // requested = 关闭

	if err := ioctlEthtool(s, ifname, unsafe.Pointer(&buf[0])); err != nil {
		return fmt.Errorf("ETHTOOL_SFEATURES: %w", err)
	}
	return nil
}

// featureIndex 通过 GSSET_INFO + GSTRINGS 查询特性名对应的位索引
// （特性索引跨内核版本不稳定，必须按名查询）。
func featureIndex(s int, ifname, want string) (int, error) {
	// 特性个数
	var ssi struct {
		Cmd, Reserved uint32
		SsetMask      uint64
		Data          [1]uint32
	}
	ssi.Cmd = ethGSsetInfo
	ssi.SsetMask = 1 << ethSSFeatures
	if err := ioctlEthtool(s, ifname, unsafe.Pointer(&ssi)); err != nil {
		return 0, fmt.Errorf("ETHTOOL_GSSET_INFO: %w", err)
	}
	count := int(ssi.Data[0])

	// 特性名表
	buf := make([]byte, 12+count*ethGStringLen)
	binary.LittleEndian.PutUint32(buf[0:], ethGStrings)
	binary.LittleEndian.PutUint32(buf[4:], ethSSFeatures)
	binary.LittleEndian.PutUint32(buf[8:], uint32(count))
	if err := ioctlEthtool(s, ifname, unsafe.Pointer(&buf[0])); err != nil {
		return 0, fmt.Errorf("ETHTOOL_GSTRINGS: %w", err)
	}
	names := buf[12:]
	first := ""
	for i := 0; i < count; i++ {
		b := names[i*ethGStringLen : (i+1)*ethGStringLen]
		end := 0
		for end < len(b) && b[end] != 0 {
			end++
		}
		if string(b[:end]) == want {
			return i, nil
		}
		if i == 0 {
			first = string(b[:end])
		}
	}
	// 附带诊断信息：实际拿到的条目数与首条名，便于定位 ioctl 路径问题
	return 0, fmt.Errorf("feature %q not found on %s (count=%d, first=%q)",
		want, ifname, count, first)
}

func ioctlEthtool(s int, ifname string, data unsafe.Pointer) error {
	var ifr ifreq
	copy(ifr.Name[:], ifname)
	ifr.Data = uintptr(data)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(s), siocEthtool, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}
