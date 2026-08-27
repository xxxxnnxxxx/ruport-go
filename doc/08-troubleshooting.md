# 08 · 常见问题与排查手册

按“症状 → 根因 → 修法”组织，覆盖 verifier 拒绝、权限、字节序/布局、
挂载残留、调试工具五类。示例多为真实报错原文（裁剪）。

---

## 1. verifier 拒绝（加载期，`BPF_PROG_LOAD` 报 EINVAL + 日志）

### 1.1 越界读包

```
invalid access to packet, off 14 size 20, R2(id=2, off=14, r=0)
```

症状：程序里读 IP/TCP 头时挂。根因：读取前没有紧邻的边界检查，或
检查用的长度与读取长度不一致。修法模板：

```c
// 坏：直接读
struct iphdr *iph = data + ETH_HLEN;
use(iph->protocol);

// 好：先证后读
struct iphdr *iph = data + ETH_HLEN;
if ((void *)(iph + 1) > data_end)
    return XDP_PASS;
use(iph->protocol);
```

动态长度（IP 选项、TCP 选项）要再用 `ihl*4/doff*4` 检查一次；一次证明
一大段的写法见 ruport 的
`(data_end - (void*)pdata) < 12 + sizeof(struct Message)`。

### 1.2 未初始化寄存器/栈

```
invalid read from stack off r6-8 size 8
```

根因：读了没写过的局部变量（常见于只填了部分字段就 `bpf_map_update`）。
修法：定义后立刻 `= {}` 或逐字段赋值；`__builtin_memset` 也可。

### 1.3 循环相关

```
back-edge from insn 20 to 4
loop detected
```

根因：内核 < 5.3 完全不允许循环；5.3+ 允许但边界必须可证。修法：
`#pragma unroll`、固定上界 `for (int i = 0; i < 64; i++)`，或老内核用
尾调用分段（ruport pidhide 的做法）。

### 1.4 指针算术/泄漏

```
R1 pointer arithmetic on map_value_or_null prohibited
R0 leaks addr into map
invalid argument: R2 subprog pointer type prohibited
```

根因分类：对可能为 NULL 的 lookup 结果做算术（先判空）；把指针存进
用户态可读 map / 当返回值（存“数值化的指针”也不行）。修法：判空后再
用；需要传地址类信息就传 ID/index。

### 1.5 程序规模/复杂度

```
BPF program is too large. Processed 1000001 insn
exceeded max instructions per thread 4096   # <5.2 内核
```

修法：拆尾调用、减少展开循环、升级内核（5.2+ 100 万条）、`-O2` 编译。

### 1.6 helper 不允许

```
helper call is not allowed in probe
```

根因：程序类型与 helper 白名单不匹配（如 XDP 里用
`bpf_probe_read_user`）。查 `bpf_helper_defs.h` 注释里的可用程序类型
列表，或换程序类型。

### 1.7 license

```
cannot call GPL-only function from proprietary program
```

修法：`char _license[] SEC("license") = "GPL";`（ruport 全部 GPL 声明）。

**拿全量日志**：cilium/ebpf 默认只在失败时带日志；要主动看全文用
`ProgramOptions{LogLevel: ebpf.LogLevelBranch|ebpf.LogLevelStats}`，
成功后读 `Program.VerifierLog`（见 doc/02 §5）。

## 2. 权限与 memlock

| 报错 | 根因 | 修法 |
|---|---|---|
| `bpf() failed: operation not permitted`，日志为空 | 非 root 且 `unprivileged_bpf_disabled≥1`；容器缺 `CAP_BPF/CAP_SYS_ADMIN` | sudo；或给二进制 capability：`setcap cap_bpf,cap_net_admin,cap_sys_admin+ep ./ruport`（注意与脚本解释器不兼容） |
| `warning: rlimit memlock=0 ... unable to change` | <5.11 内核 memlock 不足 | 代码里 `rlimit.RemoveMemlock()`（ruport 已做）；或 `ulimit -l unlimited` |
| tracepoint attach `permission denied` | 缺 tracefs 访问（容器常见） | 挂载 `/sys/kernel/tracing`，加 `CAP_PERFMON` |

Docker 里跑的最小集：`--privileged` 或
`--cap-add=BPF --cap-add=NET_ADMIN --cap-add=PERFMON` +
`/sys/fs/bpf` 与 `/sys/kernel/tracing` 的挂载。

## 3. 数据错乱（字节序/布局类，最阴险）

症状画像：

- map lookup 永远 miss，`Update` 后 `bpftool map dump` 里有数据但 Go
  读不到（key 布局不一致）；
- 端口显示成 `12345 → 14640`（0x39 0x30 ↔ 0x30 0x39，字节反转的经典
  相差 0x??00）；
- IP 显示成 `1.2.3.4 → 4.3.2.1` 或完全乱码（value 偏移错位）；
- 字段值“整体左移/右移 8 位”（pack 与不 pack 差异）。

排查三板斧：

```bash
# ① 看内核里的裸字节（终极真相）
sudo bpftool map dump name message_map
# ② 看 BTF 布局（C 侧实际偏移）
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | head
llvm-dwarfdump / bpftool prog dump 也可看 .o 的类型
# ③ 与 Go 序列化结果比对
fmt.Printf("% x", buf)   // 打印 LookupBytes 拿到的原始字节
```

修法对应关系见 doc/04 §7：布局（pack/对齐）、字节序（__be 字段转换）、
key 组成。**ruport 专用口诀**：给人看走 `ip2str/toHostPort`，算 key 用
原始值。

## 4. 挂载类

| 症状 | 根因 | 处理 |
|---|---|---|
| 二次启动 `FilterAdd: netlink receive: file exists` | 上次退出没删 filter（崩溃/被 kill -9） | 手动清：`tc qdisc del dev eth0 clsact`；或先 FilterDel 再加 |
| 程序退出后改包规则仍在生效 | 经典 tc filter 持程序引用，不随进程死 | 设计上必须信号清理 + 提供 uninstall 兜底 |
| XDP `failed to attach: device or resource busy` | 旧 XDP 程序占用 / 模式切换冲突 | `ip link set dev eth0 xdp off` 后重挂 |
| XDP `cannot use native mode, falling back`类 | 驱动不支持 native | 用 `XDPGenericMode`（ruport 默认） |
| tcx `operation not supported` | 内核 < 6.6 | 用 clsact 方案；`link.HaveTCX()` 预判 |
| veth/容器里 XDP 不生效 | veth 的 native XDP 需两端都配（4.19+）且常有怪癖 | generic 模式最稳 |

**崩溃残留的完整清理**（存成脚本备用）：

```bash
#!/bin/sh
# ruport-clean.sh：清掉 ruport-go 可能残留的全部内核态
IFACE=${1:-eth0}
tc qdisc del dev "$IFACE" clsact 2>/dev/null          # 连带删掉 tc bpf filter
ip link set dev "$IFACE" xdp off 2>/dev/null           # 摘 XDP
# 删除本程序遗留的 map/prog（按名过滤，谨慎）
bpftool map show | awk '$0 ~ /message_map|router_map/ {print $0}'
```

## 5. 工具箱

```bash
# 万能三连：现在内核里有什么？
sudo bpftool prog show
sudo bpftool map show
sudo bpftool link show
sudo bpftool net show                    # xdp/tc 挂载总览

# 挂载细节
tc qdisc show dev eth0
tc filter show dev eth0 ingress
tc filter show dev eth0 egress

# map 内容（裸字节，排布局 bug 神器）
sudo bpftool map dump name router_map
sudo bpftool map dump pinned /sys/fs/bpf/xxx

# 程序运行统计（先开 bpf_stats）
echo 1 | sudo tee /proc/sys/kernel/bpf_stats_enabled
sudo bpftool prog show    # run_time_ns / run_cnt

# bpf_printk 输出（ruport 的 bpfprint 宏）
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 程序反汇编（验证生成了什么指令）
sudo bpftool prog dump xlated id <ID>
sudo bpftool prog dump jited id <ID>     # JIT 后的本机码

# 单测运行程序（不挂载）
# Go: p.Run(&ebpf.RunOptions{Data: frame})

# 特性探测
sudo bpftool feature probe kernel full   # 一次性列出所有支持项

# 谁在用这块 BPF（排“删不掉”问题）
sudo bpftool prog pin show / ls /sys/fs/bpf/
```

## 6. Go 侧高频错误

| 报错 | 根因 | 修法 |
|---|---|---|
| `can't marshal key: ... offset N: too many bytes` | Go 结构体比 KeySize 大（布局/padding 不匹配） | 对齐字节；用 bpf2go `-type` |
| `no such file or directory`（loadXdp） | 生成文件不在/没跑 make | `make generate`；确认 `_bpfel.o` 存在 |
| `missing package, you should either set the go-package flag or the GOPACKAGE env` | make 里直调 bpf2go 没传包名 | 加 `-go-package bpf`（本仓库已修，教训记录在 git log） |
| `unexpected EOF`（binary.Read map 值） | value 结构体与 ValueSize 不符 | 同布局问题，见 §3 |
| map 读出的字符串带乱码尾巴 | 忘了截 NUL | 学 `extString`：找第一个 0 字节 |
| goroutine 泄漏在 `rd.Read()` | ringbuf 没关 | 退出路径 `rd.Close()` + 处理 `ErrClosed` |
| `objs.Close()` 后程序还挂着 | tc filter 仍引用 | 先 `FilterDel/QdiscDel` 再 Close（顺序见 doc/05 §3.2） |

## 7. Windows/WSL 备忘

- eBPF 加载与挂载**只能在 Linux**（本仓库因此只交叉编译验证、实机
  测试在 Linux 做）；
- WSL2 可用：内核 5.15+ 自带 BTF，XDP generic 与 clsact 都正常；
  注意 WSL2 的 NAT 会让外部进包的源地址改写，测试 c3 时用本机回环
  或另一台 Linux 更直观；
- 在 Windows 上想提前验证 Go 侧编译：`GOOS=linux go build ./...`
  （需要 bpf2go 生成物或临时桩，见 logs 里的实现记录）。

## 8. ruport 专属 FAQ

**Q：发指令后 message_map 没有东西？**
检查链路：c3 是否连的“对外端口”；`sudo bpftool map dump name message_map`；
XDP 是否真挂上了（`bpftool net show`）；魔术计算——c3 的 s1/s2 是奇数、
`s3=s1²+s2²` 按小端写 8 字节，手写测试客户端时最容易错这里。

**Q：路由加了但流量没被改写？**
router_map 的 key 是 `(cip<<16)|cport` 的**网络序原始值**；ingress 命中
还要求包的源 IP/源端口与之相等且 nativeport≠0。用
`bpftool map dump name router_map` 核对值；`tcpdump -i eth0 tcp port X`
看改写前后。

**Q：反弹的 nc 起不来？**
nc 必须与 ruport 同目录（`filepath.Join(cwd,"nc")`）；`ss -tnp` 看
出网连接；杀反弹用 `c3 -d -2 ...`（hiByte 置位走 killChild）。

**Q：重启 ruport 后旧的 tc filter 报 EEXIST？**
上次非正常退出残留。跑 §4 的清理脚本，或重启前先 Ctrl-C 让信号路径
完成清理。

---

至此文档完。回到 [索引](README.md)。
