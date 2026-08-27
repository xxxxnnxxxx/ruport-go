# 05 · 挂载与生命周期：XDP、TC、tracepoint 与 Link

目标：搞清“程序加载好了，怎么挂进内核、挂上之后谁保住谁、退出时怎么
干净收场”。重点是 XDP 三种模式、经典 TC clsact（vishvananda/netlink，
ruport-go 的做法）与 tcx（cilium/ebpf 原生，6.6+）的对照，以及 Link 的
生命周期语义。API 以 v0.22.0 实测为准。

---

## 1. 挂载方式的版图

| 挂载点 | cilium/ebpf API | 底层机制 | 版本 |
|---|---|---|---|
| XDP | `link.AttachXDP` | netlink `XDP` 消息 / `BPF_LINK_CREATE`（5.8 起 XDP 也走 link） | 4.8+ |
| TC（新）tcx | `link.AttachTCX` | `BPF_LINK_CREATE`（BPF_TCX_* attach type） | 6.6+ |
| TC（经典 clsact） | **无原生 API**，用 vishvananda/netlink | rtnetlink qdisc/filter | 4.5+ |
| tracepoint | `link.Tracepoint` | perf_event 打开 tracefs 事件 | 4.7+ |
| kprobe/kretprobe | `link.Kprobe/Kretprobe` | perf_event / tracefs | 4.1+ |
| fentry/fexit | `link.AttachTracing` | `BPF_LINK_CREATE`（attach_btf_id） | 5.5/5.5+ |
| freplace | `link.AttachFreplace` | BPF 扩展 | 5.7 |
| LSM | `link.AttachLSM` | `BPF_LINK_CREATE` | 5.7 |
| cgroup | `link.AttachCgroup` | `BPF_PROG_ATTACH`/link | 4.10+ |
| socket filter | `link.AttachSocketFilter` | `SO_ATTACH_BPF` | — |
| netns | `link.AttachNetNs` | — | 5.15 |

**Link 是什么**：内核 5.7+ 引入 `BPF_LINK_CREATE`，把“挂载关系”本身
变成内核对象（返回 FD）。好处：① 挂载关系可查询（`bpftool link show`）；
② link FD 关闭 = 自动卸载（不会“程序死了钩子还挂着”）；③ 可 pin。
cilium/ebpf 的 `link.Link` 接口对“link 化”和“legacy attach”做了统一
封装——legacy 路径下库会用 raw FD 模拟出 `Close()` 语义。

```go
type Link interface {
    Close() error        // 断开挂载（link FD 关闭 / 对应 detach）
    Update(*ebpf.Program) error  // 原地换程序（不闪断）
    Pin(string) error    // 挂载关系 pin 到 bpffs
    IsPinned() bool
    // Info(): 类型、progs 等
}
```

## 2. XDP

### 2.1 三种模式

| 模式 | Flags | 执行位置 | 支持面 | 性能 |
|---|---|---|---|---|
| 驱动（native） | `link.XDPDriverMode` | 网卡驱动收包最早点 | 需驱动支持（物理网卡大多支持，veth 4.19+） | 最高，可 10Mpps 级 |
| 通用（SKB/generic） | `link.XDPGenericMode` | 内核协议栈 `__netif_receive_skb` 之前 | **所有网卡** | 中（仍早于 iptables） |
| 硬件（offload） | `link.XDPEngineMode`?（hw offload 走 SmartNIC 固件） | 网卡本身 | 少数 SmartNIC | 线速，但指令子集受限 |

选型经验：veth/云环境虚拟网卡先用 Generic 保证能跑；物理机高吞吐换
Driver。不传 Flags 时内核“driver 优先、generic 兜底”。ruport 用
Generic（`XDP_FLAGS_SKB_MODE`），对应原 C 版，任何环境都能挂。

### 2.2 Attach 与清理

```go
lk, err := link.AttachXDP(link.XDPOptions{   // v0.22 实测字段
    Program:   objs.XdpParse,   // *ebpf.Program
    Interface: ifindex,         // net.Interface.Index
    Flags:     link.XDPGenericMode,
})
if err != nil { ... }
defer lk.Close()                // ← 关闭即卸载
```

同一网卡同一模式重复 attach 默认**替换**旧程序（老内核行为是替换，
5.8+ link 化后每个 link 独立）。程序 FD 关闭且无 link 时 XDP 自动摘除。

验证：`bpftool net show` 或 `ip link`（会看到 `xdpgeneric` 标记）。
（库内查询当前 XDP 挂载信息走 `link.Info`/`XDPInfo` 这条 raw-link 信息
路径，日常排障用上面两个 CLI 更直接。）

## 3. TC 挂载

### 3.1 背景：qdisc、clsact、filter

Linux 流量控制（tc）是树状的：网卡根上挂 qdisc（排队规则），qdisc 上
挂 class，再挂 filter（分类器）。BPF 程序作为 **filter** 挂载，而
`clsact` 是专为 BPF 准备的特殊 qdisc——一次创建，两个挂载点：

```
        ┌──────────── clsact qdisc（handle ffff:0000）────────────┐
 eth0 ──┤ ingress（parent ffff:fff2 = HANDLE_MIN_INGRESS）          │
        │ egress （parent ffff:fff3 = HANDLE_MIN_EGRESS）           │
        └───────────────────────────────────────────────────────────┘
```

- **ingress**：包刚进协议栈（晚于 XDP）；
- **egress**：包即将发出；
- 一个方向可以挂多条 filter，用 `priority`（小者优先）+ `handle`
  （同 priority 内的编号）定位；
- filter 关联的 BPF 程序返回 `TC_ACT_OK`（继续）/`TC_ACT_SHOT`（丢）/
  `TC_ACT_REDIRECT` 等；
- BPF filter 有两种执行语义：传统 classifier（返回 classid/动作，靠
  `BPF_F_PSEUDO_HDR`…不对——靠 flags 区分）与 **direct-action（da）**：
  程序返回值直接作为动作。ruport 返回 `TC_ACT_OK` 且不用 da，行为
  等价于“旁路观察+改包后放行”。

### 3.2 经典 clsact：vishvananda/netlink（ruport-go 采用）

cilium/ebpf 的 link 包没有经典 TC API（只有 6.6+ 的 tcx），所以走
`github.com/vishvananda/netlink`，完整流程如下（即
`cmd/ruport/main.go` 的 `attachTcFilters`）：

```go
// ① 创建 clsact qdisc（已存在则忽略 EEXIST）
clsact := &netlink.Clsact{
    QdiscAttrs: netlink.QdiscAttrs{
        LinkIndex: ifindex,
        Handle:    netlink.MakeHandle(0xffff, 0),  // ffff:0000
        Parent:    netlink.HANDLE_CLSACT,          // ffff:fff1
    },
}
if err := netlink.QdiscAdd(clsact); err != nil && !errors.Is(err, syscall.EEXIST) {
    return err
}

// ② 挂 filter（egress 与 ingress 各一条，priority=1 handle=1）
mk := func(parent uint32, prog *ebpf.Program) *netlink.BpfFilter {
    return &netlink.BpfFilter{
        FilterAttrs: netlink.FilterAttrs{
            LinkIndex: ifindex,
            Parent:    parent,                        // HANDLE_MIN_EGRESS/INGRESS
            Handle:    netlink.MakeHandle(0, 1),      // 0:1
            Priority:  1,
            Protocol:  unix.ETH_P_ALL,                // 匹配所有协议
        },
        Fd:           prog.FD(),                      // 关键：程序 FD
        DirectAction: false,
    }
}
if err := netlink.FilterAdd(mk(netlink.HANDLE_MIN_EGRESS, objs.TcEgress)); err != nil { ... }
if err := netlink.FilterAdd(mk(netlink.HANDLE_MIN_INGRESS, objs.TcIngress)); err != nil { ... }
```

卸载（对应原 `releasetc` 的 `bpf_tc_detach`+`bpf_tc_hook_destroy`）：

```go
_ = netlink.FilterDel(egressFilter)   // 传回原 filter 对象（有 handle/priority 即可）
_ = netlink.FilterDel(ingressFilter)
_ = netlink.QdiscDel(clsact)          // 删整个 clsact
```

**生命周期警报**：经典 tc filter 持有程序引用——进程退出后 **filter
依然挂着、BPF 程序依然生效**（不像 XDP link 会随 FD 消亡）。所以
ruport 必须在 SIGINT 路径里显式 `FilterDel`+`QdiscDel`，否则下次启动
`FilterAdd` 会因 handle 冲突报 EEXIST，旧改包规则也会残留。同理，
`objs.Close()` 必须在 filter 删除**之后**（程序 FD 还在被 filter 用）。

排障命令：

```bash
tc qdisc show dev eth0                 # 应看到 clsact
tc filter show dev eth0 ingress        # 应看到 bpf handle 0x1 ... prio 1
tc filter show dev eth0 egress
```

### 3.3 tcx：新方式（6.6+，供参考）

```go
lk, err := link.AttachTCX(link.TCXOptions{   // v0.22 实测字段
    Interface: ifindex,
    Program:   objs.TcIngress,
    Attach:    ebpf.AttachTCXIngress,         // 或 AttachTCXEgress
    // Anchor/ExpectedRevision 控制链上相对位置与并发安全
})
defer lk.Close()
```

tcx 是 link 化的 TC 挂载：多程序自动成链、顺序可控、进程退出自动摘除、
`bpftool link show` 可见。**语义与 clsact filter 略有差异**（链式执行、
无 priority/handle 概念），ruport 保持经典方式以对齐原版行为与老内核。

## 4. tracepoint / kprobe / fentry

### 4.1 tracepoint（ruport pidhide 用的类型）

```go
// C: SEC("tracepoint/syscalls/sys_enter_getdents64")
lk, err := link.Tracepoint("syscalls", "sys_enter_getdents64",
    objs.HandleGetdentsEnter, nil)   // v0.22 实测签名
```

分组/名字对应 `/sys/kernel/tracing/events/` 的两级目录。tracepoint
参数稳定、跨版本安全，是 tracing 首选。

### 4.2 kprobe

```go
// C: SEC("kprobe/do_sys_open")
lk, err := link.Kprobe("do_sys_open", objs.KpOpen, &link.KprobeOptions{
    // Offset:      偏移探测（内联函数场景）
    // RetprobeMaxActive: kretprobe 并发上限
})
lk2, err := link.Kretprobe("do_sys_open", prog, nil)   // 返回值探针
```

kprobe 贴内核符号，随内核版本漂移（函数被内联/改名就失效）；要稳就
fentry。

### 4.3 fentry/fexit（5.5+，BTF 化）

```c
SEC("fentry/do_sys_open")
int BPF_PROG(on_open, const char __user *filename, int flags, umode_t mode)
{
    // 参数已按原型解析好，bpf_get_attach_cookie 等可用
}
```

```go
lk, err := link.AttachTracing(link.TracingOptions{
    Program:   prog,     // ProgramSpec.AttachTo 在解析 section 时已带 "do_sys_open"
})
```

fentry/fexit 走 BTF，验证器知道函数原型，参数访问类型安全，且无
kretprobe 的 MaxActive 限制。

## 5. Link 生命周期与 pin

铁律一图流：

```
Collection(objs) ──FD──▶ Program ──引用──▶ [link / tc filter / prog_array]
     │                                                        │
     └ objs.Close() 释放程序 FD ── 无引用则程序销毁 ◀─────────┘
        （XDP/tcx：link FD 也关 → 自动卸载；经典 tc filter：需先 FilterDel）
```

- **进程崩溃**：XDP link 化挂载随 FD 全灭而摘除；经典 tc filter
  **残留**（ruport 这类程序要考虑崩溃兜底：启动时先尝试清理旧 filter，
  或提供 uninstall 子命令）；
- **跨进程接管**：`lk.Pin("/sys/fs/bpf/xdp_lk")` 把 link 本身 pin 住，
  新进程 `ebpf.LoadPinnedLink`（raw link）接管；map/program 各自 pin
  见 02 章 §7；
- **热更新**：`lk.Update(newProg)` 挂载关系不变换程序，无闪断；
  XDP 重复 `AttachXDP` 也是替换语义（同模式）。

## 6. 常见挂载报错

| 现象 | 原因 | 处理 |
|---|---|---|
| `netlink receive: file exists`（QdiscAdd） | clsact 已存在 | 忽略 `EEXIST`（ruport 的写法） |
| `netlink receive: file exists`（FilterAdd） | 同 handle/priority 已被占 | 删旧 filter 或换 handle；启动前清残留 |
| XDP attach `not supported` | 驱动不支持 native | 改 `XDPGenericMode` |
| XDP attach `device busy` | 网卡正在变更/驱动锁 | 重试；检查是否有旧 XDP 程序挂着 |
| tracepoint `no such file or directory` | 分组/名字拼错 | 对照 `/sys/kernel/tracing/events` 路径 |
| kprobe 符号找不到 | 函数被内联/改名 | `cat /proc/kallsyms | grep xxx` 确认；改 fentry/换符号 |
| tcx `ErrNotSupported` | 内核 < 6.6 | 退回 clsact 方案（`link.HaveTCX()` 探测） |

## 7. 检查与调试

```bash
bpftool prog show                 # 所有已加载程序（含 xlated 字节码、VERIFIED 状态）
bpftool link show                 # link 化挂载关系
bpftool net show                  # 网络类挂载总览（xdp/tc）
bpftool map show name message_map
tc qdisc show dev eth0 && tc filter show dev eth0 ingress && tc filter show dev eth0 egress
cat /sys/kernel/debug/tracing/trace_pipe   # bpf_printk 输出（ruport 的 bpfprint 宏）
```

---

下一章：[06-examples.md](06-examples.md)——三个从零到运行的可照抄例子。
