# 11 · 程序类型参考手册：hook 位置、签名、返回值与挂载

> 整理自 ArthurChiao's Blog《BPF 进阶笔记（一）：BPF 程序（BPF Prog）
> 类型详解》（2021，基于内核 5.8/5.10），原文见
> https://arthurchiao.art（站内搜索“BPF 进阶笔记”）。本仓库整理时
> 重组了结构并校订了版本事实（以 [09 章](09-kernel-versions.md)为准）。
> 09 章回答“什么版本有什么类型”，本章回答“这个类型的程序**在哪被
> 调用、拿到什么参数、返回什么才对、怎么挂**”。

---

## 0. 快速索引表

| 类型 | hook 位置（内核函数） | context | 返回值语义 |
|---|---|---|---|
| SOCKET_FILTER | `sock_queue_rcv_skb()` | `__sk_buff *` | n=截断保留前 n 字节；0=忽略 |
| SOCK_OPS | 多处（`tcp_call_bpf()`） | `bpf_sock_ops *` | 按 op 而异（配置值或回调忽略） |
| SK_SKB | strparser/redirect 路径 | `__sk_buff *` | verdict（`__SK_PASS/DROP/REDIRECT`） |
| SK_MSG | sendmsg 路径 | `sk_msg_md *` | 同上 verdict |
| SK_REUSEPORT | `run_bpf_filter()` | `__sk_buff *` | socket 数组下标 |
| SCHED_CLS | `sch_handle_ingress()/egress()` | `__sk_buff *` | `TC_ACT_*` |
| SCHED_ACT | tc action 路径 | `__sk_buff *` | `TC_ACT_*` |
| XDP | 网卡驱动 RX（或 generic） | `xdp_md *` | `enum xdp_action` |
| CGROUP_SKB | 入向 `sk_filter_trim_cap()`；出向 `ip[6]_finish_output()` | `__sk_buff *` | 1=放行；其他=丢（EPERM） |
| CGROUP_SOCK | `inet_create()` 等 | `bpf_sock *` | 1=放行 |
| CGROUP_DEVICE | 设备文件创建/访问 | `bpf_cgroup_dev_ctx *` | 非 0=放行 |
| KPROBE | `k[ret]probe_perf_func()` | `pt_regs *` | 忽略 |
| TRACEPOINT | `perf_trace_<event_class>()` | tracepoint 参数结构 | 忽略 |
| PERF_EVENT | perf 采样到期 | `bpf_perf_event_data *` | 忽略 |
| LWT_IN/OUT/XMIT | `lwtunnel_input/output/xmit()` | `__sk_buff *`（IN 为 `sk_buff*`） | LWT verdict |

## 1. Socket 相关类型

### 1.1 BPF_PROG_TYPE_SOCKET_FILTER（3.19）

- **场景**：流量过滤/复制（只读“抓包”，不截断原始流量——截断只影响
  副本的长度字段）；或只做统计的可观测性。
- **hook**：`sock_queue_rcv_skb()`（`net/core/sock.c`），TCP/UDP/ICMP/
  raw socket 的入向都会走到：
  ```c
  int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb) {
      err = sk_filter(sk, skb);            // 执行 BPF；err=保留前多少字节
      if (err) return err;                 // 非 0：按截断值处理，跳过后续
      return __sock_queue_rcv_skb(sk, skb);// 0：正常投递
  }
  ```
- **签名**：`struct __sk_buff *`——`sk_buff` 的**用户可访问字段镜像**
  （`include/uapi/linux/bpf.h`）。验证器会把程序对 `__sk_buff` 字段的
  访问转换成对真实 `sk_buff` 字段的访问。这层封装是 tc/socket 类程序
  跨内核版本稳定的关键（字段名稳定，内核内部怎么变无所谓）。
- **返回值**：`n(0<n<pkt_size)` 返回截断副本（只保留前 n 字节）；
  `0` 忽略该包。对原始流量只读。
- **挂载**：`setsockopt(fd, SO_ATTACH_BPF, ...)`；cilium/ebpf 用
  `link.AttachSocketFilter(conn, prog)`。
- **示例**：内核 `samples/bpf/sockex1~3`；按协议截断的样例：

```c
__section("socket")
int bpf_trim_skb(struct __sk_buff *skb) {
    int proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
    int size = ETH_HLEN + sizeof(struct iphdr);
    switch (proto) {
        case IPPROTO_TCP: size += sizeof(struct tcphdr); break;
        case IPPROTO_UDP: size += sizeof(struct udphdr); break;
        default:          size = 0; break;   // 其他协议直接忽略
    }
    return size;
}
char _license[] __section("license") = "GPL";
```

### 1.2 BPF_PROG_TYPE_SOCK_OPS（4.13）

- **场景**：① 监听 socket/TCP 事件（只读跟踪）；② 在事件里用
  `bpf_setsockopt()` 做**按连接**的动态调优（如被动建连时按网段改
  MTU）；③ 与 SK_SKB 配合做 socket 重定向（本程序把 socket 信息存
  sockmap，SK_SKB 程序查表 `bpf_sk_redirect_map()` 直达对端）。
- **hook**：与“一个固定位置”的类型不同，SOCK_OPS 在**多处**触发，
  由 `ctx->op` 区分（都经 `tcp_call_bpf()` 调入）。op 分两类：

| 类别 | op | 说明 |
|---|---|---|
| 返回值即配置 | `TIMEOUT_INIT`/`RWND_INIT`/`NEEDS_ECN`/`BASE_RTT` | 程序返回建议值；-1 用默认 |
| 状态回调 | `TCP_CONNECT_CB`/`ACTIVE(PASSIVE)_ESTABLISHED_CB`/`RTO_CB`/`RETRANS_CB`/`STATE_CB`/`TCP_LISTEN_CB` | 建连/超时/重传/状态机/listen 等事件，参数在 `args[4]` |

- **签名**：`struct bpf_sock_ops *`（op、args/reply、四元组 IP/port，
  注意 `remote_ip4/remote_port` 是网络序、`local_port` 是主机序）。
- **与 CGROUP_SOCK 的分工**：CGROUP_SOCK 每连接只执行一次（创建时）；
  SOCK_OPS 在连接生命周期内多次执行。
- **挂载**：cgroup v2，attach 类型 `BPF_CGROUP_SOCK_OPS`
  （cilium：`link.AttachCgroup`）。

### 1.3 BPF_PROG_TYPE_SK_SKB（4.14）

- **场景**：① 配合 sockmap 做 socket 重定向；② strparser 框架的
  流解析（TLS、KCM 在用）。
- **hook**：strparser 路径 `smap_parse_func_strparser()`（STREAM_PARSER
  程序）/ `smap_verdict_func()`（VERDICT 程序）。
- **签名**：`__sk_buff *`（从中提取四元组去 sockmap 查对端）。
- **返回**：verdict `__SK_PASS/__SK_DROP/__SK_REDIRECT`。
- **挂载**：attach 到 **sockmap**（`BPF_SK_SKB_STREAM_PARSER/VERDICT`）。

### 1.4 BPF_PROG_TYPE_SK_MSG（4.17）

sendmsg 系统调用路径上的同类程序（`sk_msg_md *`），用于拦截发送消息
做 verdict/redirect；用法与 SK_SKB 对称，挂到 sockmap/sockhash。

### 1.5 BPF_PROG_TYPE_SK_REUSEPORT（4.19）

- **场景**：① 发布系统新老进程**共享端口无损切流**：程序按连接特征
  （新老连接）返回不同 socket 下标；② 加速 reuseport 组的 socket 查找。
- **返回值**：REUSEPORT_SOCKARRAY 数组的**下标**；越界返回 NULL（丢）。
  内核实现（`net/core/sock_reuseport.c` 的 `run_bpf_filter()`）就是
  “跑程序→按下标取 sock”。

## 2. TC 子系统类型

### 2.1 BPF_PROG_TYPE_SCHED_CLS（4.1）—— ruport 在用

- **hook**：`sch_handle_ingress()/sch_handle_egress()` → `tcf_classify()`。
  - ingress：网卡驱动处理之后、IP 层之前；
  - egress：进入设备发送队列之前。
- **签名**：`__sk_buff *`（同 1.1 的镜像语义，可用
  `bpf_skb_store_bytes` 等改包 helper——这正是 ruport 改端口的通道）。
- **返回**：`TC_ACT_OK`（放行）/`TC_ACT_SHOT`（丢）/`TC_ACT_REDIRECT` 等。
- **挂载**：clsact qdisc + filter（`tc filter add ... bpf da obj x.o
  sec y`，背后是 netlink）或 tcx（6.6+）。完整 Go 侧流程见
  [05 章 §3](05-links.md)。

### 2.2 BPF_PROG_TYPE_SCHED_ACT（4.1）

作为 tc **action**（而非 classifier）挂载，签名/返回同上，模块实现
`act_bpf.c`。日常较少直接使用。

## 3. BPF_PROG_TYPE_XDP（4.8）—— ruport 在用

- **场景**：DDoS 防御、四层负载均衡、转发。执行时 **skb 尚未创建**，
  开销最小。
- **hook**：网卡驱动 RX（native，有专用 TX/RX queue）；驱动不支持时
  用 generic XDP（skb 创建之后，`net/core/dev.c`），功能一致性能略低。
  ——对应 cilium 的 `XDPDriverMode`/`XDPGenericMode`。
- **签名**：`struct xdp_md *`，极轻量：
  ```c
  struct xdp_md {
      __u32 data;            // 包起始（当前）
      __u32 data_end;        // 包结束
      __u32 data_meta;       // 元数据区
      __u32 ingress_ifindex, rx_queue_index, egress_ifindex;
  };
  ```
- **返回**：`enum xdp_action`：
  ```c
  XDP_ABORTED=0, XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT
  ```
- **挂载**：netlink（`AF_NETLINK`+`NETLINK_ROUTE` 的 XDP 消息，带 BPF
  fd 与 ifindex）——cilium `link.AttachXDP` 即封装此路径。

## 4. cgroup (v2) 相关类型

**通用调用栈**（理解 cgroup BPF 的钥匙）：

1. **socket 创建时**（`sk_alloc()`）初始化 `sk->sk_cgrp_data`——后面
   的 hook 都靠它找到 socket 所属 cgroup 的程序列表；
2. **入向**：`BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb)` 宏 →
   `__cgroup_bpf_run_filter_skb()`：取 socket 的 cgroup → 跑
   `cgrp->bpf.effective[type]` 程序数组 → `ret == 1 ? 0 : -EPERM`
   （**返回 1 才算放行**）；
3. **出向/事件**：`BPF_CGROUP_RUN_SK_PROG(sk, type)` →
   `__cgroup_bpf_run_filter_sk()`，语义同上。

### 4.1 BPF_PROG_TYPE_CGROUP_SKB（4.10）

- **场景**：cgroup 级别放行/丢弃包（容器网络策略的基础）。
- **hook**：入向 `sk_filter_trim_cap()`（从 `tcp_v4_rcv`/UDP 接收路径
  进入）；出向 `ip[6]_finish_output()`。
- **签名**：`__sk_buff *`；**返回 1=放行，其他=EPERM（随后被丢）**。

### 4.2 BPF_PROG_TYPE_CGROUP_SOCK（4.10）

- **场景**：socket 创建等事件上做拒绝/放行（网络访问控制）。
- **hook**：`inet_create()` → `BPF_CGROUP_RUN_PROG_INET_SOCK()`，失败
  则 socket 直接被释放。每连接一次。
- **返回**：1=放行。

### 4.3 BPF_PROG_TYPE_CGROUP_DEVICE（4.15）

- **场景**：设备文件（mknod/read/write）访问控制。
- **签名**：`struct bpf_cgroup_dev_ctx *`：
  ```c
  struct bpf_cgroup_dev_ctx {
      __u32 access_type;  // (BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_*
      __u32 major, minor; // 主次设备号
  };
  ```
- **返回**：非 0=允许，0=-EPERM。
- **示例**：内核自测 `tools/testing/selftests/bpf/progs/dev_cgroup.c`。

## 5. kprobes / tracepoints / perf events

三者定位对比：

| | 数据源 | 空间 | 特点 |
|---|---|---|---|
| kprobes | 动态（任意函数） | 内核 | 断点指令 + trap；函数被内联/改名即失效 |
| uprobes | 动态 | 用户态 | 同上 |
| tracepoints | 静态（内核显式埋点） | 内核 | 稳定、带参数格式；`ls /sys/kernel/debug/tracing/events` |
| USDT | 静态 | 用户态 | 应用自带探针 |

### 5.1 BPF_PROG_TYPE_KPROBE（4.1）

- **机制**：启用后把探测点指令替换为断点；执行到时 trap，保存寄存器，
  经 `kprobe_dispatcher()` → `k[ret]probe_perf_func()` →
  `trace_call_bpf()` 跑 BPF 程序。
- **签名**：`struct pt_regs *`——直接摸寄存器；通用取值 helper：
  `PT_REGS_RC(ctx)` 取返回值（x86 上是 ax 寄存器）。
- **挂载**：tracefs 配置 + perf_event：
  ```bash
  echo 'p:myprobe tcp_retransmit_skb' > /sys/kernel/debug/tracing/kprobe_events
  cat  /sys/kernel/debug/tracing/events/kprobes/myprobe/id   # 用此 id 开 perf event
  ```
cilium 封装：`link.Kprobe("tcp_retransmit_skb", prog, nil)`（老内核
走的就是上述 tracefs 路径）。机制走读、宏写法与 fentry 的全面对比见
[14 章](14-kprobe-fentry.md)。

### 5.2 BPF_PROG_TYPE_TRACEPOINT（4.7）—— ruport pidhide 用的类型

- **机制**：tracepoint 触发 → `perf_trace_<event_class>()` →
  `perf_trace_run_bpf_submit()` → `trace_call_bpf()`。
- **签名**：**因 tracepoint 而异**——权威定义在每个事件的 format 文件：
  ```bash
  cat /sys/kernel/debug/tracing/events/net/netif_rx/format
  # field:unsigned short common_type;      offset:0;  size:2; signed:0;
  # field:unsigned char  common_flags;     offset:2;  size:1; signed:0;
  # ...公共头之后是该事件自己的字段（skbaddr/len/name...）
  ```
  C 侧直接 include `vmlinux.h` 用对应的 `trace_event_raw_*` 结构体。
- **挂载**：`link.Tracepoint("net", "netif_rx", prog, nil)`。

### 5.3 BPF_PROG_TYPE_PERF_EVENT（4.9）

- **场景**：软/硬件 perf 事件（定时器、PMU 计数等）驱动，按采样周期
  执行。
- **签名**：`struct bpf_perf_event_data *`（regs + sample_period + addr）。
- **挂载**：`perf_event_open()` + `ioctl(fd, PERF_EVENT_IOC_SET_BPF)`。

## 6. 轻量级隧道类型（LWT，4.10）

给路由子系统编程能力，`ip route add ... encap bpf ...` 直接挂程序：

```bash
ip route add 192.168.253.2/32 encap bpf out obj lwt.o section encap dev veth0
#                                                                  ^^^ in/out/xmit
```

- `LWT_IN`：`lwtunnel_input()` 触发，检查入向是否需要解封装；
- `LWT_OUT`：`lwtunnel_output()` 触发，对出向做封装；
- `LWT_XMIT`：`lwtunnel_xmit()` 触发，发送端 encap/redirect。
- 签名：`__sk_buff *`（IN 为 `sk_buff*` 视角）；入向只读。

## 7. bpf_attach_type 速览（5.10 视角）

程序类型只是“程序长什么样”；**attach 类型**决定“挂到哪个钩子”。
cgroup 家族的 attach 类型最多（`BPF_CGROUP_INET_INGRESS/EGRESS`、
`SOCK_CREATE`、`*4/6_BIND`、`*CONNECT`、`UDP4/6_SENDMSG`、
`GET/SETSOCKOPT`、`GETPEERNAME/GETSOCKNAME`、`SOCK_RELEASE`...），
另有 `SK_SKB_STREAM_PARSER/VERDICT`、`SK_MSG_VERDICT`、`CGROUP_DEVICE`、
`TRACE_RAW_TP`、`TRACE_FENTRY/FEXIT`、`MODIFY_RETURN`、`LSM_MAC`、
`TRACE_ITER`、`XDP/DEVMAP/CPUMAP`、`SK_LOOKUP` 等。完整枚举见
`include/uapi/linux/bpf.h` 的 `enum bpf_attach_type`（09 章各类型的
挂载方式列已对应到 cilium/ebpf API）。

## 8. ruport-go 视角

- 本仓库只用了三种类型，全部命中本章重点：
  - `xdp_parse`（XDP / `xdp_md` / `XDP_PASS`）——§3；
  - `tc_ingress`/`tc_egress`（SCHED_CLS / `__sk_buff` / `TC_ACT_OK` +
    改包 helper）——§2.1；
  - pidhide 原型的 `handle_getdents_*`（TRACEPOINT / 5.2 的
    `sys_exit_getdents64` 返回值即 bytes_read）——§5.2（未移植）。
- 排障联想：程序“挂上了但不跑”，先对照本章的 hook 位置想“包/事件
  到底会不会经过那里”（例如 tc ingress 改写对本地生成包不生效、
  XDP generic 对 veth 才稳妥）。

---

关联阅读：[09 版本矩阵](09-kernel-versions.md) ·
[05 挂载与生命周期](05-links.md) · [下一章 12-map-internals](12-map-internals.md)
