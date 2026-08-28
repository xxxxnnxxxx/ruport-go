# 附录 A · 程序类型速查表

> 列：类型 / 主线版本 / 入口 context / cilium·ebpf 挂载 / 返回值要点。
> "机制与签名详解"的书内出处标注在 HG 列。版本事实校订以主线为准，
> 长尾条目（标 ~）以 `bpftool feature probe` 实测为准。

## 网络类

| 类型 | 版本 | context | 挂载（cilium） | 返回值 | 详解 |
|---|---|---|---|---|---|
| `SOCKET_FILTER` | 3.19 | `__sk_buff*` | `AttachSocketFilter` | n=截断副本前 n 字节；0=忽略 | — |
| `SCHED_CLS` (tc) | 4.1 | `__sk_buff*` | netlink clsact / `AttachTCX`(6.6+) | `TC_ACT_OK/SHOT/REDIRECT` | 第8章 |
| `SCHED_ACT` | 4.1 | `__sk_buff*` | tc action | 同上 | — |
| `XDP` | 4.8 | `xdp_md*` | `AttachXDP` | `XDP_DROP/PASS/TX/REDIRECT/ABORTED` | 第7章 |
| `CGROUP_SKB` | 4.10 | `__sk_buff*` | `AttachCgroup` | 1=放行，其他=EPERM | 第9章 |
| `CGROUP_SOCK` | 4.10 | `bpf_sock*` | `AttachCgroup` | 1=放行 | 第9章 |
| `CGROUP_DEVICE` | 4.15 | `bpf_cgroup_dev_ctx*` | `AttachCgroup` | 非0=允许 | 第9章 |
| `LWT_IN/OUT/XMIT` | 4.10 | `__sk_buff*` | `ip route ... encap bpf` | LWT verdict | — |
| `SOCK_OPS` | 4.13 | `bpf_sock_ops*` | cgroup(AttachCgroup) | 按 op（配置值/忽略） | 第9章 |
| `SK_SKB` | 4.14 | `__sk_buff*` | sockmap(PARSER/VERDICT) | `__SK_PASS/DROP/REDIRECT` | 第9章 |
| `SK_MSG` | 4.17 | `sk_msg_md*` | sockmap | verdict | 第9章 |
| `SK_REUSEPORT` | 4.19 | `__sk_buff*` | setsockopt | socket 数组下标 | 第9章 |
| `SK_LOOKUP` | 5.9 | `bpf_sk_lookup*` | `SK_LOOKUP_BPF` | 选中 socket | 第9章 |
| `FLOW_DISSECTOR` | 4.20 | 自定义 | `AttachNetNs`(5.15+) | 协议层数 | — |
| `NETFILTER` | 5.18~ | `bpf_nf_ctx*` | `AttachNetfilter` | NF verdict | — |

## 观测类

| 类型 | 版本 | context | 挂载 | 返回值 | 详解 |
|---|---|---|---|---|---|
| `KPROBE` | 4.1 | `pt_regs*` | `Kprobe/Kretprobe` | 忽略 | 第10章 |
| `TRACEPOINT` | 4.7 | `trace_event_raw_*` | `Tracepoint(组,名,..)` | 忽略 | 第10章 |
| `PERF_EVENT` | 4.9 | `bpf_perf_event_data*` | perf_event_open+SET_BPF | 忽略 | 第10章 |
| `RAW_TRACEPOINT` | 4.17 | 裸参数 u64[] | `AttachRawTracepoint` | 忽略 | — |
| `TRACING`(fentry/fexit) | 5.5 | 目标函数原型 | `AttachTracing` | fexit 可读；fmod_ret 可改 | 第11章 |
| `EXT`(freplace) | 5.5 | 目标程序原型 | `AttachFreplace` | 同被挂程序 | 第11章 |
| `LSM` | 5.7 | LSM 钩子原型 | `AttachLSM` | 非0=拒绝 | 第11章 |
| `STRUCT_OPS` | 5.6 | 结构体回调 | `AttachStructOps` | 按约定 | — |
| `SYSCALL`(bpf syscall) | 5.14 | — | — | sleepable 辅助 | — |

## 通用要点

- **section 名与类型推断**：`"xdp"`→XDP；`"tc"/"classifier"`→
  SCHED_CLS；`"tracepoint/G/N"`、`"tp/G/N"`→TRACEPOINT；
  `"kprobe/S"`→KPROBE；`"fentry/S"`/`"fexit/S"`→TRACING；
  `"cgroup_skb/egress"` 等→CGROUP 系（cilium 按此设 ProgramSpec.Type）；
- **attach 类型**：程序类型决定"长什么样"，attach 类型决定"挂到
  哪"（cgroup 家族尤其丰富，完整枚举见 `include/uapi/linux/bpf.h`
  的 `enum bpf_attach_type`）；
- **license**：用 GPL-only helper（tracing 系多数）必须声明 GPL。
