# 附录 E · 内核版本-特性矩阵

> 口径：Linux **主线**合入版本；`~` = 近似值（backport 世界以
> `bpftool feature probe` 实测为准，见第 15 章 15.1）。

## E.1 里程碑时间线（详述见第 1 章）

| 版本 | 里程碑 |
|---|---|
| 3.18 (2014) | eBPF 地基：验证器 + ARRAY/HASH + SOCKET_FILTER |
| 4.1 (2015) | kprobe/tc 程序；tc helper 家族 |
| 4.2 | 尾调用；4.5 clsact |
| 4.8 (2016) | XDP（native/generic） |
| 4.6/4.10/4.11/4.12/4.14 | perCPU/LRU/LPM/map-in-map/sockmap·devmap |
| 5.1/5.2 (2019) | 全局变量(.data/.rodata)/100万指令/LOG_LEVEL2·STATS |
| 5.3 | 有界循环 |
| 5.4 | CONFIG_DEBUG_INFO_BTF + /sys/kernel/btf/vmlinux（CO-RE 完整可用） |
| 5.5 | fentry/fexit/freplace（trampoline）；probe_read_user/kernel 拆分 |
| 5.6 | struct_ops；map 批量 |
| 5.7 | LSM；BPF link 体系 |
| 5.8 | ringbuf；bpf_iter；XDP link；CAP_BPF |
| 5.9-5.11 | SK_LOOKUP(5.9)；sleepable+task/inode storage(5.10)；memcg 计费(5.11) |
| 5.15-5.18 | timer/attach cookie(5.15)；bloom(5.16)；kprobe multi(5.18) |
| 6.6-6.8+ | tcx(6.6)；netkit(6.7~)；user-ringbuf/arena(6.8~) |

## E.2 程序类型（详表见附录 A）

3.19 SOCKET_FILTER · 4.1 KPROBE/SCHED_CLS/SCHED_ACT · 4.7 TRACEPOINT ·
4.8 XDP · 4.9 PERF_EVENT · 4.10 CGROUP_SKB/SOCK + LWT×3 · 4.13 SOCK_OPS ·
4.14 SK_SKB · 4.15 CGROUP_DEVICE · 4.17 SK_MSG/RAW_TRACEPOINT/
CGROUP_SOCK_ADDR · 4.18 LWT_SEG6LOCAL/LIRC · 4.19 SK_REUSEPORT ·
4.20 FLOW_DISSECTOR · 5.2 CGROUP_SYSCTL/RAW_TP_WRITABLE · 5.3 SOCKOPT ·
5.5 TRACING/EXT · 5.6 STRUCT_OPS · 5.7 LSM · 5.9 SK_LOOKUP ·
5.14 SYSCALL · 5.18~ NETFILTER

## E.3 map 类型（详表见附录 B）

3.18 HASH/ARRAY · 4.1 PERF_EVENT_ARRAY · 4.2 PROG_ARRAY ·
4.6 PERCPU×2/STACK_TRACE · 4.8 CGROUP_ARRAY · 4.10 LRU×2 · 4.11 LPM ·
4.12 MAP_IN_MAP×2 · 4.14 DEVMAP/SOCKMAP · 4.15 CPUMAP · 4.18 XSKMAP/
SOCKHASH · 4.19 CGROUP_STORAGE/REUSEPORT · 4.20 QUEUE/STACK ·
5.2~ SK_STORAGE · 5.3~ DEVMAP_HASH · 5.8 RINGBUF · 5.10 INODE_STORAGE ·
5.11 TASK_STORAGE · 5.16 BLOOM · 6.8~ USER_RINGBUF

## E.4 常用 helper（详表见附录 C）

4.1 map 三件套/probe_read/printk/ktime/tc 改包与校验和族 ·
4.2 tail_call/进程信息族 · 4.4~ perf_output · 4.6 stackid ·
4.8 probe_write_user/xdp_adjust_head~ · 4.14 redirect_map ·
4.16 override_return · 4.18 fib_lookup/get_stack~ · 4.20 queue 族/
sk_lookup · 5.5 probe_read_user/kernel 拆分 · 5.8 ringbuf 族 ·
5.9 snprintf~ · 5.10 copy_from_user/d_path · 5.15 timer/attach_cookie ·
5.16 vprintk · 5.17~ strncmp

## E.5 挂载与机制

clsact 4.5 · XDP attach 4.8（link 化 5.8）· raw_tp 4.17 ·
BPF link 体系 5.7 · fentry/fexit 5.5 · freplace 5.5 · LSM 5.7 ·
cgroup link 化 5.15~ · bpf_iter 5.8 · netns 5.15 · kprobe_multi 5.18 ·
uprobe_multi 6.0~ · kprobe_session 6.x · tcx 6.6 · netkit 6.7~

## E.6 环境与限制类

指令上限：4096→100 万（5.2）· 有界循环 5.3 · verifier LOG_LEVEL2/
STATS 5.2 · 全局变量 5.1 · sleepable 5.10 · memlock→memcg 5.11 ·
CAP_BPF/CAP_PERFMON 5.8 · BTF kernel 自带 5.4

## E.7 cilium/ebpf features 探测 API（v0.22.0 实测导出）

```go
features.HaveProgramType(pt)             features.HaveMapType(mt)
features.HaveProgramHelper(pt, helper)   features.HaveBatchAPI()
features.HaveMapFlag(flag)               features.HaveBoundedLoops()
features.HaveLargeInstructions()         features.HaveV2ISA()/V3ISA()/V4ISA()
features.HaveBPFLinkKprobeMulti()        features.HaveBPFLinkUprobeMulti()
features.HaveBPFLinkKprobeSession()
// 错误三态：nil=支持；ErrNotSupported=确定不支持；其他=探测失败（≠不支持）
```
