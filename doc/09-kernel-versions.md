# 09 · 内核版本-特性支持完全对照

目标：回答“什么内核版本支持什么接口”。给出程序类型、map 类型、常用
helper、挂载/link 机制、syscall 子命令、环境类里程碑的版本矩阵，以及
**在目标机器上自查支持情况的操作手册**。

> **版本号的可信度说明（务必先读）**
> 表中版本 = 该功能合入 Linux **主线**（mainline）的大版本。两点注意：
> 1. **发行版会 backport**：RHEL 8/9、Ubuntu HWE 等常把新特性反向移植
>    到老版本号内核里，因此“内核版本号低”≠“没有该特性”，反之亦然
>    （厂商内核也可能裁剪）；
> 2. 标注 `~` 的条目为主线合入窗口的近似值（长尾特性），精确值请以
>    §9 的自查方法为准（`bpftool feature probe`）。
> 未标注的条目为主流资料交叉印证过的稳定值。

---

## 1. 基础里程碑（先建立时间轴）

| 内核 | 里程碑 | 对开发者的意义 |
|---|---|---|
| 3.18 | eBPF 验证器 + ARRAY/HASH map + `bpf()` 系统调用 | eBPF 元年；socket filter 可用 |
| 3.19 | SOCKET_FILTER 程序类型 | 第一个正式程序类型 |
| 4.1 | KPROBE / SCHED_CLS / SCHED_ACT；tc eBPF 系列 helper | tracing 与 tc 可写 |
| 4.2 | BPF-to-? 尾调用（`bpf_tail_call`） | 程序可接力 |
| 4.5 | `clsact` qdisc | TC 双向挂载的现代载体 |
| 4.6 | per-CPU map、STACK_TRACE map | 高性能计数、栈回溯 |
| 4.7 | TRACEPOINT 程序类型 | 稳定 tracing 钩子 |
| 4.8 | **XDP**（驱动/通用模式）、`bpf_probe_write_user` | 网络最快路径可用 |
| 4.12 | map-in-map | 两级表 |
| 4.14 | sockmap、devmap、`bpf_redirect_map` | BPF 转发/代理 |
| 4.16 | BPF-to-BPF 函数调用 | C 函数直接调用 |
| 4.17 | RAW_TRACEPOINT、SK_MSG、CGROUP_SOCK_ADDR | 高性能探针、socket 代理 |
| 4.19 | veth 原生 XDP | 容器/虚拟环境 |
| 4.20 | QUEUE/STACK map、FLOW_DISSECTOR | 队列语义 |
| 5.1 | 全局变量（`.data`/`.rodata`，BTF DATASEC） | `const volatile` 配置下发 |
| 5.2 | 指令上限提到 100 万；`BPF_LOG_LEVEL2/STATS` | 大程序；verifier 统计日志 |
| 5.3 | **有界循环** | 可以写 `for` 了 |
| 5.4 | `CONFIG_DEBUG_INFO_BTF` + `/sys/kernel/btf/vmlinux` | **CO-RE 完整可用**的分水岭 |
| 5.5 | fentry/fexit/freplace（BPF trampoline）；`bpf_probe_read_user/kernel` 拆分 | 类型安全 tracing |
| 5.6 | STRUCT_OPS；map 批量 API | 内核结构体实现、批量搬运 |
| 5.7 | LSM 程序；**BPF link 体系**（`BPF_LINK_CREATE`） | 挂载成为内核对象 |
| 5.8 | **RINGBUF**；bpf_iter；XDP link 化；`CAP_BPF` 等 capability 细分 | 事件通道、细粒度权限 |
| 5.9 | SK_LOOKUP | socket 查找重定向 |
| 5.10 | sleepable 程序；TASK/INODE storage；`bpf_copy_from_user` | 可睡眠 tracing |
| 5.11 | BPF 内存改 **memcg 计费**，不再受 `RLIMIT_MEMLOCK` 管 | 加载不再调 memlock |
| 5.15 | bpf_timer；attach cookie；netns attach | 定时器、链接附件 |
| 5.16 | BLOOM_FILTER map | 概率过滤 |
| 5.18 | kprobe multi（多探针一次挂）；BTF decl_tag；NETFILTER 程序（~） | 批量探针、netfilter 钩子 |
| 6.0~ | uprobe multi（~） | 批量用户态探针 |
| 6.6 | **tcx**（link 化 TC 挂载） | cilium/ebpf `link.AttachTCX` |
| 6.7 | netkit（~） | 新型虚拟网卡 BPF |
| 6.8 | USER_RINGBUF（~，用户态→内核事件）；arena（~6.9 实验性） | 反向事件、大内存 |

ruport-go 的最低要求由用到的特性决定：XDP generic（4.8）+ clsact（4.5）
+ HASH map → 理论 4.8；实际建议 5.4+（BTF/CO-RE 生态完整）乃至
Ubuntu 24.04（6.8）。

## 2. 程序类型（`bpf_prog_type`）全表

| 程序类型 | 版本 | 挂载方式 | 一句话用途 |
|---|---|---|---|
| `SOCKET_FILTER` | 3.19 | `SO_ATTACH_BPF` | socket 收包过滤（tcpdump 同源） |
| `KPROBE` | 4.1 | perf_event / tracefs | 内核函数进出探针 |
| `SCHED_CLS` | 4.1 | clsact filter / tcx | **tc 分类器（ruport 用）** |
| `SCHED_ACT` | 4.1 | tc action | tc 动作 |
| `TRACEPOINT` | 4.7 | perf_event（tracefs 事件） | **稳定 tracing（ruport pidhide 用）** |
| `XDP` | 4.8 | XDP attach / link | **驱动级包处理（ruport 用）** |
| `PERF_EVENT` | 4.9 | perf_event | perf 事件程序 |
| `CGROUP_SKB` | 4.10 | cgroup v2 | cgroup 进出包过滤 |
| `CGROUP_SOCK` | 4.10 | cgroup v2 | socket 生命周期回调 |
| `LWT_IN` / `LWT_OUT` / `LWT_XMIT` | 4.10 | 轻量隧道 | 封装/解封装点执行 |
| `SOCK_OPS` | 4.13 | `setsockopt` | TCP 状态回调（调参） |
| `SK_SKB` | 4.14 | sockmap | socket 间流水线转发 |
| `CGROUP_DEVICE` | 4.15 | cgroup v1/v2 | 设备访问控制 |
| `SK_MSG` | 4.17 | sockmap | sendmsg 拦截重定向 |
| `RAW_TRACEPOINT` | 4.17 | `BPF_RAW_TRACEPOINT_OPEN` | 无参数预处理的快探针 |
| `CGROUP_SOCK_ADDR` | 4.17 | cgroup v2 | connect/bind/sendmsg 地址改写 |
| `LWT_SEG6LOCAL` | 4.18 | SRv6 | 段路由本地动作 |
| `LIRC_MODE2` | 4.18 | lirc | 红外遥控解码 |
| `SK_REUSEPORT` | 4.19 | `setsockopt` | reuseport 组负载均衡 |
| `FLOW_DISSECTOR` | 4.20 | netns attach (5.15+) | 自定义协议解析器 |
| `CGROUP_SYSCTL` | 5.2 | cgroup v2 | sysctl 访问控制 |
| `RAW_TRACEPOINT_WRITABLE` | 5.2 | 同 raw tp | 可写参数变体 |
| `CGROUP_SOCKOPT` | 5.3 | cgroup v2 | getsockopt/setsockopt 拦截 |
| `TRACING` | 5.5 | `BPF_LINK_CREATE`（attach_btf_id） | **fentry/fexit/fmod_ret** |
| `EXT` | 5.5 | freplace | 替换/挂接另一个 BPF 程序 |
| `STRUCT_OPS` | 5.6 | struct_ops link | 实现内核结构体（TCP CC） |
| `LSM` | 5.7 | `BPF_LINK_CREATE`（lsm hook） | LSM 安全钩子 |
| `SK_LOOKUP` | 5.9 | `SK_LOOKUP_BPF` | 入向 socket 选择 |
| `SYSCALL` | 5.14 | `bpf()` 内部调用 | sleepable 辅助（`bpf_sys_bpf`） |
| `NETFILTER` | 5.18~ | netfilter link | nftables 钩子内执行 |

## 3. map 类型全表

| map 类型 | 版本 | 关键约束/备注 |
|---|---|---|
| `ARRAY` / `HASH` | 3.18 | 预分配/动态；一切的地基 |
| `PERF_EVENT_ARRAY` | 4.1 | 每 CPU 一条环形，事件旧通道 |
| `PROG_ARRAY` | 4.2 | value=程序 FD，尾调用表 |
| `PERCPU_HASH` / `PERCPU_ARRAY` | 4.6 | 每 CPU 副本，无锁 |
| `STACK_TRACE` | 4.6 | 栈回溯存储（`bpf_get_stackid`） |
| `CGROUP_ARRAY` | 4.8 | cgroup 句柄数组 |
| `LRU_HASH` / `LRU_PERCPU_HASH` | 4.10 | 满则淘汰最久未用 |
| `LPM_TRIE` | 4.11 | 最长前缀匹配（路由表） |
| `ARRAY_OF_MAPS` / `HASH_OF_MAPS` | 4.12 | map-in-map，内层为模板 |
| `DEVMAP` | 4.14 | 网卡→程序映射，XDP REDIRECT |
| `SOCKMAP` | 4.14 | socket↔程序，sk_skb/sk_msg |
| `CPUMAP` | 4.15 | CPU 重定向（XDP） |
| `XSKMAP` | 4.18 | AF_XDP socket 表 |
| `SOCKHASH` | 4.18 | hash 版 sockmap（可组合键） |
| `CGROUP_STORAGE` / `PERCPU_CGROUP_STORAGE` | 4.19~4.20 | cgroup 本地状态 |
| `REUSEPORT_SOCKARRAY` | 4.19 | reuseport 组管理 |
| `QUEUE` / `STACK` | 4.20 | FIFO/LIFO（`push/pop/peek`） |
| `SK_STORAGE` | 5.2~ | socket 本地存储（local storage 框架） |
| `DEVMAP_HASH` | 5.3~ | hash 版 devmap |
| `RINGBUF` | 5.8 | **事件首选**：单缓冲、保序、高效 |
| `INODE_STORAGE` | 5.10 | inode 本地存储 |
| `TASK_STORAGE` | 5.11 | task 本地存储（tracing 神器） |
| `BLOOM_FILTER` | 5.16 | 概率成员测试 |
| `USER_RINGBUF` | 6.8~ | 用户态→内核方向的事件 |
| arena | 6.9~（实验） | BPF 程序大块可读写内存 |

## 4. 常用 helper 分组表（~60 个）

完整权威列表：`/usr/include/bpf/bpf_helper_defs.h`（每个 helper 注释里
列了可用程序类型与版本）或内核文档
`Documentation/bpf/helpers`（`bpf.h` 头注释）。

**map 操作**

| helper | 版本 |
|---|---|
| `bpf_map_lookup_elem` / `update_elem` / `delete_elem` | 3.19 |
| `bpf_map_push_elem` / `pop_elem` / `peek_elem`（queue/stack） | 4.20 |
| `bpf_for_each_map_elem` | 5.13~ |

**包处理（tc/XDP 系）**

| helper | 版本 | 适用 |
|---|---|---|
| `bpf_skb_store_bytes` | 4.1 | tc（**ruport tc 改端口**） |
| `bpf_l3_csum_replace` / `bpf_l4_csum_replace` | 4.1 | tc（**ruport 修校验和**） |
| `bpf_csum_diff` | 4.1 | 通用增量和 |
| `bpf_skb_load_bytes` / `load_bytes_relative` | 4.1 / 4.~ | tc、多数类型 |
| `bpf_skb_adjust_room` / `bpf_csum_update` | 4.1/4.~ | tc |
| `bpf_xdp_adjust_head` / `adjust_meta` | 4.8~ | XDP |
| `bpf_redirect` / `bpf_redirect_map` | 4.1 / 4.14 | tc/XDP |
| `bpf_clone_redirect` | 4.1 | tc |
| `bpf_fib_lookup` | 4.18 | tc/XDP（走路由表） |
| `bpf_sk_lookup_tcp` / `udp` | 4.20 | tc/XDP（查 socket） |

**tracing / 进程**

| helper | 版本 |
|---|---|
| `bpf_probe_read`（老的统一读） | 4.1 |
| `bpf_probe_read_user` / `_str`、`bpf_probe_read_kernel` / `_str` | 5.5（拆分） |
| `bpf_probe_write_user` | 4.8（GPL-only） |
| `bpf_get_current_pid_tgid` / `uid_gid` / `comm` | 4.2 |
| `bpf_get_current_task` / `_btf` | 4.~ / 5.6~ |
| `bpf_override_return` | 4.16（需内核函数标注 error injection） |
| `bpf_send_signal` | 5.3 |
| `bpf_get_stackid` / `bpf_get_stack` | 4.6 / 4.18~ |
| `bpf_d_path` | 5.10 |

**打印与格式化**

| helper | 版本 | 说明 |
|---|---|---|
| `bpf_trace_printk`（`bpf_printk` 宏） | 4.1 | 调试打印，见 10 章 |
| `bpf_snprintf` | 5.9~ | 格式化到 buffer，支持 `%s` |
| `bpf_seq_printf` / `_btf`、`bpf_seq_write` | 5.8 | bpf_iter 输出 |
| `bpf_trace_vprintk` | 5.16~ | 超过 3 参数的 printk |

**事件**

| helper | 版本 |
|---|---|
| `bpf_perf_event_output`（+ `BPF_F_CURRENT_CPU`） | 4.4~ |
| `bpf_ringbuf_reserve` / `submit` / `discard` / `output` | 5.8 |

**时间 / 随机 / 其他**

| helper | 版本 |
|---|---|
| `bpf_ktime_get_ns` / `bpf_ktime_get_boot_ns` | 4.1 / 5.8~ |
| `bpf_get_prandom_u32` | 4.1 |
| `bpf_get_smp_processor_id` | 4.1 |
| `bpf_tail_call` | 4.2 |
| `bpf_strncmp` | 5.17~ |
| `bpf_copy_from_user` / `_kernel` | 5.10~ |
| `bpf_timer_init` / `set_callback` / `start` | 5.15 |
| `bpf_get_attach_cookie` | 5.15（cilium `KprobeOptions.Cookie` 注释印证） |
| `bpf_sys_bpf` / `bpf_sys_close` | 5.14（SYSCALL 类型） |
| `bpf_per_cpu_ptr` / `this_cpu_ptr` | 5.6~ |
| `bpf_skb_ecn_set_ce`、`bpf_getsockopt`/`setsockopt`、`bpf_tcp_*` 系 | 4.13~5.~ | 网络细粒度（按需查） |

## 5. 挂载与 link 机制

| 机制 | cilium/ebpf | 版本 |
|---|---|---|
| tc filter（clsact） | 无原生（netlink） | 4.5 |
| XDP attach（generic/driver） | `link.AttachXDP` | 4.8 |
| XDP link 化 | 同上（link 路径） | 5.8 |
| raw tracepoint | `link.AttachRawTracepoint` | 4.17 |
| tracepoint | `link.Tracepoint` | 4.7 |
| kprobe/kretprobe | `link.Kprobe/Kretprobe` | 4.1 |
| fentry/fexit/fmod_ret | `link.AttachTracing` | 5.5 |
| freplace | `link.AttachFreplace` | 5.5 |
| LSM | `link.AttachLSM` | 5.7 |
| **BPF link 通用体系** | 各 `Link` | 5.7 |
| cgroup（link 化） | `link.AttachCgroup` | 4.10（attach）/ 5.15~（link 化） |
| bpf_iter | `link.AttachIter` | 5.8 |
| netns（FLOW_DISSECTOR） | `link.AttachNetNs` | 5.15 |
| kprobe multi | `link.AttachKprobeMulti`?（`features.HaveBPFLinkKprobeMulti` 探测） | 5.18 |
| kprobe session | `features.HaveBPFLinkKprobeSession` | 6.~ |
| uprobe multi | `features.HaveBPFLinkUprobeMulti` | 6.0~ |
| netfilter | `link.AttachNetfilter` | 6.~（link 形式） |
| **tcx** | `link.AttachTCX` | 6.6 |
| netkit | `link.AttachNetkit` | 6.7~ |

## 6. `bpf()` 系统调用子命令演进（粗粒度）

| 子命令 | 版本 | 说明 |
|---|---|---|
| `MAP_CREATE` / `MAP_LOOKUP_ELEM` / `MAP_UPDATE_ELEM` / `MAP_DELETE_ELEM` / `MAP_GET_NEXT_KEY` / `PROG_LOAD` | 3.18 | 核心 |
| `PROG_TEST_RUN` | 4.4 | 用户态直接运行程序 |
| `OBJ_PIN` / `OBJ_GET` | 4.4 | bpffs pin |
| `PROG_ATTACH` / `PROG_DETACH` | 4.1+ | 旧式挂载（cgroup/sockmap） |
| ID/FD 管理族（`*_GET_FD_BY_ID` 等） | 4.13± | 枚举/引用已有对象 |
| `BTF_LOAD`、`BTF_GET_FD_BY_ID` | 4.18 | BTF 上传 |
| `MAP_FREEZE` | 5.2 | map 只读化 |
| `MAP_LOOKUP_BATCH` / `UPDATE_BATCH` / `DELETE_BATCH` / `LOOKUP_AND_DELETE_BATCH` | 5.6 | 批量（cilium `HaveBatchAPI`） |
| `LINK_CREATE` / `LINK_UPDATE` / `LINK_GET_FD_BY_ID` / `LINK_DETACH` | 5.7 | link 体系 |
| `ENABLE_STATS` | 5.8 | `run_time_ns` 统计 |
| `ITER_CREATE` | 5.8 | iter link 实例化 |
| `PROG_BIND_MAP` | 5.10~ | 程序绑定 map 生命周期 |

## 7. verifier 与日志能力

| 能力 | 版本 |
|---|---|
| 验证器基础（4096 指令上限） | 3.18 |
| 指令上限 100 万 | 5.2 |
| `BPF_LOG_LEVEL2`（每指令状态）、`BPF_LOG_STATS`（统计） | 5.2 |
| 有界循环 | 5.3 |
| BPF-to-BPF 调用 | 4.16 |
| 尾调用深度 33 | 4.2~ |
| 32 位与 64 位混合运算精确校验 | 4.14+ 持续收紧 |

## 8. cilium/ebpf 能力探测 API ↔ 特性

全部在 `github.com/cilium/ebpf/features`（v0.22 实测导出）：

```go
features.HaveProgramType(ebpf.XDP)                 // error: nil=支持
features.HaveMapType(ebpf.RingBuf)                 // ErrNotSupported=确定不支持
features.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbStoreBytes)  // 某类型能否用某 helper
features.HaveBatchAPI()                            // map 批量
features.HaveMapFlag(ebpf.FNoPrealloc)             // map flag
features.HaveBoundedLoops()                        // 有界循环
features.HaveLargeInstructions()                   // 100 万指令
features.HaveV2ISA()/V3ISA()/V4ISA()               // 指令集扩展
features.HaveBPFLinkKprobeMulti()                  // kprobe multi
features.HaveBPFLinkUprobeMulti()                  // uprobe multi
features.HaveBPFLinkKprobeSession()                // kprobe session
```

返回错误语义：`nil` 支持；`ebpf.ErrNotSupported` 确定不支持；其他错误
（常见权限）= 探测失败，**不要**当“不支持”。结果有进程内缓存。

## 9. 自查手册：这台机器到底支持什么

### 9.1 一眼看全貌

```bash
uname -r                                          # 内核版本（先记下）
ls /sys/kernel/btf/vmlinux                        # 有 → BTF/CO-RE 可用（5.4+）
zcat /proc/config.gz | grep -E "CONFIG_BPF=|CONFIG_BPF_SYSCALL|CONFIG_DEBUG_INFO_BTF|CONFIG_BPF_JIT" \
  || grep -E "CONFIG_BPF=|CONFIG_DEBUG_INFO_BTF" /boot/config-$(uname -r)
cat /proc/sys/kernel/unprivileged_bpf_disabled    # 0=允许非特权 1=禁(可改回) 2=禁(不可逆)
grep -o bpf /sys/kernel/security/lsm              # LSM 程序是否可用
```

### 9.2 bpftool feature probe（权威）

```bash
sudo bpftool feature probe                       # 摘要：版本+关键能力
sudo bpftool feature probe full                 # 全量（很长）
sudo bpftool feature probe full | grep -i ringbuf
sudo bpftool feature probe map_type name ringbuf       # 单项：map 类型
sudo bpftool feature probe prog_type name xdp          # 单项：程序类型
sudo bpftool feature probe helper name bpf_probe_read_kernel  # 单项：helper
sudo bpftool feature probe macro                # 输出 C 宏形式（可 include 用）
```

### 9.3 看当前挂载与对象

```bash
sudo bpftool prog show / map show / link show / net show
ls -l /sys/fs/bpf/                              # pinned 对象
```

### 9.4 Go 侧探测（部署期降级逻辑用）

```go
if err := features.HaveMapType(ebpf.RingBuf); errors.Is(err, ebpf.ErrNotSupported) {
    // 退回 PerfEventArray 方案
}
```

### 9.5 发行版注意

- Ubuntu LTS HWE 内核（如 22.04 跑 6.8）功能远超其“发行版本直觉”；
- RHEL 系大量 backport，**永远以 feature probe 结果为准**；
- 容器内看到的是宿主机内核（`uname -r` 同宿主），但 capability 与挂载
  （bpffs、tracefs）受容器 runtime 限制。

---

下一章：[10-debugging.md](10-debugging.md)——调试信息查看完全指南。
