# 附录 C · helper 分组速查表

> 权威来源：`/usr/include/bpf/bpf_helper_defs.h`（每个 helper 的
> 注释列明可用程序类型与引入版本）。本表按用途分组，标注主线
> 版本（~ 表示近似，实测为准）。

## map 操作

| helper | 版本 |
|---|---|
| `bpf_map_lookup_elem` / `update_elem` / `delete_elem` | 3.19 |
| `bpf_map_push_elem` / `pop_elem` / `peek_elem`（queue/stack） | 4.20 |
| `bpf_for_each_map_elem` | 5.13~ |

## 包处理（tc / XDP / cgroup）

| helper | 版本 | 常用侧 |
|---|---|---|
| `bpf_skb_store_bytes` | 4.1 | tc 改包（ruport 用） |
| `bpf_l3_csum_replace` / `bpf_l4_csum_replace` | 4.1 | tc 校验和 |
| `bpf_csum_diff` | 4.1 | 增量和 |
| `bpf_skb_load_bytes(_relative)` | 4.1 | 通用读包 |
| `bpf_xdp_adjust_head(_meta)` | 4.8~ | XDP |
| `bpf_redirect` / `bpf_redirect_map` | 4.1 / 4.14 | tc+XDP 转发 |
| `bpf_fib_lookup` | 4.18 | 查路由 |
| `bpf_sk_lookup_tcp` / `udp` | 4.20 | 查 socket |
| `bpf_skb_adjust_room` / `clone_redirect` | 4.1 | tc |

## tracing / 进程

| helper | 版本 |
|---|---|
| `bpf_probe_read`（老统一版） | 4.1 |
| `bpf_probe_read_user(_str)` / `kernel(_str)` | 5.5（拆分） |
| `bpf_probe_write_user` | 4.8（GPL） |
| `bpf_get_current_pid_tgid` / `uid_gid` / `comm` | 4.2 |
| `bpf_get_current_task(_btf)` | 4.~ / 5.6~ |
| `bpf_get_stackid` / `bpf_get_stack` | 4.6 / 4.18~ |
| `bpf_override_return` | 4.16（error-injection 函数） |
| `bpf_send_signal(_thread)` | 5.3 / 5.10~ |
| `bpf_d_path` | 5.10 |

## 打印与格式化（详见第 15 章 15.4）

| helper | 版本 | 限制 |
|---|---|---|
| `bpf_trace_printk`（`bpf_printk` 宏） | 4.1 | ≤3 参；格式白名单 |
| `bpf_snprintf` | 5.9~ | 先格式化再输出/入环 |
| `bpf_trace_vprintk` | 5.16~ | 多参版 |
| `bpf_seq_printf(_btf)` / `seq_write` | 5.8 | bpf_iter 输出 |

## 事件

| helper | 版本 |
|---|---|
| `bpf_perf_event_output`（`BPF_F_CURRENT_CPU`） | 4.4~ |
| `bpf_ringbuf_reserve` / `submit` / `discard` / `output` | 5.8 |

## 时间 / 随机 / 其他

| helper | 版本 |
|---|---|
| `bpf_ktime_get_ns` / `boot_ns` | 4.1 / 5.8~ |
| `bpf_get_prandom_u32` / `smp_processor_id` | 4.1 |
| `bpf_tail_call` | 4.2 |
| `bpf_strncmp` | 5.17~ |
| `bpf_copy_from_user(_kernel)` | 5.10~ |
| `bpf_timer_init` / `set_callback` / `start` | 5.15 |
| `bpf_get_attach_cookie` | 5.15 |
| `bpf_per_cpu_ptr` / `this_cpu_ptr` | 5.6~ |
| `bpf_sys_bpf` / `bpf_sys_close` | 5.14（SYSCALL 型） |

## 白名单机制（为什么"这个 helper 不让我用"）

每种程序类型的可用集合由内核 `get_func_proto` 回调决定，验证器
逐调用检查（第 3 章典型拒绝之六）。查证顺序：
`bpf_helper_defs.h` 注释 → `bpftool feature probe helper name xxx`
→ 换程序类型或换实现思路。
