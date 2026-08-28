# 附录 B · map 类型速查表

> 选型三问：键形态？（下标/任意/无键）· 并发模型？（全局锁/桶锁/
> perCPU）· 语义？（表/队列/环形/引用表）

## hash 家族（kernel/bpf/hashtab.c，源码走读见第 13 章）

| 类型 | 版本 | 要点 |
|---|---|---|
| `HASH` | 3.18 | 任意键；桶锁；满→E2BIG；可删 |
| `PERCPU_HASH` | 4.6 | 每核一份 value，高频写无锁（第 5 章） |
| `LRU_HASH` | 4.10 | 满则淘汰最久未用（per-bucket 近似 LRU） |
| `LRU_PERCPU_HASH` | 4.10 | 两者结合 |
| `HASH_OF_MAPS` | 4.12 | value=内层 map 引用（两层） |

## array 家族（kernel/bpf/arraymap.c）

| 类型 | 版本 | 要点 |
|---|---|---|
| `ARRAY` | 3.18 | key=下标；零初始化；不可删；`BPF_F_MMAPABLE` 可 mmap |
| `PERCPU_ARRAY` | 4.6 | 计数器标配 |
| `PROG_ARRAY` | 4.2 | value=程序 FD，尾调用跳转表 |
| `PERF_EVENT_ARRAY` | 4.1 | 旧事件通道（每核一环，第 6 章） |
| `ARRAY_OF_MAPS` | 4.12 | map-in-map |
| `CGROUP_ARRAY` | 4.8 | value=cgroup FD，包/进程归属判定 |

## 事件与队列

| 类型 | 版本 | 要点 |
|---|---|---|
| `RINGBUF` | 5.8 | **事件首选**：单环保序、reserve/submit 零拷贝；max_entries 须 2 的幂 |
| `USER_RINGBUF` | 6.8~ | 用户态→内核方向 |
| `QUEUE` / `STACK` | 4.20 | FIFO/LIFO；push/pop/peek，满则报错可背压 |

## 查找与引用

| 类型 | 版本 | 要点 |
|---|---|---|
| `LPM_TRIE` | 4.11 | 最长前缀匹配；key 首字段=prefixlen；建议 NO_PREALLOC |
| `BLOOM_FILTER` | 5.16 | 概率成员（可能误判不漏判） |
| `STACK_TRACE` | 4.6 | `bpf_get_stackid` 的栈存储 |
| `DEVMAP` / `DEVMAP_HASH` | 4.14 / 5.3~ | XDP 转发出口表（value 可带程序） |
| `CPUMAP` | 4.15 | XDP 重定向到指定 CPU |
| `XSKMAP` | 4.18 | AF_XDP socket 表 |
| `SOCKMAP` / `SOCKHASH` | 4.14 / 4.18 | socket 引用，配合 SK_SKB/SK_MSG 做短路（第 9 章） |
| `REUSEPORT_SOCKARRAY` | 4.19 | reuseport 组下标选择 |
| `SK_STORAGE` | 5.2~ | 以 socket 为键的本地存储 |
| `CGROUP_STORAGE`(±percpu) | 4.19~ | attach 同 cgroup 的程序共享 |
| `INODE_STORAGE` / `TASK_STORAGE` | 5.10 / 5.11 | inode/task 本地存储 |

## 通用规则速记

- value 读出为**副本**（用户态）/ **指针可原地写**（内核态）——第 4 章；
- per-CPU 体积 = `round_up(value_size,8) × CPU 数`；hash 元素
  `key_size` 取整到 8——第 13 章；
- 常用 flags：`BPF_F_NO_PREALLOC`（hash 不预分配）、
  `BPF_F_MMAPABLE`（array 可 mmap）、pin 常量
  `LIBBPF_PIN_BY_NAME` 配合 `MapOptions.PinPath`。
