# 12 · Map 使用场景补遗与内核实现

> 整理自 ArthurChiao's Blog《BPF 进阶笔记（二）：BPF Map 类型详解》与
> 《（三）：BPF Map 内核实现》（2021，基于内核 5.8/5.10），原文见
> https://arthurchiao.art。04 章讲“用户态怎么用 map”，本章补齐
> “每种 map 适合干什么”与“map 在内核里长什么样、增删查改怎么走”
> ——后者是理解 map 行为边界（锁、预分配、E2BIG、迭代语义）的钥匙。

---

## 1. 类型 → 内核实现映射

map 的多态由 `struct bpf_map_ops` 函数表实现，注册在
`include/linux/bpf_types.h`：

| map 家族 | ops | 实现文件 |
|---|---|---|
| HASH / PERCPU_HASH / LRU_HASH / LRU_PERCPU_HASH / HASH_OF_MAPS | `htab_*_map_ops` | `kernel/bpf/hashtab.c` |
| ARRAY / PERCPU_ARRAY / PROG_ARRAY / PERF_EVENT_ARRAY / ARRAY_OF_MAPS / CGROUP_ARRAY | `array_map_ops` 等 | `kernel/bpf/arraymap.c` |
| CGROUP_STORAGE | `cgroup_storage_map_ops` | `kernel/bpf/local_storage.c` |
| STACK_TRACE | `stack_trace_map_ops` | `kernel/bpf/stackmap.c` |
| QUEUE / STACK | `queue_map_ops`/`stack_map_ops` | `kernel/bpf/queue_stack_maps.c` |
| RINGBUF | `ringbuf_map_ops` | `kernel/bpf/ringbuf.c` |
| LPM_TRIE | `trie_map_ops` | `kernel/bpf/lpm_trie.c` |
| SOCKMAP / SOCKHASH | `sock_map_ops`/`sock_hash_ops` | `net/core/sock_map.c`（网络栈侧） |
| DEVMAP / DEVMAP_HASH | `dev_map_ops`/`dev_map_hash_ops` | `kernel/bpf/devmap.c` |
| REUSEPORT_SOCKARRAY | `reuseport_array_ops` | `kernel/bpf/reuseport_array.c` |

读内核源码时按这张表进门即可。

## 2. 通用结构体：struct bpf_map

`BPF_MAP_CREATE` 后内核持有一个 `struct bpf_map`（`include/linux/bpf.h`），
**所有类型共用**，只存元数据：

```c
struct bpf_map {
    const struct bpf_map_ops *ops;   // 多态入口：增删查改都在这
    enum bpf_map_type map_type;
    u32 key_size, value_size, max_entries, map_flags;
    int spin_lock_off;               // 内嵌 bpf_spin_lock 的偏移
    u32 id;
    struct btf *btf;                 // map 的 BTF（key/value 类型）
    bool frozen;                     // MAP_FREEZE 后置位，只读
    atomic64_t refcnt;               // 引用计数：归零触发回收
    atomic64_t usercnt;
    ...
};
```

要点：**map 的生命周期由 refcnt 驱动**——程序引用、pin 引用、用户态
FD 都会计数；这也是“进程退了 map 还在（被 pin/被程序引用）”与
“FD 全关 map 才释放”的机制根源（见 [02 章 §7](02-cilium-ebpf-core.md)）。
各类型再把 `bpf_map` 嵌进自己的私有结构（hash 是 `bpf_htab`，array
是 `bpf_array`）。

## 3. Hash 家族内核实现（kernel/bpf/hashtab.c）

### 3.1 数据结构：bucket 与 element 分离

```
       BPF Hash Map (struct bpf_htab)
  +--------------------+
  | struct bpf_map map |          通用元数据
  |--------------------|
  | struct bucket *    |------->  哈希槽数组：只存 链表头 + 锁
  |--------------------|
  | void *elems        |------->  元素区：htab_elem + key + value（链表串起）
  |--------------------|
  | count, n_buckets,  |          元数据：元素数/槽数/元素大小/哈希种子
  | elem_size, hashrnd |
  +--------------------+
```

```c
struct bpf_htab {
    struct bpf_map map;
    struct bucket *buckets;        // 槽数组（链表头 + 锁）
    void *elems;                   // 预分配元素区（prealloc 时）
    union { struct pcpu_freelist freelist; struct bpf_lru lru; };
    struct htab_elem *__percpu *extra_elems;   // 普通hash的每CPU备用元素
    atomic_t count;
    u32 n_buckets, elem_size, hashrnd;         // hashrnd：哈希随机化种子
};

struct bucket {                    // 槽：不放数据，只放链表头和锁
    struct hlist_nulls_head head;
    union { raw_spinlock_t raw_lock; spinlock_t lock; };
};

struct htab_elem {                 // 元素头，后面紧跟 key+value
    union { struct hlist_nulls_node hash_node; ... };
    union { struct rcu_head rcu; struct bpf_lru_node lru_node; };
    u32 hash;
    char key[] __aligned(8);       // key 之后（8对齐处）就是 value
};
```

设计要点（都对应你会观察到的行为）：

- **bucket 只挂链表和锁**：哈希定位 O(1)，冲突在同桶链表顺序比较
  `hash + memcmp(key)`；
- **value 地址 = elem->key + round_up(key_size, 8)**——**key_size 会
  向上取整到 8**，这解释了为什么 Go 侧结构体必须精确对齐布局
  （[04 章 §7](04-maps.md)）；
- 链表用 `hlist_nulls`（尾节点不是 NULL 而是“nulls 标记”，携带
  bucket 序号）：查找途中若发现元素被并发搬移可重走——**无锁查找**
  与 RCU 删除的基础；
- `hashrnd`：每次建表随机化哈希种子，防哈希碰撞攻击。

### 3.2 创建：htab_map_alloc()

```text
htab_map_alloc(attr)
  |- kzalloc(bpf_htab)
  |- bpf_map_init_from_attr()               # 复制 key/value_size 等元数据
  |- n_buckets = round_up(max_entries)*...   # 槽数取 2 的幂（位与取模）
  |- bpf_map_charge_init(&cost)              # 内存记账，防超限
  |- buckets = bpf_map_area_alloc()          # 小则 kmalloc，大则 vmalloc
  |- hashrnd = 随机
  |- if (prealloc) {                         # 默认预分配！
  |      elems = bpf_map_area_alloc(elem_size * n_entries)
  |      freelist/lru 初始化
  |      if (!percpu && !lru) alloc_extra_elems()   # 每CPU 1 个备用元素
  |  }
```

**预分配（默认）的取舍**：插入路径零内存分配、性能高；代价是建表即
占满 `max_entries` 全部内存。`BPF_F_NO_PREALLOC` 换成插入时
`kmalloc(GFP_ATOMIC)`——省内存但慢且可能分配失败。Cilium 的
`--preallocate-bpf-maps` 默认 false 即此权衡。ruport 的两张表
（1024 项）用默认预分配完全无感。

### 3.3 查找：htab_map_lookup_elem()

```c
static void *htab_map_lookup_elem(struct bpf_map *map, void *key) {
    struct htab_elem *l = __htab_map_lookup_elem(map, key);
    if (l)
        return l->key + round_up(map->key_size, 8);  // value 起始地址
    return NULL;
}
// __htab_map_lookup_elem:
//   hash = htab_map_hash(key, key_size, hashrnd);
//   head = &htab->buckets[hash & (n_buckets-1)].head;   // O(1) 定槽
//   遍历链表：l->hash == hash && memcmp(&l->key, key, key_size)==0 命中
```

内核态程序拿到的就是**直接指向 value 内存的指针**（所以
`*cnt += 1` 原地写、`__sync_fetch_and_add` 原子加都成立）；用户态则
由 syscall 拷贝出副本——**这是内核/用户两侧“指针 vs 副本”行为差异
的根源**。

### 3.4 插入/更新：htab_map_update_elem()

流程（合并了 BPF_F_LOCK 分支的主干）：

```text
hash → 定位 bucket
无锁快查旧元素（BPF_F_LOCK 场景）→ 命中则拿元素锁原地覆盖 value，返回
取 bucket 锁 → 再查一次旧元素（双重检查）
alloc_htab_elem():
    prealloc: 从 freelist 摘一个（或复用 extra_elems/old_elem）
    非prealloc: count++ 后 kmalloc；count > max_entries → -E2BIG
    memcpy key/value，记录 hash
新元素 hlist_nulls_add_head_rcu() 挂链表头（并发查找先见新值）
若存在旧元素：RCU 摘除，非 prealloc 则延迟释放
```

三个行为结论：

1. **满表报 E2BIG**（非 LRU）——ruport message_map 1024 项上限的来源；
2. **同 key 更新 = 新元素头插 + 旧元素 RCU 摘除**，读者要么见旧要么
   见新，不会见半截（单条 update 的原子性）；
3. bucket 锁粒度 = 单个哈希槽——并发度取决于 `n_buckets`。

### 3.5 迭代：htab_map_get_next_key()

“取下一个 key”没有额外索引：给 key 算 hash 定位到桶，**返回同桶链表
的下一个元素**；本桶没了就顺序扫到下一个非空桶取头元素；`key=NULL`
则从头扫。因此：

- **迭代顺序 = 桶序 + 链表序**，与插入序无关；
- **并发删除会让游标“跳桶”**（nulls 序号对不上时重走）——这就是
  [04 章 §4.1](04-maps.md) 说 Iterate“不是快照”的内核侧解释；
- 首个 key 只能全桶扫描，大表首次迭代稍慢。

### 3.6 LRU 变体

LRU_HASH 为**每个 bucket 维护本地 LRU 链**（`struct bpf_lru`），
插入满时淘汰“最久未用”——注意是 per-bucket 近似 LRU 而非全局精确
LRU（换性能）。conntrack/NAT 这类“固定容量、老连接可牺牲”的表用它。

## 4. Array 家族内核实现（kernel/bpf/arraymap.c）

```c
static void *array_map_lookup_elem(struct bpf_map *map, void *key) {
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    u32 index = *(u32 *)key;                        // key 就是下标
    if (unlikely(index >= array->map.max_entries))
        return NULL;
    return array->value + array->elem_size * index; // 直接寻址
}
```

- `elem_size = round_up(value_size, 8)`——**value 8 字节对齐**，
  per-CPU array 更是按 CPU 对齐取整（04 章的体积计算由此而来）；
- **一次指针运算，无哈希无锁**——计数器/配置表最快的形态；
- 建表时 `bpf_map_area_alloc` 一次性零初始化全部元素（所以 array 的
  lookup 永远“命中”，`sockex1` 里不初始化直接 `*value += len` 是对的，
  hash 这么写就是 bug）；
- **不能删除**：连续内存无法释放中间项——想“删”就写零值覆盖
  （hash 是链表所以能真删，这是两家族的语义分界）；
- 变体：PROG_ARRAY/CGROUP_ARRAY 存 **FD**（更新时由
  `map_fd_get_ptr` 换成内核对象引用，尾调用/cgroup 判断的基础）；
  `BPF_F_MMAPABLE` 让 array 可 mmap（cilium `Map.Memory()`）。

## 5. 其他家族速览（按文章三 + 本仓库注记）

- **QUEUE/STACK**（4.20）：`push/pop/peek` 语义，操作集与 hash/array
  完全不同（`queue_stack_maps.c`）；
- **CGROUP_STORAGE**：key 固定为
  `{cgroup_inode_id, attach_type}`；attach 到同一 cgroup 的程序链
  （`bpf_prog_list`）**共享**一组 storage——程序间通信不用额外 map；
- **SK_STORAGE**：以 socket 为 key 的本地存储（`bpf_sk_storage_get`，
  可 `BPF_SK_STORAGE_GET_F_CREATE` 惰性创建）；
- **DEVMAP/CPUMAP/XSKMAP**：XDP 场景的“特殊 array”——XDP 执行点太早，
  普通基础设施不可用，重定向目标（网卡/CPU/AF_XDP socket）需要专门
  表；`bpf_redirect_map()` + DEVMAP 即“极简 XDP 路由器”
  （`samples/bpf/xdp_router_ipv4_kern.c` 用 LPM_TRIE 存路由、HASH 存
  ARP、DEVMAP 做出接口）；
- **LPM_TRIE**：最长前缀匹配，路由表的正确形态（注意需
  `BPF_F_NO_PREALLOC`）；
- **RINGBUF**：见 [04 章 §6](04-maps.md)；原文标注 5.7+，主线实为
  5.8（09 章已校订）。

## 6. map 声明与 pinning（文章二补遗）

声明方式三代演进：

```c
/* ① 古老：bpf_map_def 平铺结构（samples/bpf 遍布） */
struct bpf_map_def SEC("maps") my_map = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = 4,
    .value_size = 8, .max_entries = 128,
};

/* ② iproute2/tc 私有：bpf_elf_map（多 pinning/id 字段） */

/* ③ 现代：BTF 定义（本仓库采用，libbpf 与 cilium/ebpf 均原生支持） */
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __be64);
         __type(value, struct Message); __uint(max_entries, 1024);
} message_map SEC(".maps");
```

pinning 常量（②③通用语义）：

```c
#define PIN_NONE       0   // 不 pin
#define PIN_OBJECT_NS  1   // 按对象命名空间
#define PIN_GLOBAL_NS  2   // /sys/fs/bpf/tc/globals/（tc 生态惯例）
```

libbpf/cilium 对应 `bpf_obj_pin()/bpf_obj_get()` 与 `Map.Pin()/
LoadPinnedMap()`；BTF 定义里写 `__uint(pinning, LIBBPF_PIN_BY_NAME);`
配合 `MapOptions.PinPath` 即按名自动 pin/复用（04 章已展开）。

## 7. ruport-go 视角

- `message_map`/`router_map` 都是 **HASH（预分配）**：建表即占满
  1024 项内存、满表 E2BIG、同 key 更新头插 RCU 摘旧、迭代按桶序
  ——本章 §3 的每一条都直接解释 `pollMessages` 与 XDP 侧的行为；
- TC 程序里 `struct Router *value = bpf_map_lookup_elem(...)` 后直接
  读字段、必要时拷贝到 `tmp` 再整体 `update`——正是“内核态拿 value
  指针”的用法；端口学习字段（connport/nativeport）之所以用
  “memcpy 整条替换”而不是原地点改，是为了避免与并发读者竞争；
- 用户态 Go 侧 `LookupAndDelete` 的原子性由 bucket 锁保证，
  “取出即删除”的消息语义（§3.4 + [07 章](07-ruport-go-notes.md)）
  因此成立。

---

关联阅读：[04 map 深入](04-maps.md) ·
[09 版本矩阵](09-kernel-versions.md) ·
[下一章 13-printk-and-trampoline](13-printk-and-trampoline.md)
