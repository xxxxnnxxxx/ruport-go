# 第 13 章 map 的内核实现

> 第 4 章背过 hash/array 的行为差异，第 5 章解释过迭代语义与
> E2BIG——这些结论在 `kernel/bpf/` 里有逐一对应的源码。本章带你
> 走读 hashtab 的数据结构与增删查改流程，把"背下来的行为"变成
> "推导出来的必然"；最后用 bpftool 做几个实验，亲手验证源码
> 结论。ruport 的 message_map/router_map 是本章的贯穿案例。

## 13.1 从用到懂：为什么读源码

三个功利理由：

1. **排障降维**：理解 bucket 锁粒度后，"多线程读 map 偶发慢"不再
   是玄学（13.2.4 的锁区间）；
2. **容量估算有据**：预分配内存到底占多少，能算出来（13.4 实验）；
3. **API 语义不模糊**：迭代为什么"跳键"、LookupAndDelete 为什么
   原子——源码即标准答案。

map 多态的骨架先立起来：内核用一张**函数表**把"类型"接到
"实现"上（`include/linux/bpf_types.h`）：

```
 BPF_MAP_TYPE(HASH,            htab_map_ops)         ┐
 BPF_MAP_TYPE(PERCPU_HASH,     htab_percpu_map_ops)   ├ hash 家族共用
 BPF_MAP_TYPE(LRU_HASH,        htab_lru_map_ops)      │ hashtab.c
 BPF_MAP_TYPE(HASH_OF_MAPS,    htab_of_maps_map_ops) ┘
 BPF_MAP_TYPE(ARRAY,           array_map_ops)         ┐ array 家族共用
 BPF_MAP_TYPE(PERCPU_ARRAY,    percpu_array_map_ops)  ├ arraymap.c
 BPF_MAP_TYPE(PROG_ARRAY,      prog_array_map_ops)    ┘
 （完整映射表见附录 B；QUEUE/STACK→queue_stack_maps.c，
   RINGBUF→ringbuf.c，SOCKMAP→net/core/sock_map.c …）
```

所有类型的"户口本"是同一个 `struct bpf_map`（通用元数据）：

```c
struct bpf_map {
    const struct bpf_map_ops *ops;   // ★ 多态入口：增删查改函数指针
    enum bpf_map_type map_type;
    u32 key_size, value_size, max_entries, map_flags;
    u32 id;                          // 系统级编号（bpftool 枚举用）
    struct btf *btf;
    bool frozen;                     // MAP_FREEZE 后只读
    atomic64_t refcnt;               // ★ 引用计数：归零即销毁
    ...                              //  （第2章"FD关=销毁"的机制根源）
};
```

每种类型再把它嵌进自己的私有结构（hash 是 `bpf_htab`，array 是
`bpf_array`）。

## 13.2 hashtab：数据结构与增删查改走读

源码：`kernel/bpf/hashtab.c`（本章按 5.10 前后的主线版本讲，读者
内核细节可能略异，主干稳定）。

### 13.2.1 数据结构：bucket 与 element 分离

```
 struct bpf_htab —— 一个 hash map 的全部
 ┌─────────────────────────────────────────────────┐
 │ struct bpf_map map;      通用元数据               │
 │ struct bucket *buckets;  ──▶ 槽数组：只存链表头+锁 │
 │ void *elems;             ──▶ 预分配元素区(可选)    │
 │ union { pcpu_freelist / bpf_lru };               │
 │ atomic_t count;          当前元素数               │
 │ u32 n_buckets, elem_size, hashrnd;               │
 └─────────────────────────────────────────────────┘

 bucket（槽）—— 不放数据，只挂链表和锁：
 ┌──────────────────────────┐
 │ hlist_nulls_head head;    │
 │ spinlock_t lock;          │ ★ 锁粒度 = 单个桶
 └──────────────────────────┘

 htab_elem（元素头）—— 后面紧跟 key+value：
 ┌──────────────────────────────────────┐
 │ hlist_nulls_node hash_node;  桶内链表  │
 │ rcu_head / lru_node;         延迟释放  │
 │ u32 hash;                    缓存的哈希│
 │ char key[] __aligned(8);     ←key，8对齐│
 │            ←value 紧跟其后    │
 └──────────────────────────────────────┘
```

三个设计点，每个都对应你观察过的行为：

- **value 地址 = elem->key + round_up(key_size, 8)**——`key_size`
  向上取整到 8！第 4 章"Go 结构体必须精确对齐"的内核侧依据；
- 槽内链表用 `hlist_nulls`（尾节点是带桶号的"nulls 标记"）：
  查找途中若元素被并发搬到别的桶，能检测出来并重走——**无锁
  查找**的基础；
- `hashrnd`：建表时随机化的哈希种子——防碰撞攻击。

### 13.2.2 创建：htab_map_alloc()

```
htab_map_alloc(attr)
 ├─ 分配 bpf_htab，复制 key/value_size 等元数据
 ├─ n_buckets = round_up_pow_of_two(max_entries)   ← 桶数取2的幂
 │                                                  （位与代替取模）
 ├─ bpf_map_charge_init(cost)          内存记账，防超限
 ├─ buckets = bpf_map_area_alloc(...)  小则kmalloc，大则vmalloc
 ├─ hashrnd = 随机
 └─ if (预分配，默认开)
      elems = 一次性分配 elem_size × max_entries
      freelist 初始化（LRU 变体则建 LRU 链）
      if (!percpu && !lru) 每CPU再备 1 个 extra_elem
```

**预分配（默认）的取舍**：插入路径零内存分配（从 freelist 摘），
性能高；代价是**建表瞬间占满全部容量内存**（13.4 实验验证）。
`BPF_F_NO_PREALLOC` 换成插入时 `kmalloc(GFP_ATOMIC)`——省内存
但慢、可能分配失败。ruport 两张 1024 项的表用默认预分配毫无
压力。

### 13.2.3 查找：为什么"先比 hash 再比 key"

```
htab_map_lookup_elem(map, key)
 ├─ hash = hash(key, hashrnd)
 ├─ head = &buckets[hash & (n_buckets-1)]     ← O(1) 定桶
 ├─ 遍历桶链：
 │     if (elem->hash == hash && memcmp(elem->key, key)==0)
 │         return elem->key + round_up(key_size, 8);  ★ value 指针
 └─ 没找到 → NULL
```

内核态 `bpf_map_lookup_elem` 拿到的是**直接指向内核 value 的
指针**——第 4 章"原地写"的源码出处；用户态走系统调用，内核把
value **拷贝**给用户——"指针 vs 副本"差异的出处。

### 13.2.4 插入/更新：锁、头插与 E2BIG

主干流程（省略 BPF_F_LOCK 分支）：

```
htab_map_update_elem(map, key, value, flags)
 ├─ hash → 定桶
 ├─ 无锁快查旧元素（命中则元素锁内原地覆盖，结束）
 ├─ ★ 取 bucket 锁
 ├─ 再查一次旧元素（双检：快查后可能有人抢先插入）
 ├─ alloc_htab_elem：
 │    预分配：从 freelist 摘
 │    非预分配：count++ 后 kmalloc；count > max_entries → -E2BIG ★
 ├─ 新元素 hlist_nulls_add_head_rcu() ← 挂链表头（并发查找先见新值）
 └─ 若有旧元素：RCU 摘除 + 延迟释放；解锁
```

三个行为结论落锤：**E2BIG 在非预分配路径的计数检查处**（预分配
路径上 freelist 空即等价满）；**同 key 更新 = 新元素头插 + 旧元素
RCU 摘除**，读者要么见旧要么见新、绝不见半截（单条 update 的
原子性）；**锁区间只覆盖单桶**——并发度取决于桶数。

ruport 的端口学习写法（`memcpy` 出 `tmp`、改字段、整条 `update`
回表）正是为了不与并发读者竞争——在源码层面你能看清为什么"原地
改 value 指针的字段"在 bucket 锁外是不安全的。

### 13.2.5 迭代：桶序的真相

`htab_map_get_next_key`（用户态 `Iterate/NextKey` 的底层）：

```
给 key → hash 定桶 → 返回【同桶链表的下一个元素】
本桶没了 → 顺序扫描下一个非空桶，返回其首元素
key=NULL → 全表扫第一个非空桶
```

所以迭代顺序 = **桶序 × 桶内链序**，与插入顺序无关；并发删除让
游标"跳桶"、并发插入的新键可能漏看——第 5 章"游标非快照"的
源码出处。ruport 的 `pollMessages` "先收集 key 再 LookupAndDelete"
模式，处理的正是这里的不确定性。

## 13.3 array 家族与 FD 数组

`kernel/bpf/arraymap.c`，一切从"key 就是下标"出发：

```c
static void *array_map_lookup_elem(struct bpf_map *map, void *key) {
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    u32 index = *(u32 *)key;                      // key 直接当下标
    if (index >= array->map.max_entries)
        return NULL;
    return array->value + array->elem_size * index;   // 一次指针运算
}
```

- `elem_size = round_up(value_size, 8)`——**value 8 字节对齐**，
  per-CPU 变体再按 CPU 取整（第 5 章体积公式的出处）；
- 建表 `bpf_map_area_alloc` 一次性分配并**清零**——第 4 章
  "array 的 lookup 永远命中（界内）+ 天然零初始化"的出处；
- **没有 delete 回调**——连续内存挖不掉中间格，"不可删"是物理；
- 变体 `PROG_ARRAY`/`CGROUP_ARRAY` 的 value 是 **FD**：更新时
  `map_fd_get_ptr` 把 FD 换成内核对象引用（尾调用表/cgroup 判断的
  机制基础）。

## 13.4 用 bpftool 实验验证源码结论

三个实验，把本章源码结论变成亲手事实：

**实验一：预分配内存即时占用**

```bash
free -m                                  # 记录基线
sudo bpftool map create name bigmap type hash key 8 value 128 entries 1000000
free -m                                  # 立刻少 ~130MB+
# 对应 13.2.2：elem_size≈144B × 100万 ≈ 137MB，建表瞬间全额占用
sudo bpftool map show name bigmap        # 记下 map id
sudo bpftool map pinned del? ── 直接 rm：引用消失即销毁（回读 free -m）
```

**实验二：E2BIG 与 LRU 对照**

```bash
# Go 侧建 entries=4 的 hash 与 lru_hash，灌 10 个 key：
#   hash   → 第 5 个 Update 返回 "field exceeds..."(E2BIG)
#   lru    → 全部成功，bpftool map dump 看到的是最新 4 个
```

**实验三：迭代顺序 = 桶序**

```bash
# 依次插入 key=1000,1,500,7（Go 侧逐个 Update）
sudo bpftool map dump name xxx           # dump 顺序≠插入顺序
# 再插入一个新 key，观察它插在 dump 的哪个位置（桶内头插的痕迹）
```

## 13.5 小结与练习

**小结**：map 多态 = `bpf_map.ops` 函数表；hash 的核心设计是
"bucket 只挂链与锁、element 独立成区、nulls 链表支持无锁查找"；
key_size 取整到 8 解释了布局铁律；预分配换性能、桶锁定并发度、
头插+RCU 定单条原子性、get_next_key 的桶序解释迭代语义；array
的一切行为源于"下标直接寻址 + 一次零初始化 + 物理不可删"。

**练习**：
1. 完成实验一，把实测内存与理论值（`round_up(value_size,8) +
   key_size 取整 + 元素头开销` × entries）对账，误差在哪（提示：
   桶数组本身、per-CPU extra）；
2. 读 `queue_stack_maps.c` 的 `queue_map_ops`，对比它为什么
   **没有** `map_lookup_elem` 常规语义（push/pop/peek 三件套）；
3. 思考题：ruport 的 router_map 若并发场景极端化（多控制进程同时
   写），桶锁保护了什么、没保护什么？（用 13.2.4 的锁区间回答，
   并解释为什么"读-改-写整条记录"要拿出来做。）

---

map 的里子看完了。下一章回到 Go 侧：把前三篇散落的加载代码升级成
工程化的 cilium/ebpf + bpf2go 体系——ruport 的构建方式全解。
