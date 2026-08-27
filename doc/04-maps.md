# 04 · Map 深入：API、迭代、事件与数据一致性

目标：掌握 map 的全部日常 API（含批量与 per-CPU 的特殊规则）、两种
内核→用户事件通道（ringbuf/perf）、以及“结构体布局 + 对齐 + 字节序”
这个 eBPF 工程中最阴险的 bug 来源。API 以 v0.22.0 实测为准。

---

## 1. map 从哪来

三条路：

```go
// ① ELF 里定义（BTF map definition），随 Collection 加载
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be64);
    __type(value, struct Message);
    __uint(max_entries, 1024);
} message_map SEC(".maps");

// ② Go 手搓 MapSpec 再实例化（适合纯用户态建表/动态表）
m, err := ebpf.NewMap(&ebpf.MapSpec{
    Type:       ebpf.Hash,
    KeySize:    8,
    ValueSize:  110,
    MaxEntries: 1024,
    Name:       "ctrl_map",
})

// ③ 恢复 pin
m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/ctrl_map", nil)
```

`MapSpec` 完整字段（v0.22 实测）：

```go
type MapSpec struct {
    Name       string
    Type       MapType
    KeySize    uint32
    ValueSize  uint32
    MaxEntries uint32
    Flags      uint32      // 如 BPF_F_NO_PREALLOC
    Pinning    PinType     // 配合 MapOptions.PinPath
    NumaNode   uint32
    Contents   []MapKV     // 初始键值（加载时写入）
    InnerMap   *MapSpec    // map-in-map 模板（ArrayOfMaps/HashOfMaps）
    MapExtra   uint64      // 5.16+，语义随 map 类型
    Key, Value btf.Type    // 类型信息（BTF 定义时自动带）
    // ...
}
```

BTF map 定义里还能写 `__uint(pinning, LIBBPF_PIN_BY_NAME);`、
`__uint(map_flags, BPF_F_NO_PREALLOC);`——与 MapSpec 字段一一对应。

## 2. 类型选型表

| MapType | key/value 特点 | 语义要点 | 版本 |
|---|---|---|---|
| `Hash` | 任意 | 动态增删；单 key 操作原子；bucket 锁 | 4.x |
| `Array` | key=u32 下标 | 预分配连续；查找零哈希开销；不能删 | 4.x |
| `PerCPUHash` / `PerCPUArray` | value 变成每 CPU 一份 | 无锁高频写；读取要聚合 | 4.x |
| `LRUHash` / `LRUPerCPUHash` | 同 Hash | 满 `max_entries` 淘汰最久未用 | 4.10 |
| `RingBuf` | 无 key | 内核→用户事件环形队列（单缓冲多生产者） | 5.8 |
| `PerfEventArray` | key=cpu | 旧事件通道，per-CPU 缓冲 | 4.x |
| `ProgArray` | key=u32, value=prog FD | 尾调用跳转表 | 4.x |
| `ArrayOfMaps`/`HashOfMaps` | value 是内层 map FD | 两级 map | 4.12 |
| `Queue`/`Stack` | 无 key | FIFO/LIFO，`peek/pop` | 4.20/5.4? 队列 4.20，栈 4.20 |
| `BloomFilter` | 概率成员 | 可能误判、绝不漏判 | 5.16 |
| `SockHash`/`DevMap`/`CPUMap` | 存 socket/设备 | 做 REDIRECT/sockmap 代理 | — |

flags 常用位：`BPF_F_NO_PREALLOC`（hash 不预分配，省内存但首次写慢）、
`BPF_F_MMAPABLE`（array 可 mmap，配合 `Map.Memory()`）、LRU 用类型而非
flag 表达。

## 3. 用户态 CRUD API

```go
// 写
err := m.Update(key, value, ebpf.UpdateAny)     // 存在则覆盖
err = m.Update(key, value, ebpf.UpdateNoExist)  // 已存在报错（EEXIST）
err = m.Update(key, value, ebpf.UpdateExist)    // 不存在报错（ENOENT）
err = m.Put(key, value)                          // UpdateAny 的糖

// 读（valueOut 会被 marshal 填充）
err = m.Lookup(key, &value)
raw, err := m.LookupBytes(key)                   // 不解码，拿原始字节

// 读并删除（原子）
err = m.LookupAndDelete(key, &value)

// 删 / 遍历游标
err = m.Delete(key)
err = m.NextKey(key, &next)        // key==nil 时返回第一个 key

// 元信息
info, _ := m.Info()                // MapInfo: Type/KeySize/ValueSize/MaxEntries/ID...
id := info.ID

// pin
_ = m.Pin("/sys/fs/bpf/foo")
```

`key/value` 参数是 `any`：库按 Go 结构体布局序列化（规则见 §7），
传指针或值皆可；不匹配 `KeySize/ValueSize` 会报错，这是排查布局问题的
第一信号。

### 3.1 map value 的原地修改（内核侧）

内核侧 `bpf_map_lookup_elem` 返回 value 的**指针**，写 `*cnt += 1`
直接改内核内存；用户态 `Update` 则是整值替换——没有“读改写原子性”，
需要的话：

- 用 `LookupAndDelete`/单 key 语义设计（消息队列式，ruport 的
  message_map 就是“取出即删除”，天然不丢不重）；
- 或内核侧用 `bpf_spin_lock`（hash map 内嵌锁，4.x 后期）；
- 或接受 last-writer-wins（计数器场景用 per-CPU map）。

## 4. 迭代与批量

### 4.1 Iterate（get_next_key 封装）

```go
iter := m.Iterate()
var k uint64
var v TcRouter
for iter.Next(&k, &v) {
    // ...
}
if err := iter.Err(); err != nil { /* 迭代中出错 */ }
```

语义：底层是 `BPF_MAP_GET_NEXT_KEY` 游标，**不是快照**——迭代期间
被并发增删的 key 可能出现（新插入）或消失（已删），也可能游标跳跃
（删的是“下一个”）。需要稳定视图就先收集 key 再处理，或用批量 API。
ruport-go 的 `pollMessages` 正是“Iterate 只收集 key，随后逐个
LookupAndDelete”，与原 C 版 get_next_key 循环语义一致。

### 4.2 批量 API（kernel 5.6+）

```go
var keys [64]uint64
var vals [64]TcRouter
cursor := new(ebpf.MapBatchCursor)
n, err := m.BatchLookup(cursor, &keys, &vals, &ebpf.BatchOptions{})

n, err = m.BatchUpdate(&keys[:n], &vals[:n], &ebpf.BatchOptions{})
n, err = m.BatchDelete(&keys[:n], &ebpf.BatchOptions{})
n, err = m.BatchLookupAndDelete(cursor, &keys, &vals, opts)  // 消费队列利器
```

一次系统调用搬一批，比逐 key 快一个量级；`cursor` 记录断点，循环直到
`n==0`。老内核上报 `ErrNotSupported`，可用 `ebpf.HaveBatchAPI()` 探测。

## 5. per-CPU map

value 在每个 CPU 各存一份，内核侧写自己 CPU 的副本，**无锁**。代价：
value 实际占用 = `value_size` 上取整到 8 字节 × CPU 数；用户态必须整组读。

cilium/ebpf 对 per-CPU map 的 `Lookup/Update` 做Transparent 处理：
传入**切片**（长度 = CPU 数）即可：

```go
ncpu := runtime.NumCPU()
vals := make([]uint64, ncpu)          // ArrayOfCounter: value=u64
_ = m.Lookup(uint32(0), &vals)        // 每核一份
var total uint64
for _, v := range vals { total += v } // 聚合
```

内核侧则毫无感知差异（`bpf_map_lookup_elem` 拿到的就是本核指针）。

## 6. 内核→用户事件

### 6.1 ringbuf（首选，5.8+）

内核侧：

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);    // 16MB，2 的幂
} events SEC(".maps");

struct event { u32 pid; char comm[16]; };

struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (e) {
    e->pid = (bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);        // 或 bpf_ringbuf_discard(e, 0) 弃单
}
```

Go 侧（v0.22 实测 API）：

```go
rd, err := ringbuf.NewReader(objs.Events)
defer rd.Close()

for {
    record, err := rd.Read()      // 阻塞；类型 ringbuf.Record
    if err != nil {
        if errors.Is(err, ringbuf.ErrClosed) {  // rd.Close() 后唤醒
            return
        }
        log.Printf("ringbuf: %v", err)          // 其余按记录级错误处理
        continue
    }
    // record.RawSample 就是 bpf_ringbuf_submit 的那块字节
    var e Event
    if err := binary.Read(bytes.NewReader(record.RawSample),
        binary.LittleEndian, &e); err != nil { ... }
}
```

要点：

- 单个 map、无 per-CPU 缓冲，**天然保序**（同一生产者），内核侧
  reserve/submit 零拷贝；
- 消费太慢内核会覆盖旧记录，`Record.Remaining` 反映拥塞程度；
  需要不丢就 `max_entries` 开大 + 消费并行化；
- `NewReader` 会设置 epoll，多 reader 各自独立；`Close` 触发
  `ErrClosed` 唤醒阻塞中的 `Read`。

### 6.2 perf event array（老内核兼容）

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
```

```go
rd, err := perf.NewReader(objs.Events, 4096 /*每 CPU 缓冲字节*/)
// perf.Record{ CPU int; RawSample []byte; ... }
record, err := rd.Read()   // 或 ReadInto(&record)
```

差异：per-CPU 各一条环形缓冲，极端负载下**跨 CPU 乱序**；旧内核兼容
（4.x）是唯一优势。新代码一律 ringbuf。

## 7. 结构体一致性：布局、对齐、字节序

（最常见的一类“程序对但数据全错”问题，ruport 全链路都踩在这条线上。）

### 7.1 C 侧布局与 `#pragma pack`

ruport 的 `common.h`：

```c
#pragma pack(1)
struct Message {
    __be16 ins;         // +0, 2B
    __be32 cip;         // +2, 4B（pack(1)：不加对齐填充）
    __be16 cport;       // +6
    __be16 connport;    // +8
    __be16 nativeport;  // +10
    unsigned char ext[100]; // +12
};                      // 共 110 字节
#pragma pack()
```

若不 pack，编译器会在 `ins` 后插 2 字节对齐 `cip`，结构变成 112 字节，
且偏移全变——**内核和用户只要有一边 pack 一边不 pack，数据立刻错位**。
工程纪律：跨边界的结构一律 pack(1)（或两边都用自然对齐并显式留
padding 字段），并用 `sizeof`/BTF 双重确认（`bpftool btf dump` 可看）。

### 7.2 Go 侧布局

Go 结构体有自然对齐（`uint32` 字段按 4 字节对齐）。bpf2go 生成时依据
BTF 处理 packed 结构（不加 padding，逐字段排）；手写就要自己保证：

```go
type Message struct {
    Ins        uint16    // +0
    Cip        uint32    // +2 ← Go 会想把它对到 +4！
    ...
}
```

上面手写版在 Go 里 `Cip` 实际偏移是 +4（编译器插了 padding），
与 pack(1) 的 C 版不兼容。手写修法：

```go
type Message struct {
    Ins  uint16
    _    [2]byte "padding"   // 显式补齐
    Cip  uint32
    ...
}
```

——这也是为什么本仓库坚持 `-type Message`/`-type Router` 生成而非手写。

### 7.3 字节序：`__be` 字段的 Go 处理

map 内存里 `__be16 cport = htons(3333)` 存的是**网络序字节**。Go 从
map 读出的 `uint16` 是“这些字节按主机序解释”——小端机器上数值等于
字节反转。ruport-go 的转换（`internal/control/control.go`）：

```go
// ntohs 等价：先按主机序还原成字节（小端），再按大端读出数值
func toHostPort(port uint16) uint16 {
    var b [2]byte
    binary.LittleEndian.PutUint16(b[:], port) // 还原内存中的原始字节
    return binary.BigEndian.Uint16(b[:])      // 按网络序解释
}

// __be32 → 点分字符串：内存字节本就是网络序，直接按大端拼 IP
func ip2str(ipv4 uint32) string {
    b := make(net.IP, 4)
    binary.LittleEndian.PutUint32(b, ipv4)
    return b.String()
}
```

为什么 `PutUint32` 用 `LittleEndian`：把主机序整数还原成“内存里的
原字节序列”，而那串字节本来就是网络序的 IP。三步口诀：
**主机序整数 → LittleEndian 还原字节 → 按字段语义（BigEndian）再解释**。

反过来往 map 写网络序字段（c3 构造指令包、用户态写 router_map 的
key/value）用 `binary.BigEndian.PutUint16/32`。

### 7.4 key 的设计

- hash map 的 key 也是裸字节：复合键要么用 packed struct，要么像
  ruport 一样**手工压成一个整数**：
  `key = uint64(cip) << 16 | uint64(cport)`（内核/用户用同一份原始值
  计算，字节序无关）；
- key 长度影响哈希散布，一般 8/16 字节为宜；
- 注意“逻辑不同但字节相同”的冲突：上面这个 key 里 cport 只占 16 位，
  同 IP 同端口不同场景会撞键——ruport 语义上“一个控制端连接一条路由”，
  正好一一对应。

## 8. map 的内核侧 API 速查（bpf_helpers）

```c
void    *bpf_map_lookup_elem(&map, &key);
long     bpf_map_update_elem(&map, &key, &val, BPF_ANY | BPF_EXIST | BPF_NOEXIST);
long     bpf_map_delete_elem(&map, &key);
long     bpf_map_push_elem(&map, &val, flags);      // queue/stack
void    *bpf_map_lookup_percpu_elem / ...           // 显式取他核副本（少用）
```

内核侧不能“遍历”普通 hash map（没有迭代器 helper）；要做聚合就
`for` 固定 key 空间（array）或把逻辑搬到用户态。ruport 的分工是
典型的“内核只做单 key 读写 + 用户态轮询搬运”。

## 9. 实战小抄

- **计数器**：`PerCPUArray` + 定时聚合；
- **配置下发**：`Array`，用户态 `Update`，内核侧 lookup 默认值兜底；
- **事件**：`RingBuf` + goroutine 消费 + `ErrClosed` 退出；
- **会话/路由表**：`Hash`，如 ruport `router_map`；配 `LRUHash` 防膨胀；
- **跨进程共享**：pin + `LIBBPF_PIN_BY_NAME` + `MapOptions.PinPath`；
- **调试利器**：`bpftool map dump name message_map` 直接看内核里的
  原始字节，与 Go 读数对照，布局 bug 一眼现形。

---

下一章：[05-links.md](05-links.md)——把程序挂到 XDP/TC/tracepoint 上，
以及挂载的生命周期。
