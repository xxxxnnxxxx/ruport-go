# 第二篇 · 数据之道

> 程序跑在内核里，价值却要落在用户态的屏幕上、告警里、决策中。
> 本篇解决 eBPF 应用的"下半身"：map 的基础语义（第 4 章）、并发与
> 规模问题（第 5 章）、从轮询到事件驱动的通信模式（第 6 章）。
> 读完本篇，你写的程序就不再只是"能在内核跑"，而是"能把数据
> 漂亮地交出来"。

---

# 第 4 章 让内核把数据交出来

> 第 1 章埋过一颗种子：cBPF 最大的局限是"算出结果没地方放"。
> eBPF 补上这块短板的发明就是 map。本章从"数据怎么出来"这个
> 原始问题出发，吃透两种基础容器（hash/array）的语义差异、内核
> 与用户态两套 API 的对照，以及跨边界最容易翻车的布局与字节序
> 问题——后者用 ruport 的真实代码做案例。

## 4.1 问题：程序在内核跑，数据要在用户态用

没有 map 的世界是什么样的？设想第 2 章的计数器只能把计数
`bpf_printk` 打进日志：

```
 无 map：数据只能"喊"出来
 ┌─────────┐   printk   ┌──────────────┐  轮询解析文本   ┌─────────┐
 │ 内核程序 │──────────▶│ trace_pipe 日志│──────────────▶│ 你的程序 │
 └─────────┘           └──────────────┘                └─────────┘
   缺点：慢(全局锁)/丢(环形覆盖)/无结构(文本)/无法反向下发配置
```

我们真正需要的是一块**内核与用户态都能直接读写的结构化存储**，
既能把数据递出来（观测），也能把配置递进去（控制）：

```
 有 map：数据双向流动
                    ┌─────────────────────┐
   观测流向 ──────▶ │  map（内核对象）      │ ◀────── 控制流向
   计数/事件/统计    │  key → value         │        规则/参数/策略
                    └─────────────────────┘
                        ▲       ▲
                bpf_map_*_elem │ │ bpf()/Lookup/Update
                        │       │
                   内核程序   用户态程序
```

map 的三个本质属性，先立住再往下走：

1. **它是内核对象**：由 `BPF_MAP_CREATE` 创建，生命周期由引用计数
   管理（第 2 章 2.6 已见过：FD 关闭即销毁）；
2. **它是裸字节容器**：内核只认 `key_size/value_size` 两个长度，
   不懂你的结构体——"两边怎么解释这串字节"是你自己的契约
   （4.5 节的全部痛苦与解法都源于此）；
3. **两侧各有一套 API**：内核侧 helper（热路径）与用户态系统调用
   （冷路径），语义对照见 4.4。

## 4.2 hash 与 array：第一对伙伴

eBPF 3.18 的最初两种 map，至今仍覆盖 80% 的使用场景。它们的能力
差异全部来自**内存组织方式**：

```
 ARRAY：连续内存，key 就是下标
 ┌────┬────┬────┬────┬────┬────┐
 │ v0 │ v1 │ v2 │ v3 │ v4 │ .. │   创建即全部分配并清零
 └────┴────┴────┴────┴────┴────┘
   ▲ key=1 直接算出地址：value区 + 1*elem_size
   └─ 无哈希、无锁、查找 O(1)；不能删除（中间挖不掉）

 HASH：桶数组 + 链表，key 任意
 buckets:  [0]→(elem)         [1]→(elem)→(elem)   [2]→ …
                 key=…,value        key=…,value
   └─ hash(key) 定桶，桶内链表比对 key；动态增删；桶锁保并发
      （内部实现在第 13 章逐行走读，本章记住行为差异即可）
```

行为差异对照（**这张表值得背下来**）：

| 维度 | ARRAY | HASH |
|---|---|---|
| key | u32 下标，必须 `< max_entries` | 任意字节串（结构体、整数…） |
| 创建时 | 一次性分配、**全部清零** | 分配桶表，元素按需进入 |
| lookup 查不到？ | 界内下标**永远"查到"**（值可能为 0） | 键不存在时真返回 NULL |
| 删除 | **不支持**（写零值覆盖模拟） | 支持，真删除 |
| 写满 | 不存在"满" | 超过 `max_entries` 报 **E2BIG** |
| 典型用途 | 固定桶计数、配置表、prog 数组 | 会话表、路由表、按 IP 统计 |

两个容易踩的推论：

- **array 的"零初始化"是语义的一部分**——第 2 章敢写
  `*cnt += 1` 而不初始化，正是因为 lookup 返回的格子天然是 0；
  同样的代码换到 hash 上，`lookup` 会先返回 NULL（键还不存在），
  必须走"先 update 插入"的分支；
- **hash 的 E2BIG 是设计而非故障**：`max_entries` 是资源承诺
  （预分配内存的依据），满了要么换 LRU（第 5 章），要么做淘汰。

## 4.3 动手：从固定桶到任意键——按源 IP 统计

第 2 章的计数器把协议号当 array 下标。现在需求升级：

> 统计**每个源 IP** 发来的包数——IP 是 40 亿种可能，固定桶爆炸，
> 而且活跃 IP 可能只有几百个。

这正是 hash 的主场（动态键、按需插入）。内核侧完整代码：

```c
// ipcount.bpf.c —— 按源 IP 统计（hash 版）
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);      // 源 IP（网络序原值，见 4.5）
    __type(value, __u64);     // 包数
    __uint(max_entries, 1024);// 活跃 IP 上限
} ip_cnt SEC(".maps");

SEC("xdp")
int count_by_ip(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __be32 src = iph->saddr;                 // 源 IP（网络序 4 字节）

    __u64 *cnt = bpf_map_lookup_elem(&ip_cnt, &src);
    if (cnt)
        *cnt += 1;                           // 已有：原地自增
    else {
        __u64 one = 1;
        bpf_map_update_elem(&ip_cnt, &src, &one, BPF_ANY); // 首见：插入
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

与第 2 章的关键差异只有一处：**lookup 必须处理 NULL**（首见的 IP
还没有键），走"插入初值"分支。`BPF_ANY` 表示"存在则覆盖、不存在
则插入"（另有 NOEXIST/EXIST 两种严格模式，排障时有用）。

Go 侧加载与第 2 章完全同构（换对象名即可），新东西是**怎么把整张
表读出来**——这引出迭代，也是 4.4 的收尾：

```go
// 每秒打印 Top：先收集全部 key，再逐个取值
type entry struct {
    ip   net.IP
    pkts uint64
}

func dumpTop(m *ebpf.Map, n int) {
    var entries []entry
    var key uint32          // __be32 的原值
    var val uint64
    iter := m.Iterate()
    for iter.Next(&key, &val) {
        b := make(net.IP, 4)
        binary.LittleEndian.PutUint32(b, key)  // 还原网络序字节（4.5）
        entries = append(entries, entry{b, val})
    }
    sort.Slice(entries, func(i, j int) bool { return entries[i].pkts > entries[j].pkts })
    for i := 0; i < n && i < len(entries); i++ {
        log.Printf("%-16s %d", entries[i].ip, entries[i].pkts)
    }
}
```

跑起来后 `curl` 几个不同站点，屏幕上就会看到按源 IP 排序的实时
榜单——**第一次体会到"任意键"带来的表达力**。

## 4.4 两侧 API 对照：同一张表的两种入口

同一张 map，两侧各有一套读写入口。对照表如下（左侧在内核热路径
执行，右侧是用户态系统调用）：

```
 内核侧 helper（C）                    用户态 API（Go, cilium/ebpf）
 ─────────────────────────────────────────────────────────────────
 bpf_map_lookup_elem(&m,&k)  ──对应──▶  m.Lookup(k, &v)
   返回 value 指针：可原地写！            返回 value 副本（拷贝进你的变量）
 bpf_map_update_elem(...,BPF_ANY) ──▶   m.Update(k, v, ebpf.UpdateAny)
 bpf_map_delete_elem(&m,&k)  ──对应──▶  m.Delete(k)
 （无对应：内核不迭代）          ◀──────  m.Iterate() / m.NextKey(k,&next)
 bpf_map_lookup_and_delete?  ──近似──▶  m.LookupAndDelete(k, &v)
```

**最要紧的语义差**：内核侧 lookup 拿到的是**指向内核内存的指针**
（`*cnt += 1` 是零拷贝的原地修改）；用户态 lookup 拿到的是**拷贝**
（你改的是自己这份副本，想写回去必须 Update）。一张图钉死：

```
                ┌────────────────────────┐
   内核侧 lookup │ key=1.2.3.4 → value:57 │  ← 用户态 lookup
        ┌───────┴────────────────────────┴───────┐
        │ ptr = &value(内核地址)                  │ copy = 57(你的栈上)
        │ *ptr += 1  ──▶ 内核里变成 58 ✅          │ copy += 1 ──▶ 栈上58，
        └────────────────────────────────────────┘   内核还是 57 ❌
                                                    （要生效须 m.Update）
```

**"取出即删"模式**：`LookupAndDelete`（读走的同时原子删除）是
**单向消息队列**的经典实现——内核写、用户取、取完即消，天然不重
不丢。ruport 的指令通道 `message_map` 正是这个模式：XDP 把指令
塞进 map，Go 控制面每秒 `LookupAndDelete` 取走处理（第 17 章 17.4
逐行分析）。什么时候用它、什么时候用普通表？一句话：**数据属于
"事件"就取出即删，数据属于"状态"就普通读写**。

## 4.5 数据对不上的那些坑：布局、对齐、字节序

跨边界共享结构体是 eBPF 工程中**症状最诡异**的一类 bug：程序对的、
逻辑对的，读出来的值却是乱的。三个来源逐一拆解，全部用 ruport 的
真实代码演示。

### 4.5.1 布局：pack 与不 pack 的 2 字节惨案

ruport 的跨边界消息结构（`bpf/common.h`）：

```c
#pragma pack(1)                    // ← 关键：按 1 字节对齐
struct Message {
    __be16 ins;                    // 偏移 0，2 字节
    __be32 cip;                    // 偏移 2 ←没有这行 pack，这里会是 4！
    __be16 cport;                  // 偏移 6
    __be16 connport;               // 偏移 8
    __be16 nativeport;             // 偏移 10
    unsigned char ext[100];        // 偏移 12，共 110 字节
};
```

C 编译器默认会把 4 字节的 `cip` 对齐到 4 的倍数（偏移 4），在
`ins` 后面塞 2 字节空洞。`#pragma pack(1)` 关掉对齐，字段紧凑排列。
**只要内核侧与用户侧有一边 pack、一边不 pack，所有字段就会错位**：

```
 pack(1)：  [ins 2B][cip 4B][cport 2B][connport 2B][native 2B][ext 100B] = 110B
 默认对齐： [ins 2B][洞2B][cip 4B][cport 2B][...]                        = 112B
                      ▲
              用户态按 110 读 → 从第 6 字节起全部错位 → "端口号像乱码"
```

**纪律**：跨边界结构一律 pack(1)（或两侧都显式写明填充字段）。

### 4.5.2 对齐：Go 结构体的"隐形填充"

就算 C 侧 pack 了，Go 侧手写结构体仍有陷阱——Go 编译器**自动**给
字段加对齐填充：

```go
type Message struct {
    Ins  uint16   // 偏移 0
    Cip  uint32   // Go 会把它放到偏移 4！中间垫 2 字节 ←与 pack(1) 的 C 侧不符
    ...
}
```

这就是为什么本仓库坚持用 bpf2go 的 `-type Message` **生成** Go 结构
（生成器读 BTF，精确复刻 packed 布局）。手写时的等价修法是显式
填充：`_ [2]byte "padding"`。判断有没有中招的黄金手段：

```
 排障三板斧（字节级对账）
 1) sudo bpftool map dump name xxx     ← 内核里的裸字节（终极真相）
 2) Go 侧 raw, _ := m.LookupBytes(k); log.Printf("% x", raw)
 3) 两串 hex 逐字节比对 → 对不上=布局问题；对得上但值"反着"=字节序
```

### 4.5.3 字节序：`__be` 字段的三步口诀

ruport 的 map 里存着网络字节序的 IP 和端口。小端机器上 Go 读出的
`uint32` 是"内存字节按小端解释"的结果——数值看起来是反的。ruport
的转换函数（`internal/control/control.go`）：

```go
// ntohs 等价：主机序数值 → 小端还原字节 → 大端解释
func toHostPort(port uint16) uint16 {
    var b [2]byte
    binary.LittleEndian.PutUint16(b[:], port)  // ① 按主机序(小端)还原成字节
    return binary.BigEndian.Uint16(b[:])       // ② 按字段的网络序语义读出
}

// __be32 → 点分字符串：内存字节本来就是网络序，直接拼 IP
func ip2str(ipv4 uint32) string {
    b := make(net.IP, 4)
    binary.LittleEndian.PutUint32(b, ipv4)     // 同样先还原字节
    return b.String()                          // net.IP 按大端输出点分
}
```

口诀：**主机序整数 →（LittleEndian）还原原始字节 →（按字段语义
BigEndian）重新解释**。而 4.3 动手节里 `binary.LittleEndian.PutUint32
(b, key)` 直接得到可读 IP，用的正是同一条推导。

一个反直觉但重要的推论：**算 map 的 key 不需要任何转换**。
ruport 内核侧 `key = (cip<<16) | cport`、Go 侧 `uint64(msg.Cip)<<16 |
uint64(msg.Cport)`——两边用的是"同一份原始字节解释出的同一数值"，
天然一致。字节序只影响"给人看"，不影响"用来匹配"。

## 4.6 小结与练习

**小结**：map 是内核↔用户态的共享裸字节容器；array（下标寻址/
零初始化/不可删）与 hash（任意键/动态/E2BIG）的分歧源自内存组织；
内核侧 lookup 拿指针可原地写、用户侧拿副本须回写；"取出即删"是
事件型数据的标准模式；跨边界结构体必须两侧布局一致（pack(1) +
生成/显式填充），字节序用三步口诀转换，排障靠字节级对账三板斧。

**练习**（基于 4.3 的 ipcount）：
1. 改成统计**目的 IP**（egress 方向没有 XDP，提示：改成在 TC
   egress 挂——如果还没学第 8 章，先用两个 key 的结构体
   `{src,dst}` 在现有 XDP 程序里统计）；
2. 把 `max_entries` 降到 4，用脚本灌 10 个不同源 IP，观察
   E2BIG 时 `bpf_map_update_elem` 的返回值（打印它！）——为
   第 5 章 LRU 做铺垫；
3. 制造一次布局 bug：把 Go 侧结构体故意去掉一个字段再读 map，
   用三板斧观察错位现象；
4. 思考题：为什么 `LookupAndDelete` 能保证"不重不丢"，而
   `Lookup` + `Delete` 两步不行？（提示：两步之间内核可能写入）

---

数据能出来了，但第 2 章埋的那个缺陷还在：多核机器上计数会丢。
下一章正面刚并发与规模。
