# 第三篇 · 网络即战场

> eBPF 的诞生地与主战场都在网络。本篇沿"一个包的一生"重走内核
> 网络栈：收包路径最早一刀的 XDP（第 7 章）、发包路径手术台 TC
> （第 8 章）、容器时代的 cgroup 与 socket 钩子（第 9 章）。
> ruport 的三大核心技术（嗅探、改写、复用）全部出自这一篇——
> 第 8 章结束时你实际上已经写出了它的雏形。

---

# 第 7 章 XDP：最早的那一刀

> XDP（eXpress Data Path）是 eBPF 网络能力的性能之巅：程序挂在
> **网卡驱动收包的第一站**，连内核的包描述符（skb）都还没分配。
> 本章先建立收包路径的全景地图（它同时是第 8、9 章的底图），
> 再动手写一个真正可用的迷你防火墙，最后看懂 XDP 的五种动作与
> 三种模式如何支撑起 DDoS 清洗与四层负载均衡这类生产系统。

## 7.1 收包的一生：第一张 hook 全景图

从网卡到应用，一个包要走过下面每一站。**★ 标出的位置都能挂
eBPF 程序**——这张图是网络篇的"作战地图"，值得反复回看：

```
 ① 网卡收到帧 → DMA 写入内存 → 硬中断
        │
 ② 驱动 NAPI 轮询批量取包
        │
        ├─★ XDP(native) ──────────── 全链路最早（skb 未创建）
        │     DROP 可在此完成：单核百万级 pps，防火墙圣位
        │     （驱动不支持时退到 generic：位置在③之后，功能相同）
        ▼
 ③ __netif_receive_skb —— 进入内核协议栈
        │
        ├─★ TC ingress(clsact) ──── 进协议栈前最后一站
        │     可改包/镜像/重定向（第 8 章主场）
        ▼
 ④ netfilter（iptables/nft 的 PREROUTING…，非 eBPF，对照参照）
        ▼
 ⑤ 路由判断：交给本机？还是转发？
        ▼
 ⑥ IP/TCP/UDP 层处理
        │   （这一路上的任意内核函数都能挂 kprobe/fentry，第四篇）
        ▼
 ⑦ cgroup ingress ★ ── 容器/进程组维度的过滤（第 9 章）
        ▼
 ⑧ socket 接收队列
        │   ├─★ SK_LOOKUP（选 socket）  ├─★ SOCK_OPS（连接事件）
        ▼
 ⑨ 应用 read() 拿到数据 ──★ SOCKET_FILTER（socket 级过滤）
```

三句话记住这张图：

1. **越往上越快**（早处理 = 早丢弃/早转出，后续全部成本归零）；
2. **越往下信息越全**（XDP 时只有裸包；socket 层连"属于哪个进程"
   都知道）；
3. **选钩子 = 在性能与信息量之间选位置**。ruport 的分工是教科书
   示例：嗅探用 XDP（最早看到指令包）、改写用 TC（需要 skb 的
   改包 helper）、决策在用户态（信息最全）。

## 7.2 XDP 是怎么来的：驱动层的可编程性

第 1 章提过 2016 年 XDP 随 4.8 进主线。它回答的问题是：
**iptables 丢包为什么还是不够快？**——因为包已经走完中断、分配了
skb、进了协议栈，才在 netfilter 钩子被丢，"丢弃"本身也要付全程
路费。XDP 把执行点搬到驱动轮询循环里：**在 skb 分配之前**跑你的
程序，返回 DROP 则包直接在内存里被丢弃——理论上只花了一次 DMA
和一次函数调用的钱。

```
                    丢同一个包的成本对比
  ┌──────────────────────────────────────────────────┐
  │ iptables INPUT 链丢弃：中断+skb分配+协议栈爬升+   │
  │                        netfilter匹配 ≈ 全程成本    │
  │ XDP native 丢弃：    中断+NAPI+一次BPF调用 ≈≈≈ 0  │
  └──────────────────────────────────────────────────┘
```

代价是上下文极简：XDP 程序只能看到 `xdp_md`（包首尾指针 + 网卡
元信息），**没有 skb 那些丰富的字段与改包 helper**——所以 XDP
适合"尽早决策"，不适合"精细手术"（那是 TC 的事）。

## 7.3 动手：一个能用的迷你防火墙

需求：**黑名单 IP 一律丢弃，其余放行；黑名单可随时从用户态增删**。
这个"程序+控制面"的结构就是生产防火墙的骨架。

### 7.3.1 C 侧

```c
// fw.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);   // 黑名单可动态增删；
    __type(key, __be32);                   // 规模不可控 → LRU 防爆
    __type(value, __u8);                   // 值无意义，占位
    __uint(max_entries, 4096);
} blacklist SEC(".maps");

SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 第 3 章三模式之一：定长头逐层证明
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // 黑名单命中即丢（key 用网络序原值——第 4 章的"匹配不需要转序"）
    __u8 *hit = bpf_map_lookup_elem(&blacklist, &iph->saddr);
    if (hit)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### 7.3.2 Go 侧：加载 + 挂载 + 规则下发

加载挂载与第 2 章同构（`link.AttachXDP` + generic 模式），新东西
是**运行时改 map**：

```go
// 拉黑一个 IP（命令行或 API 触发）
func block(m *ebpf.Map, ip string) error {
    key := binary.BigEndian.Uint32(net.ParseIP(ip).To4()) // 网络序原值
    return m.Update(key, uint8(1), ebpf.UpdateAny)
}

// 解除拉黑
func unblock(m *ebpf.Map, ip string) error {
    key := binary.BigEndian.Uint32(net.ParseIP(ip).To4())
    return m.Delete(key)
}
```

### 7.3.3 验证

```bash
go run . &
curl -s --max-time 2 https://正常站点     # 通
block 93.184.216.34                       # 拉黑 example.com
curl -s --max-time 2 https://example.com  # 超时（包在驱动层消失）
sudo bpftool map dump name blacklist      # 规则在内核里
```

注意"包在驱动层消失"的含义：**tcpdump 都看不到它**（抓包点在
XDP 之后）——排障时这是特征而非 bug（第 15 章 15.3 的对照表）。

## 7.4 五种动作、三种模式

### 7.4.1 返回值即决策

XDP 程序的返回值直接决定包的命运：

| 动作 | 语义 | 典型用途 |
|---|---|---|
| `XDP_DROP` | 就地丢弃 | 防火墙/DDoS 清洗（本章） |
| `XDP_PASS` | 继续正常协议栈路径 | 默认/白名单 |
| `XDP_TX` | 从**同一网卡**弹回去 | 轻量应答（如 SYN cookie） |
| `XDP_REDIRECT` | 转到**其他网卡/CPU/socket** | 负载均衡/分流（7.5） |
| `XDP_ABORTED` | 异常中止（带 tracepoint） | 程序自身 bug 的显式信号，别当正常返回用 |

### 7.4.2 三种挂载模式

| 模式 | cilium 标志 | 位置 | 支持与性能 |
|---|---|---|---|
| native（驱动） | `XDPDriverMode` | 驱动内 | 需驱动支持（主流物理网卡/veth 4.19+ 都支持）；最快 |
| generic（SKB） | `XDPGenericMode` | 协议栈入口 | **所有网卡**；本书示例全用它 |
| hardware | （库暂不直接暴露） | 网卡固件 | 少数 SmartNIC；指令子集受限 |

选型：**generic 起步（保证能跑），性能不够换 native（同一段 C
代码不用改，只换挂载标志）**。云上虚拟网卡建议先探测：
`ethtool -i eth0 | grep xdp` 或直接试 native 模式看报错。

## 7.5 更进一步：redirect/devmap 与四层负载均衡一瞥

`XDP_DROP` 是"挡"，`XDP_REDIRECT` 是"转"——生产级四层负载均衡
（Facebook Katran、Cloudflare 边缘）的核心就是它：

```
 XDP 负载均衡骨架（示意图）
                     ┌──────────────────────────┐
   客户端包 ─────▶  │ XDP 程序（每包）：          │
   dst=VIP:443      │  后端 = hash(四元组)查表    │
                     │  return bpf_redirect_map(  │
                     │      &backend_map, idx, 0) │
                     └────────────┬─────────────┘
                                  ▼ XDP_REDIRECT（包几乎原样转出）
                    ┌──────────────┬──────────────┐
                    ▼              ▼              ▼
                 后端1网卡      后端2网卡       后端3网卡
        backend_map: DEVMAP 类型，key=索引, value=出网卡（可含改 MAC 的程序）
```

两个新概念点到为止（附录 B/C 有速查）：

- **DEVMAP**：存"转发出口"的专用 map（XDP 执行太早，不能直接引用
  网卡对象）；`bpf_redirect_map` 一步完成查表+转发；
- **CPUMAP**：把包**重定向到指定 CPU** 再走协议栈——RX 队列不均
  时的调优利器。

Go 侧挂载与本章完全一致，差别只在 C 程序的返回动作——**XDP 的
编程模型就是"每包一次纯函数 + 返回动作码"**，简单到配得上它的
速度。

## 7.6 小结与练习

**小结**：收包地图三定律（越早越快/越晚信息越全/选位=权衡）；
XDP = skb 分配前的驱动层钩子，天然适合尽早决策；返回值五动作
（挡/过/弹/转/崩）；三种模式 generic 保底、native 提速、代码不改
只换标志；黑名单防火墙的"程序+map 控制面"结构可直通生产；
REDIRECT+DEVMAP 是四层 LB 的骨架。

**练习**：
1. 给迷你防火墙加**白名单模式**：map 里 value=1 表示丢弃、2 表示
   放行（其余默认丢弃）——体会"map 即策略"的设计；
2. 改成按 `(源IP, 目的端口)` 二元组拉黑（提示：key 换 packed
   结构体，第 4 章的布局纪律）；
3. 把挂载从 generic 换成 native（`XDPDriverMode`），在你机器上
   观察 `ip link` 的 xdp 标记变化；若失败，读懂报错判断网卡支持性；
4. 思考题：为什么 XDP 程序里没有 `bpf_skb_store_bytes` 这类改包
   helper？（从 7.2 的"上下文极简"推演——改包的活儿留给谁？）

---

收包路径最早的一刀已经下完。下一章走到路径的另一头——出向的
手术台 TC，在那里我们第一次**修改**数据包。
