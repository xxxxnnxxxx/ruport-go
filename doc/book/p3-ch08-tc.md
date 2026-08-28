# 第 8 章 TC：包的手术台

> XDP 快但"手短"——没有改包的 helper。当需求变成"改写端口、
> 封装隧道、镜像流量"，主战场就移到 TC（Traffic Control）。本章
> 先看发包路径的全景图与 clsact 的由来，然后完成本章主实验：
> **端口改写 + 增量校验和**（ruport 的核心技术），并把单向改写
> 扩展成双向的"端口复用"雏形。Go 侧将首次引入 netlink 挂载——
> 这是全书与 ruport main.go 最接近的一章。

## 8.1 发包的一生：第二张全景图

```
 ① 应用 write()/send()
        │
 ② socket 层（TCP 段生成、拥塞控制）
        │   ├─★ SOCK_OPS（连接级事件/调参，第 9 章）
        │   └─★ cgroup egress（容器级放行，第 9 章）
        ▼
 ③ IP 层：选路由、netfilter OUTPUT/POSTROUTING（iptables 对照）
        ▼
 ④ __dev_queue_xmit（进入设备发送队列前）
        │
        ├─★ TC egress(clsact) ──── 发包方向最后一站、可改包
        │     ★ 本章 8.3 的用武之地（ruport 回包源端口改写处）
        ▼
 ⑤ qdisc 排队 → 驱动 → 网卡发出
```

对照第 7 章收包图：TC 是**唯一**一个"ingress 与 egress 双向都有、
且两个方向都持 skb（可改包）"的钩子——"手术台"之名由此而来。

## 8.2 从流量分类器到 clsact

TC 子系统的祖先是 QoS：树形的 `qdisc（排队规则）→ class（类别）→
filter（分类器）`，BPF 最初只能作为众多 filter 之一（`SCHED_CLS`
程序类型，4.1）。给 BPF 用的标准姿势是 **clsact**（4.5+）：一个
专用 qdisc，没有 class、不做排队，只为 BPF 提供 ingress/egress
两个挂点：

```
 clsact qdisc（handle ffff:0000）
 ┌─────────────────────────────────────────────┐
 │  ingress（parent ffff:fff2）  egress（fff3）  │
 │   ├ filter #1 (prio 1)         ├ filter #1   │
 │   │  └─ BPF 程序 A             │  └─ BPF 程序 B│
 │   └ filter #2 (prio 2)…        └ …           │
 └─────────────────────────────────────────────┘
   挂载结构 = qdisc + filter（priority 定执行序，handle 定身份）
```

**tc 程序的返回值**沿用 filter 语义：`TC_ACT_OK`（继续正常处理）、
`TC_ACT_SHOT`（丢弃）、`TC_ACT_REDIRECT`（重定向）等。本章程序
都返回 `TC_ACT_OK`——"改完放行"，即旁路观察+手术模式。

## 8.3 动手：端口改写（DNAT）与增量校验和

### 8.3.1 需求与方案

> 外部访问 `本机:8080`，把它改写成 `本机:80`——本机 80 端口的
> 服务"以为"自己监听在 8080；客户端完全无感。

```
 客户端 ── dst=8080 ──▶ [TC ingress: 8080→80] ──▶ 80 端口服务
 服务   ── src=80  ──▶ [TC egress:  80→8080] ──▶ 客户端看到 8080
        （8.4 完成闭环；8.3 先做 ingress 半边）
```

### 8.3.2 C 侧：改写与校验和的"手术三步"

```c
// portmap.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <stddef.h>

#define FAKE_PORT 8080   // 对外（伪装）端口
#define REAL_PORT 80     // 本地服务真实端口

SEC("tc")   // ingress 方向（挂载时决定方向，程序本身不感知）
int tc_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 与 XDP 同款的边界检查（ctx 换成 __sk_buff）
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    struct tcphdr *tcph = (void *)iph + 20;      // 固定 20B IP 头
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    if (tcph->dest == bpf_htons(FAKE_PORT)) {
        __be16 real = bpf_htons(REAL_PORT);

        // ★ 手术三步：算差值 → 写新值 → 修校验和
        __wsum diff = bpf_csum_diff(&tcph->dest, 2, &real, 2, 0);
        bpf_skb_store_bytes(skb, (long)((void *)tcph - data)
                                 + offsetof(struct tcphdr, dest),
                            &real, 2, 0);
        bpf_l4_csum_replace(skb, (long)((void *)tcph - data)
                                 + offsetof(struct tcphdr, check),
                            0, diff, BPF_F_PSEUDO_HDR);
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
```

四个要点讲透：

**① `__sk_buff` 是 skb 的"安全视图"**：验证器把它翻译成对真实
skb 字段的访问（第 9 章对照 cgroup 时再展开）。TC 程序能用的
helper 家族比 XDP 富裕得多——`bpf_skb_store_bytes`（改包）、
`bpf_l4_csum_replace`（修校验和）都只在 TC/cgroup 侧可用。

**② 改包必须用 helper，不能直接写内存**：`bpf_skb_store_bytes`
负责把新字节写进包并处理 skb 内部簿记（长度、线性区等）——
直接 `tcph->dest = real` 验证器直接拒绝（数据包指针只读）。

**③ 增量校验和的数学**（ruport 同款，值得完全理解）：TCP 校验和
覆盖"伪头（含 IP）+ TCP 段"。全量重算太贵，标准做法是增量更新：

```
 new_sum = old_sum + ~old_field + new_field     （16位反码和域内）
 bpf_csum_diff(from, from_len, to, to_len, seed)
   返回的正是 ~from + to 的累加值（seed 可链式累加）
 BPF_F_PSEUDO_HDR：告知本次改动经由伪头影响校验和（端口字段在
   伪头参与项? 否——伪头含 IP 地址；端口不涉及伪头，但 TCP 校验和
   的 update flag 按内核约定照此传递，ruport 与内核 samples 同款写法）
```

改的是 2 字节端口，但 `bpf_csum_diff` 传 4 字节宽（值等同）——
反码和下低 16 位等价，这是内核示例约定俗成的写法。

**④ IP 头校验和不用管**：我们没改 IP 头任何字段。

### 8.3.3 Go 侧：netlink 挂载（clsact + filter）

cilium/ebpf 不提供经典 clsact 挂载（tcx 是 6.6+ 的新路，8.5 对比），
标准做法用 `vishvananda/netlink`：

```go
//go:build linux

package main

import (
	"errors"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type tcAttach struct {
	filters []*netlink.BpfFilter
	clsact  *netlink.Clsact
}

// attachTC：创建 clsact qdisc（已存在则复用），挂一个方向的 filter
// 完整双向版本见 8.4；priority=1、handle 0:1 与 ruport 一致
func attachTC(ifindex int, parent uint32, prog *ebpf.Program) (*tcAttach, error) {
	clsact := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),  // ffff:0000
			Parent:    netlink.HANDLE_CLSACT,          // ffff:fff1
		},
	}
	if err := netlink.QdiscAdd(clsact); err != nil &&
		!errors.Is(err, syscall.EEXIST) {           // 已存在=复用
		return nil, err
	}

	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    parent,                        // EGRESS/INGRESS
			Handle:    netlink.MakeHandle(0, 1),      // 0:1
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,                // 匹配所有协议
		},
		Fd: prog.FD(),                                 // ★ 程序经 FD 关联
	}
	if err := netlink.FilterAdd(f); err != nil {
		return nil, err
	}
	return &tcAttach{filters: []*netlink.BpfFilter{f}, clsact: clsact}, nil
}

// release：卸载 filter 与 qdisc —— 顺序不可反！
func (t *tcAttach) release() {
	for _, f := range t.filters {
		_ = netlink.FilterDel(f)
	}
	_ = netlink.QdiscDel(t.clsact)
}
```

**必须刻在脑子里的生命周期差异**（第 2 章 2.6 埋的雷在此引爆）：
经典 tc filter **引用程序**——进程退出后 filter 依然挂着、改写规则
继续生效！所以 `release()` 是路径而不是礼貌：main 里要挂信号处理
（`signal.Notify` → release → `objs.Close()`，顺序如上，先删 filter
再关程序 FD）。**崩溃残留**（kill -9）的清法与自查见第 15 章。

### 8.3.4 运行验证

```bash
# 只监听 80 的服务
sudo python3 -m http.server 80 &
go run .                     # 加载 + ingress 挂载
sudo tc filter show dev eth0 ingress   # 应看到 bpf ... prio 1

curl -v http://<本机IP>:8080/          # ← 8080！能通=改写生效
# 对照：停掉程序（走 release），curl :8080 立刻失败、:80 正常
```

## 8.4 双向改写：端口复用的雏形

只有 ingress 改写时，回包源端口是 80——客户端内核会当作"非法
应答"丢弃（它只认识 8080 的连接）。闭环必须补上 egress 的源端口
改回：

```c
SEC("tc")   // egress：把来自 80 的回包源端口改回 8080
int tc_egress(struct __sk_buff *skb)
{
    // ……（同款边界检查，略）
    if (tcph->source == bpf_htons(REAL_PORT)) {
        __be16 fake = bpf_htons(FAKE_PORT);
        __wsum diff = bpf_csum_diff(&tcph->source, 2, &fake, 2, 0);
        bpf_skb_store_bytes(skb, off + offsetof(struct tcphdr, source),
                            &fake, 2, 0);
        bpf_l4_csum_replace(skb, off + offsetof(struct tcphdr, check),
                            0, diff, BPF_F_PSEUDO_HDR);
    }
    return TC_ACT_OK;
}
```

两个方向合成一张图——**这就是端口复用的全部原理**：

```
                对外只有 8080，内部真实服务在 80
 客户端 ◀──────────────────────────────────────▶ 本机
    │  dst=8080                        ▲
    │           ┌──────────────────────┤
    ▼           │  TC ingress: dst→80  │
   发出 ──────▶ │  [80端口服务收到"发给自己"的包] │
   收到 ◀────── │  服务回包 src=80      │
    ▲           │  TC egress:  src→8080│
    │  src=8080（闭环！）               │
    └──────────────────────────────────┘
```

**从雏形到 ruport 只差两步**（第 16 章推演、17 章逐行）：
1. 固定端口对（8080↔80）换成**查路由表决定改写目标**——谁的包
   改到哪，由 `router_map` 说了算；
2. 两端端口未知时的**端口学习**（connport/nativeport 自动补全）。

## 8.5 经典 clsact 与 tcx 的抉择

6.6 起内核提供 tcx：link 化的 TC 挂载（`link.AttachTCX`）。对比：

| 维度 | clsact+filter（本章） | tcx（6.6+） |
|---|---|---|
| 多程序 | priority 排序的 filter 列表 | 自动成链、锚点可控 |
| 生命周期 | **filter 持程序引用，需手动清理** | link 语义，进程退出自动卸载 |
| 挂载 API | netlink（本章 Go 代码） | cilium `link.AttachTCX` |
| 兼容 | 4.5+，几乎所有在役内核 | 仅新内核 |

选型：**兼容优先选 clsact（ruport 的选择，对齐老内核）；纯新
环境可上 tcx 免去清理责任**。写法上只需替换挂载层，C 程序不变。

## 8.6 小结与练习

**小结**：TC 是唯一双向可改包的钩子；clsact 是 BPF 专用 qdisc
（ingress/egress 两个挂点，priority/handle 组织 filter）；改包
手术三步= csum_diff 算差值 → store_bytes 写入 → l4_csum_replace
修正（增量校验和：`new = old + ~old_field + new_field`）；Go 侧
netlink 创建 clsact+filter，**filter 残留特性决定必须显式清理**；
双向改写 = 端口复用原理，ruport= 加路由表与端口学习的完整版。

**练习**：
1. 完成 egress 侧的 Go 挂载（8.3.3 的 attachTC 传
   `netlink.HANDLE_MIN_EGRESS`），验证 8080 全双工闭环；
2. 把固定端口对改成 map 驱动：`map<fake_port, real_port>`，用户态
   可动态增删映射——你已经写出了 ruport router_map 的前半生；
3. 实验 filter 残留：加载后 `kill -9`（跳过 release），用
   `tc filter show` 确认 filter 还在、curl 仍被改写；再用
   `tc qdisc del dev eth0 clsact` 清理——记住这个手感；
4. 思考题：为什么 ingress 改写后不需要改 IP 头校验和，而如果
   改的是源/目的 IP 就需要动两处校验和？（IP 头校验和 + TCP 伪头
   参与的 L4 校验和——从 8.3.2 的③推演）

---

网络栈的收发两个方向都下过刀了。下一章补齐最后一块地图：容器
时代的 cgroup 与 socket 钩子。
