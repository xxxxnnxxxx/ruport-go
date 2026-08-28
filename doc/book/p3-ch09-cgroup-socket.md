# 第 9 章 cgroup 与 socket：容器时代的钩子

> 前两章的钩子都挂在"包"上——同一台机器所有流量一视同仁。但
> 云原生时代的基本单位是**容器/进程组**：安全策略要按"哪个
> 容器"放行或拒绝，调优要按"哪类连接"进行。cgroup BPF 家族把
> 钩子挂到了"进程组"维度，socket 家族则钻进了连接生命周期内部。
> 本章补齐网络篇地图的最后两块，ruport 虽未使用它们，但读懂后
> 你就能看懂 Cilium 的 NetworkPolicy 是怎么实现的。

## 9.1 cgroup BPF 的调用栈与家族语义

### 9.1.1 一个 socket 的"组织关系"

理解 cgroup BPF 的钥匙是一句话：**每个 socket 在创建时就记住了
自己属于哪个 cgroup**，之后所有挂钩点都靠这个归属找到"该跑哪些
程序"：

```
 socket 创建（sk_alloc）
   └─ 初始化 sk->sk_cgrp_data = 当前进程所在 cgroup v2
        │
        ▼ 后续每个事件点都执行同样的三步：
 ┌────────────────────────────────────────────────┐
 │ ① 取 socket 的 cgroup                           │
 │ ② 找 cgrp->bpf.effective[attach_type] 程序数组  │
 │    （含所有祖先 cgroup 的有效程序，按序执行）      │
 │ ③ 跑程序 → 返回 1 放行 / 其他值 = -EPERM（拒绝） │
 └────────────────────────────────────────────────┘
```

**返回值语义与 XDP/TC 完全不同**：这里只有"1=允许、其他=拒绝"
两种（安全策略语义），没有 REDIRECT/DROP 那种丰富动作。

### 9.1.2 家族速览

按挂的事件点分（完整表见附录 A，此处只讲三个代表）：

| attach 类型 | 触发时机 | 典型用途 |
|---|---|---|
| `INET_INGRESS/EGRESS` | 包进入/离开**该 cgroup 的 socket** | 容器级包过滤（9.3 动手） |
| `INET_SOCK_CREATE` | socket 创建时 | 按容器禁止某类 socket（如禁 raw） |
| `INET4_CONNECT` 等 | connect/bind 时 | **地址改写**（透明代理、Service 转发的基础！） |

第三个值得多看一眼：`CONNECT` 钩子能**修改** connect 目标——
Cilium 把 Pod 到 Service 的连接改写到真实后端，用的正是它。
这印证了第 7 章地图的三定律：**越靠近应用，语义越贴近"意图"**
（包级钩子改的是字节，连接级钩子改的是"去哪"）。

## 9.2 socket 家族能做什么

socket 家族程序挂进**连接生命周期内部**，两类代表：

**SOCK_OPS（4.13+）**——连接事件回调。程序按 `ctx->op` 区分事件
（建连完成/RTO 超时/重传/状态迁移…），既能观测也能**按连接调参**
（返回值即建议值，如自定义初始 RTO）：

```
 一个连接的一生 × SOCK_OPS
 connect() ──▶ TCP_CONNECT_CB ──▶ ACTIVE_ESTABLISHED_CB
                                                    │
        数据传输期：RTO_CB / RETRANS_CB（超时/重传事件）
                                                    │
 close() ◀─── STATE_CB（状态迁移）◀────────────────┘
```

**sockmap/SK_SKB/SK_MSG（4.14/4.17+）**——同机通信加速。两条程序
配合一条 SOCKMAP：SOCK_OPS 程序在建连时把 socket 存入 map；SK_MSG
程序在 sendmsg 路径查 map 找到**对端 socket**，`bpf_msg_redirect_hash`
直接投递——绕过整段协议栈：

```
 普通同机路径：App A → TCP/IP 整套 → 环回 → TCP/IP 整套 → App B
 sockmap 路径：App A → sendmsg → [SK_MSG 查表] ──────▶ App B 收缓冲
                                          （协议栈被短路）
```

**SK_LOOKUP（5.9+）**：入向 socket 选择——reuseport 场景按任意
逻辑（含查 map 的策略）决定包交给哪个监听 socket。

这些家族 ruport 用不上，但它们是"地图完整度"的必要拼图：现在回看
第 7/8 章的两张路径图，每一站你都能叫出钩子名字了。

## 9.3 动手：容器级放行/拒绝

做一个最小但真实的安全策略：**禁止本 cgroup 下的进程访问某个
外部 IP**（模拟 NetworkPolicy 的 Egress DENY）。

C 侧（CGROUP_SKB，attach 到 EGRESS）：

```c
// cgblock.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("cgroup_skb/egress")
int block_egress(struct __sk_buff *skb)
{
    // __sk_buff 里直接可用网络头字段（验证器转译）：
    // 注意 CGROUP_SKB 上下文的包指针语义：字段访问经由 ctx
    bpf_skb_pull_data(skb, 0);            // 确保头可读（细节略）
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *iph = data + 14;        // 以太头后
    if ((void *)(iph + 1) > data_end)
        return 1;                         // 看不清就放行（fail-open 示例）

    __be32 bad = iph->daddr;
    __u32 blocked = 0x2200A8C0;           // 192.168.0.34 的网络序原值示例
    if (bad == blocked)
        return 0;                         // ★ 0 = 拒绝（丢弃）
    return 1;                             // 1 = 放行
}

char _license[] SEC("license") = "GPL";
```

Go 侧挂载到 cgroup v2（cilium 的 cgroup attach）：

```go
// 挂到当前 cgroup（生产中挂到容器所在 cgroup 或根）
cgPath := "/sys/fs/cgroup"               // cgroup v2 挂载点
cgFD, err := os.Open(cgPath)
if err != nil { log.Fatal(err) }
defer cgFD.Close()

lk, err := link.AttachCgroup(link.CgroupOptions{
    Path:    cgPath,
    Attach:  ebpf.AttachCGroupInetEgress,
    Program: objs.BlockEgress,
})
if err != nil { log.Fatal(err) }
defer lk.Close()          // cgroup 挂载是 link 化的：进程退出自动摘除
```

验证：

```bash
ping -c1 192.168.0.34    # 100% loss（egress 包被 CGROUP_SKB 丢弃）
ping -c1 192.168.0.1     # 正常
```

三个工程要点：

1. **挂载点即策略范围**：挂容器 cgroup=单容器策略，挂根=全机策略
   （顺序与优先级按 cgroup 层级合并，effective 数组就是合并结果）；
2. **fail-open 还是 fail-close**：示例里"看不清就放行"——真实
   安全策略通常反过来（看不清就拒绝），这是个**策略声明**而非
   技术约束；
3. **cgroup 挂载是 link 化的**（与 tc filter 的残留特性相反），
   清理责任模型见第 14 章的责任矩阵。

## 9.4 小结

**小结**：cgroup BPF 的机制=socket 创建时记录归属+事件点查
effective 程序数组+返回 1/0 定放行拒绝；家族覆盖包过滤/创建控制/
连接改写（透明代理基石）；socket 家族深入连接内部（SOCK_OPS 事件
与调参、sockmap 短路同机通信、SK_LOOKUP 选 socket）。至此网络篇
地图集齐：XDP（最早一刀）→ TC（双向手术台）→ cgroup（进程组
策略）→ socket（连接内部），ruport 用到的正是前两个。

**练习**：
1. 把 9.3 从"拒绝一个 IP"改成"map 驱动的黑名单"（复用第 7 章
   firewall 的 blacklist 结构）——观察两种钩子（XDP vs CGROUP_SKB）
   下，同一份 map 与几乎同一份 C 逻辑如何复用；
2. 思考题：同样的"按源 IP 拉黑"，挂在 XDP 和挂在 cgroup egress
   有什么语义差别？（提示：cgroup 看到的是"本组 socket 发出的
   包"，且位置在协议栈尾部——对照第 7 章地图标注两站的位置）；
3. 探索题：`cat /sys/fs/cgroup/cgroup.controllers` 确认你的系统是
   cgroup v2，找出现有系统（如 systemd）已挂了哪些 cgroup BPF：
   `bpftool cgroup tree /sys/fs/cgroup`。

---

网络篇完结。第四篇换一个视角——不再改包，而是**看见一切**：
观测的艺术。
