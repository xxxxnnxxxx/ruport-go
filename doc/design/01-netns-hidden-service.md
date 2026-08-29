# 设计文档 01：netns 隐藏服务架构（宿主侧连接隐藏）

> 状态：**已禁用（2026-08-30），代码保留**——见第 10 节。实现历经
> 门动态控制与清场语义两轮演进后功能完整，但因宿主转发依赖 iptables
> FORWARD 放行（Docker 等默认 DROP）且系统状态面偏大，经用户决定停用。
> 将 internal/control 的 NetnsDisabled 置 false 可恢复。
> 范围：仅 ruport-go；原 C 项目不改动
> 前置结论来源：2026-08-29 端口复用排障（校验和三连修、TC 挂载自愈），
> 详见 logs/log_20260829130340/144754/173029 系列

## 1. 背景与目标

### 1.1 现状

当前 TC 双向 L4 NAT（只改端口）方案实测可用，但连接四元组在宿主
内核 socket 表中以真实形态存在：

```
宿主 netstat -an：
tcp  0 0 172.16.17.33:22  172.16.76.86:3333  ESTABLISHED   ← 暴露点
```

### 1.2 目标

1. 宿主常规巡检（`netstat -an` / `ss -tn`）看不到隐藏连接；
2. 单程序交付：netns 创建/配置/服务拉起全部内嵌 ruport，无外部脚本、
   不依赖 `ip`/`ethtool` 命令行工具；
3. c3 敲门协议**零改动**；
4. 可回退：不带新参数启动时行为与现版本完全一致。

### 1.3 非目标（明确不做）

- 进程表隐藏（宿主 `ps` 仍可见服务进程）；
- 登录/审计日志隐藏（auth.log 照写）；
- 篡改 /proc/net/tcp 输出之类的内核级隐藏（rootkit 范畴，排除）。

## 2. 总体架构

```
                                              宿主 network namespace
 172.16.76.86(客户端)                        ┌──────────────────────────────┐
 │  nc -p 3333                        ens33 │  TC ingress: DNAT            │
 │     │  dst=172.16.17.33:80        ┌─────┴─────┐                        │
 ▼     ▼                              │           │   路由转发(ip_forward) │
════════════════════════════════════▶ │  dst IP→192.0.2.2                 │
        (网络上只见 :80 流量)          │  dst端口→22                      │
        (硬件防火墙只放行80)          └─────┬─────┘                        │
                                           │         veth0(192.0.2.1/24)  │
                                           ▼              │              │
                                     [内核路由]           │              │
                                           └──────┬───────┘              │
                                                  │                      │
 ┌────────────────────────────────────────────────┼──────────────────────┐
 │ netns: ruport_ns（独立协议栈）                ▼                      │
 │                                        veth1(192.0.2.2/24)            │
 │                                               │                      │
 │                                          sshd -D -p 22               │
 │                                        (由 ruport --exec 拉起)        │
 └───────────────────────────────────────────────────────────────────────┘

 回程（关键：宿主 socket 表无任何条目，纯转发不创建 socket）：
 sshd:22 → veth1 ─(TX卸载已关，软件校验和)→ veth0 → 路由 → ens33
   → TC egress: src IP 192.0.2.2→172.16.17.33, src端口 22→80
   → 客户端看到 172.16.17.33:80 ↔ 本机:3333
```

可见性对照（改前 → 改后）：

| 视角 | 现版本 | 本设计 |
|---|---|---|
| 网络观察者 | :80 流量 ✅ | :80 流量 ✅（不变） |
| 客户端 netstat | 连接显示 :80 ✅ | :80 ✅（不变） |
| **宿主 netstat/ss** | **真实 :22↔:3333 ❌** | **无条目 ✅** |
| netns 内 netstat | — | 真实四元组（需 `ip netns exec` 或 nsenter 查看） |
| 宿主 ps | sshd 可见 ❌ | 仍可见 ❌（非目标） |
| /var/log/auth.log | 记录 ❌ | 照记 ❌（非目标） |

## 3. 组件设计

### 3.1 netns 生命周期管理（纯 Go，无外部命令）

- 库：`vishvananda/netlink`（已依赖）+ `vishvananda/netns`（新增小依赖，
  netlink 的伴生库）；配置目标 ns 用 `netlink.NewHandleAt(ns)`，
  不切换当前线程即可操作 ns 内链路。
- 启动幂等流程：
  1. `netns.Get`/`netns.New`：已存在则复用，不存在则创建 named netns
     （`/var/run/netns/<name>`，机器重启后自动消失，启动重建）；
  2. veth 对不存在则创建：宿主侧 `veth0`（名字带前缀避免冲突），
     ns 侧 `veth1`，后者 `LinkSetNsFd` 移入 ns；
  3. 地址：veth0 = 网关地址（默认 `192.0.2.1/24`），veth1 = 服务地址
     （默认 `192.0.2.2/24`）；ns 内 lo up + 默认路由 via 网关；
  4. **关闭 veth 两端的 TX 校验和卸载**（原因见 3.5，实现走
     `ETHTOOL_SFEATURES` ioctl 的 Go 封装，不 exec ethtool）；
  5. `net.ipv4.ip_forward=1`（记录原值；见 5 风险）。
- 退出策略：SIGINT 清理时**不销毁** netns/服务（保持会话连续），
  下次启动幂等复用；`--ns-destroy` 参数提供手动彻底销毁。

### 3.2 隐藏服务拉起（--exec）

- 形如 `--exec "/usr/sbin/sshd -D -p 22"`；`-D` 必须前台运行，
  否则 spawn 后立即退出。
- 实现：`runtime.LockOSThread` → `netns.Set(ns)` → `cmd.Start()`
  （子进程继承线程当前 netns）→ 切回原 ns → 解锁；
- 生命周期与 ruport 绑定：ruport 退出前向服务进程发 SIGTERM；
  `--exec-detach` 可选分离；
- 不给 `--exec` 时 netns 照建（兼容用户自管服务的方式，但需手工
  `ip netns exec`，不推荐，见 1.2 目标 2）。

### 3.3 BPF 程序改造（bpf/ruport_tc.bpf.c）

- **协议零改动**：Message/Router 结构、敲门格式、c3 命令全部不变；
  netns 服务地址不走敲门下发，改为**运行时注入 config_map**（实施时
  对设计稿的调整：原计划用 `RewriteConstants` 重写 .rodata 常量，但
  bpf2go 生成的加载器不暴露 spec 层入口；改用 ARRAY 型 config_map
  （key 恒 0，value = {nativeip, hostip}），加载后 `Put` 注入即可，
  语义等价且与生成代码流完全兼容）：
  ```c
  struct Config { __be32 nativeip; __be32 hostip; };   // common.h
  ```
- tc_ingress（命中注册客户端时）：
  - 现状：仅 dst 端口→nativeport；
  - 新增：`NATIVE_IP != 0` 时 dst IP→NATIVE_IP（`bpf_skb_store_bytes` 4B
    + `bpf_l3_csum_replace` 修 IP 头校验和）+ dst 端口照旧；
    包随后按路由走向 veth0（纯转发，宿主无 socket）；
  - `NATIVE_IP == 0` 时行为与现版本完全一致（兼容/回退模式）。
- tc_egress（匹配条件细化）：
  - 现状：仅按目的=客户端匹配；改为 `src IP==NATIVE_IP && 目的==注册客户端`
    （避免误伤宿主上其他发往客户端的流量）；
  - 改写：src IP→HOST_IP（l3 修正）+ src 端口→connport（TCP 增量修正）；
  - `NATIVE_IP == 0` 时退化为现版本行为（仅端口改写、不碰校验和）。
- XDP 嗅探、message_map、用户态 control：零改动。

### 3.4 Go 侧参数与启动顺序

新增参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-N` | 关 | 启用 netns 隐藏模式（注入 NATIVE_IP） |
| `--ns-name` | ruport_ns | named netns 名 |
| `--ns-subnet` | 192.0.2.0/24 | ns 内网段（.1 网关/.2 服务） |
| `--exec` | 空 | ns 内拉起的服务命令（推荐 sshd -D） |
| `--exec-detach` | 关 | 服务不随 ruport 退出 |
| `--ns-destroy` | — | 销毁既有 netns/veth 后退出 |

启动顺序：解析参数 → netns/veth/特性/sysctl 就绪 →（拉服务）→
加载 BPF（注入 NATIVE_IP/HOST_IP）→ 挂 XDP/TC → 伺服循环。
HOST_IP 取所选网卡的第一个 IPv4 地址。

### 3.5 校验和处理矩阵（本设计最关键的正确性约束）

| 方向 | 包到达 hook 时的校验和状态 | 改写内容 | 处理 |
|---|---|---|---|
| ingress（客户端来） | 软件态（收包路径） | dst IP+端口 | IP 头 l3_csum_replace；TCP 增量修正（已在 08-29 排障实证） |
| egress（ns 回包） | **必须软件态**（依赖 3.1-4 关 veth TX 卸载保证） | src IP+端口 | IP 头 l3_csum_replace；TCP 增量修正 |

为什么必须关 veth 卸载：改 IP 必然动了 TCP 伪头，就必须修 TCP 校验和；
而 CHECKSUM_PARTIAL 的包修不了（BPF 读不到校验和状态，08-29 已实证
0x3A 恒偏问题，且 UAPI 无 csum_start）。关掉 veth TX 卸载后，ns 内
产生的包跨过 veth 时已被软件算好完整校验和（CHECKSUM_NONE），egress
的增量修正安全。此为 Cilium 对 veth 的同款处理。**若跳过此步，
该方案必然重演 0x3A 类故障。**

### 3.6 验证方案（实施完成后的验收清单）

1. 宿主：`netstat -an | grep 3333` 与 `ss -tn | grep :22` 均为空；
2. ns 内：`ip netns exec ruport_ns ss -tn` 可见真实四元组；
3. 客户端：敲门 → ssh 登录成功；客户端 tcpdump 全程 `(correct)` 校验和；
4. 回退验证：不带 `-N` 启动，行为与现版本一致（宿主 netstat 恢复可见）；
5. 重启机器后启动 ruport：netns 自动重建，功能恢复；
6. `kill`（SIGTERM）ruport 后再启动：TC 挂载自动顶替（已具备）。

## 4. 实施计划（每步日志 + 提交，Linux 编译验证由用户执行）

| 步骤 | 内容 | 交付 |
|---|---|---|
| S1 | BPF：NATIVE_IP/HOST_IP 常量 + ingress/egress 双模式改写 | bpf/ruport_tc.bpf.c |
| S2 | Go：netns/veth/ethtool-ioctl/sysctl 管理 | internal/netnsx（新包） |
| S3 | Go：参数、常量注入、--exec 服务拉起、启动顺序整合 | cmd/ruport/main.go |
| S4 | README/书稿（ch16/17 增补架构说明）+ 验收记录 | 文档 |

## 5. 风险与边界

- `ip_forward=1` 是全局 sysctl：若该服务器另有严格转发策略需评估
  （仅新增了到 192.0.2.0/24 的转发路径，不改变已有策略）；
- 若宿主 iptables FORWARD 链为 DROP（部分加固模板如此），转发到 ns 的
  包会被丢：需放行 `veth0 ↔ ns 网段`（实施时文档说明，不自动改防火墙）；
- 网段安全：默认 TEST-NET-1 保留段（真实网络不路由该段），Ensure 时对
  宿主现有地址/路由做重叠检测，冲突则自动回退备选（TEST-NET-2/3、
  172.31.255.0/24），全部冲突才报错退出（需 `--ns-subnet` 显式指定）；
  （2026-08-29 实测教训：旧默认 10.0.0.0/24 与现网重叠曾导致整机断网）；
- 宿主与 ns 各有一个 sshd 进程（ps 可见两个，端口不冲突，协议栈隔离）；
- ps / auth.log 痕迹仍在（非目标，见 1.3）；
- veth 关闭卸载对 ns 内流量吞吐有轻微影响（单连接 ssh 场景可忽略）。

## 6. 决策点（已确认 2026-08-29）

1. **退出策略**：默认保留 netns 与服务（named netns 持久，机器重启后
   自动消失、启动幂等重建）；`--ns-destroy` 手动彻底销毁。
2. **FORWARD 链**：只检测提示（启动时打印 hint），不自动改防火墙。
3. **服务生命周期**：默认绑定 ruport（退出即 SIGTERM 服务）；
   `--exec-detach` 可选分离。

## 7. 实施记录

| 步骤 | 提交 | 内容 |
|---|---|---|
| S1 | 0d9b9f1 | common.h Config 结构；TC config_map + ingress DNAT/egress 双模式；Makefile `-type Config` |
| S2 | 1bfa5f1 | internal/netnsx：named netns 创建（ip netns add 同款 bind mount 配方）、veth/地址/路由、ETHTOOL_SFEATURES ioctl 关闭 veth TX 卸载（纯 Go，无外部命令） |
| S3 | 351fd10 | cmd/ruport：-N/--ns-name/--ns-subnet/--exec/--exec-detach/--ns-destroy 参数、config_map 注入、服务生命周期、FORWARD 提示 |
| S4 | 本次 | 本文档状态更新与 config_map 实施说明、README 用法、书稿 16.5 延伸阅读 |

注：S1 的 BPF 改动与 Makefile 的 `-type Config` 需要 Linux 上 `make`
重新生成绑定后才能编译通过（internal/bpf 生成物不入库）。

## 8. 演进：敲门动态控制（2026-08-29 二次确认后实施）

用户提出更高灵活性的操作方式：ruport 启动时不做模式决定，先按普通
（01）路由连接确认情况，再通过敲门切换 netns 隐藏模式，之后还可对不同
服务用不同模式，全程不重启 ruport。实施要点：

1. **新指令 ins=0x05**（netns 隐藏路由）：帧格式/魔术数/结构零改动，
   服务命令复用空闲的 ext 段（≤100 字节）；c3 增加 `-5` 快捷方式，
   `-e` 传服务命令，`-y` 仍为 ns 内服务端口。旧 C 版 ruport 收到 05
   忽略（无副作用）。
2. **netns 标志从全局改按表项**：Router 结构 10B→18B，新增
   nativeip（0=普通路由）与 hostip；ingress/egress 据此逐表项分支，
   不同 源ip:port 的连接可同时各自处于普通/隐藏模式（S1 的全局
   config_map 退役删除）。
3. **控制面懒初始化**（internal/control）：收到 05 时才 Ensure netns
   （幂等）、按 ext 命令拉服务（同命令字符串去重复用）、解析宿主 IP
   填入表项。启动参数 -N/--exec 降级为"预热"语义（可选）。
4. **生命周期（用户确认）**：`-d` 删除路由不杀 ns 内服务（可复用秒连）；
   服务统一在 ruport 退出（ctl.Shutdown）或 --ns-destroy 时回收。
5. 操作注意：同一 源ip:port 已有表项时新敲门不生效，切换模式需先 `-d`
   删除或换源端口。

实施提交：bc80cc5（BPF 按表项）、55c27d9（控制面/c3/main 集成）、
本次（文档与日志）。

## 9. 演进二：清场语义（2026-08-29 三次确认后实施）

用户修正生命周期要求（推翻第 6 节决策 1/4 的"保留"语义）：

1. **ruport 退出即完整清场**：SIGTERM ns 内全部服务 → 拆除 veth/netns →
   恢复 Ensure 之前的 ip_forward（NS.OldForward 记录）。
2. **`-d` 删除路由触发条件清场**：删表项后扫描 router_map，若已无其他
   netns 表项（nativeip != 0，即不影响其他 源ip:port 的隐藏连接），
   同样完整清场；下一条 05 指令自动重建。
3. `--ns-destroy` 保留，仅用于异常残留处置（如 kill -9 后）；
   `--exec-detach` 的分离服务在清场后残留为无网络进程。

依据：TC filter 随 ruport 退出卸载、表项随进程消失，连接本来就会断——
"保留 ns"仅省服务重启的几百毫秒，清场语义基本无损失且状态更干净。

实施提交：05194dc（netnsx 恢复 ip_forward + NS.Destroy；control 清场
与删除扫描；main 帮助文本）。
