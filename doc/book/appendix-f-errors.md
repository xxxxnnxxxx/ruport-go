# 附录 F · 常见报错字典

> 按"报错关键词 → 根因 → 修法"组织；括号内为详解章节。加载期
> 报错先读 verifier 日志（第 3 章），本字典负责"翻译"。

## 加载期（verifier / 权限）

| 报错关键词 | 根因 | 修法 |
|---|---|---|
| `invalid access to packet, off X size Y, R?(r=Z)` | 读取超出已证明窗口 | 补紧邻边界检查（3.5 三模式） |
| `invalid read from stack` / `!read_ok` | 读未初始化 | `= {}` 初始化（3.1） |
| `loop detected` / `back-edge` | 循环上界不可证 | 常量上界或 clamp 输入（3.1） |
| `invalid mem access 'inv'` | 拿数字当指针 | 值须来自 ctx/map/helper（3.6） |
| `R0 leaks addr` | 指针外泄 | 传 ID/index（3.6） |
| `helper call not allowed` / 类型不符 | 白名单限制 | 查 bpf_helper_defs.h（附录C） |
| `cannot call GPL-only function...` | license 不符 | 声明 GPL（附录A） |
| `map .rodata: ... requires >= v5.2` | printk 宏用了全局区 | 升内核或裸 bpf_trace_printk（15.4） |
| `BPF program is too large / complexity limit` | 指令/状态爆炸 | 拆尾调用、简化分支（3.3） |
| load 返回 EPERM 且无日志 | 权限/配置 | root 或 CAP_BPF；unprivileged_bpf_disabled；<5.11 调 RemoveMemlock（15.1） |
| `can't marshal key: offset N` | Go 结构体≠KeySize | 布局对齐/用 -type 生成（4.5） |

## 挂载期

| 报错关键词 | 根因 | 修法 |
|---|---|---|
| netlink `file exists`（QdiscAdd） | clsact 已在 | 忽略 EEXIST（8.3.3） |
| netlink `file exists`（FilterAdd） | handle/prio 冲突（多为残留） | 删旧或启动清残留（8.6/14.4） |
| XDP `not supported` | 驱动无 native | XDPGenericMode（7.4.2） |
| XDP `device busy` | 旧程序占用/模式冲突 | `ip link set dev x xdp off` |
| tcx/netfilter `not supported` | 内核过老 | 退经典 clsact（8.5） |
| tracepoint `no such file` | 组/名拼错 | 对照 tracing/events 目录（10.2） |
| kprobe `symbol not found` | 内联/改名 | kallsyms 核对；fentry 或相邻函数（10.3） |
| fentry 报 BTF 相关 | <5.5 或无 BTF | ls vmlinux；退 kprobe（11.2） |

## 运行期

| 症状 | 根因 | 修法 |
|---|---|---|
| map 里有值但 Go 读不到/读错 | 布局或字节序 | 三板斧字节对账（4.5） |
| 端口/IP 显示"反了" | 网络序未转换 | 三步口诀（4.5.3） |
| 计数偏小 | 并发竞争 | 原子或 perCPU（5.1） |
| 插入失败 E2BIG | 表满 | LRU/容量公式（5.2） |
| 迭代漏键/重键 | 游标非快照 | 先收集 key 再处理（5.3.1） |
| ringbuf 丢事件/乱包 | 容量不足/消费慢 | 容量预算+Remaining+消费纪律（6.3） |
| kretprobe 高并发丢事件 | MaxActive 耗尽 | 调大或 fexit（10.4.1） |
| 程序退出后改写仍在 | tc filter 残留 | 显式清理+清残留（8.3.3/14.4） |
| `undefined: loadXxxObjects` / redeclared | bpf2go ident 大小写误判 | 大写 ident 生成导出 API，直接调（14.3.2） |
| bpf2go `missing package...` | go run 直调无 GOPACKAGE | 加 `-go-package`（14.3.2） |
| clang `linux/bpf.h not found` | BPF 目标不含系统头路径 | `-idirafter` 推导（14.3.2） |
| `-Wunused-variable` 报错 | -Werror+死变量 | 删除死代码（14.3.2） |

## Go / cilium 特有

| 报错 | 根因 | 修法 |
|---|---|---|
| `no Go files` / `undefined: bpf.Xxx` | 未先 make generate | 先生成绑定（14.3） |
| `unexpected EOF`（binary.Read） | value 结构与 ValueSize 不符 | 布局核对（4.5） |
| goroutine 卡在 `rd.Read()` | ringbuf 未关 | 退出路径 rd.Close()+ErrClosed（6.2.2） |
| `objs.Close()` 后程序还挂着 | 被 tc filter 引用 | 先 FilterDel 再 Close（14.4） |
| 探测函数返回非 nil 非 ErrNotSupported | 探测失败 | 报错而非降级（15.2） |
