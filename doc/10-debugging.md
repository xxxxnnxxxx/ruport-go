# 10 · eBPF 调试信息查看完全指南

目标：**任何阶段出问题，都知道去哪里看什么**。按程序生命周期组织：
编译期 → 加载期（verifier）→ 挂载期 → 运行期（内核侧输出、用户态观察、
状态统计）→ 性能层，最后给出四条标准排障动线。bpftool 部分为逐子命令
手册。症状级速查仍见 [08-troubleshooting.md](08-troubleshooting.md)。

---

## 0. 调试信息全景图

```
阶段                可观察的信息                    工具
────────────────────────────────────────────────────────────
编译期      预处理/汇编/ELF 段/BTF          clang -E/-S, llvm-objdump, bpftool btf
加载期      verifier 逐指令日志/统计        ProgramOptions.LogLevel, dmesg
挂载期      挂载关系/qdisc/filter/link      bpftool net/link, tc, ip
运行期-内核  printk/trace_pipe/snprintf     bpf_printk + trace_pipe
运行期-用户  map 内容/对象信息/事件         bpftool map/prog, Go LookupBytes
统计层      运行次数/耗时/丢样             bpf_stats, ringbuf Remaining
系统层      权限/配置/能力                 sysctl, /proc/config.gz, feature probe
```

## 1. 编译期：确认“进内核的字节码长什么样”

```bash
# 1) 预处理结果（宏/BTF map 定义展开对不对）
clang -target bpf -E -I... ruport_xdp.bpf.c | less

# 2) 生成 BPF 汇编（-S 保留符号）
clang -target bpf -O2 -S -c ruport_xdp.bpf.c -o -    # 直接输出 .s

# 3) 看 ELF 段（.maps? 用 BTF 定义时无 .maps 段，看 BTF/license/programs）
llvm-readelf -S ruport_xdp.bpf.o
llvm-readelf -x .BTF ruport_xdp.bpf.o               # BTF 原始 hex

# 4) 反汇编目标文件
llvm-objdump -d --no-show-raw-insn ruport_xdp.bpf.o

# 5) 把 .o 里的 BTF 展开成 C（检查 -type 生成、结构体偏移）
bpftool btf dump file ruport_xdp.bpf.o format c | sed -n '/struct Message/,/};/p'

# 6) 对照：vmlinux.h 是否存在/重新生成
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

典型用途：验证 `#pragma pack(1)` 是否生效（看 BTF 里 `cip` 偏移是不是
2）、确认 helper 调用被编译成了 `call` + 正确编号、找 license 段缺失。

## 2. 加载期：verifier 日志完全指南

### 2.1 cilium/ebpf 怎么拿到日志（v0.22 实测）

```go
coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{
        LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelStats,
        LogSizeStart: 64 << 10,
    },
})
```

- **默认（LogLevel=0）两段式**：先静默加载；失败自动以
  `LogLevelBranch` 重试并把日志附进返回的 error——所以“什么都不配，
  失败时 error 字符串里就有完整 verifier 日志”。排障时直接
  `log.Fatalf("load: %v", err)` 打全量即可。
- 显式设 LogLevel 后**单次加载**就带日志，且**成功也能拿到**：
  ```go
  p := coll.Programs["xdp_parse"]
  fmt.Println(p.VerifierLog)   // Program.VerifierLog string（v0.22 字段）
  ```
- 级别（`types.go`）：`LogLevelBranch`（分支点状态）、
  `LogLevelInstruction`（每指令状态，**5.2+**）、`LogLevelStats`
  （末尾统计 processed insns/states，**5.2+**），可 OR。
- `LogDisabled: true` 彻底关闭（性能敏感的重复加载场景）。

### 2.2 逐行读 verifier 日志

```
28: (61) r2 = *(u32 *)(r1 +0)
29: (bf) r3 = r1
30: (07) r3 += 14
31: (2d) if r3 > r2 goto pc+8
 R1=ctx(id=0,um?...) R2=pkt(id=3,off=0,r=14) R3_w=inv(id=0)   ← 到达该分支时的寄存器状态
```

- 每行：`指令号: (操作码) 汇编`；
- `R2=pkt(id=3,off=0,r=14)`：包指针、从 0 起、**还可安全读 14 字节**——
  出现 `r=0` 还在解引用就是越界（修法见 08 §1.1）；
- 带 `was-verified-before`? / 状态等价剪枝行可忽略；
- 末尾 `processed 57 insns (limit 1000000) max_states_per_insn 2
  total_states 13 peak_states 13 mark 12`：状态数接近百万上限 =
  循环/分支爆炸，需要重写逻辑而不是调参数；
- 错误行 `invalid access to packet...` 后紧跟的 `This error...`? 或
  `if statement` 提示——定位到指令号后，回到源码对应位置（`clang -S`
  的汇编可对照指令序号）。

### 2.3 加载期的其他信息源

```bash
sudo dmesg | grep -i bpf        # 老路径/极端情况的内核侧报错
sudo strace -f -e bpf ./ruport  # 看 BPF_PROG_LOAD 的 errno 与 attr
```

libbpf 用户对照：libbpf 的 `bpf_obj_load` verbose（`LIBBPF_STRICT`/
`bpf_set_print`）≈ cilium 的 LogLevel + error 链。

## 3. 挂载期：确认“钩子真的挂上了”

```bash
sudo bpftool net show                 # XDP/tc/flow dissector 总览
sudo bpftool link show                # link 化挂载（含 prog id、pinned 路径）
sudo tc qdisc show dev eth0           # clsact 在不在
sudo tc filter show dev eth0 ingress  # bpf filter、prio、handle、直接看 prog id
sudo tc filter show dev eth0 egress
ip -d link show eth0                  # xdp 标记（xdpgeneric/xdp）
sudo bpftool prog show                # 所有已加载程序：id/type/name/tag/通过时长
```

挂载了但“没生效”时进一步：`bpftool prog show` 看 `run_cnt`（先开
统计，见 §6）是否随流量增长——区分“没挂上/没被调用”与“被调用了但
逻辑没命中”。

## 4. 运行期·内核侧输出（bpf_printk 家族）

### 4.1 bpf_printk / bpf_trace_printk（4.1+）

```c
#include <bpf/bpf_helpers.h>

bpf_printk("xdp: pkt len %d sport %d", len, sport);   // 宏，≤3 个参数自动拆
bpf_printk("comm %s", comm);                          // %s 用 char 数组/内核指针
```

规则与限制（**限制的内核根源**——栈、helper 5 参上限、.rodata——
见 [13-printk-and-trampoline.md](13-printk-and-trampoline.md)）：

- 底层 helper `bpf_trace_printk`：**最多 3 个**可变参数；`%s` 需要内核
  空间可读指针（用户态指针要先 `bpf_probe_read_user_str`）；不支持
  宽度/精度修饰；`bpf_printk` 宏（bpf_helpers.h）封装了单参/多参两种
  形态（多参 ≤3）；
- 超过 3 参或要 `%s`+复杂格式：`bpf_snprintf`（5.9~）先格式化到栈
  buffer，再 printk 或走 ringbuf；5.16+ 有 `bpf_trace_vprintk`；
- **性能**：走全局 trace ring + 锁，高频路径（每包打印）会显著拖慢并
  互相踩踏——仅调试期使用，生产换 ringbuf 事件。

### 4.2 trace_pipe：看 printk 输出

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe      # 实时流（阻塞读，Ctrl-C 退）
sudo cat /sys/kernel/debug/tracing/trace           # 快照（读完不清除，可 echo 0 > trace 清）
sudo tail -f /sys/kernel/debug/tracing/trace_pipe  # 等 tail -f 用法
```

输出形如：

```
<...>-1234  [003] d..1 12345.678910: :insert a message into the map.
 ^pid        ^CPU        ^时间戳(单调钟)              ^你的文本
```

- 多 CPU 输出会**交织**，靠 `[CPU]` 与时间戳对齐；ruport 的
  `bpfprint` 宏输出就出现在这里；
- 需要 tracefs/debugfs 已挂载（主流发行版默认）；
- **配套神器 `trace_marker`**：用户态也能往同一条时间线打点——
  `echo "user: sending c3 packet" | sudo tee /sys/kernel/debug/tracing/trace_marker`，
  内核侧与用户侧事件对表排时序专用；
- 控制开关：`/sys/kernel/debug/tracing/tracing_on`（0/1）。

### 4.3 结构化替代：ringbuf 当调试通道

正式做法（生产可留）：事件带上下文（cpu/pid/ktime）走 ringbuf，用户态
结构化打印。参考 doc/06 例 3。判断“该用哪个”：临时看一眼用 printk；
要保留、要并发安全、要带二进制负载就 ringbuf。

### 4.4 bpf_iter（5.8+）：把 map/内核状态“cat 出来”

```bash
sudo bpftool iter pin /sys/fs/bpf/dump myprog.bpf.o map_dump     # 示意
cat /sys/fs/bpf/dump                                            # 触发遍历输出
```

内核侧用 `bpf_seq_printf`。适合“定期 dump 大 map”类运维需求。

## 5. 运行期·用户态观察

### 5.1 bpftool 完全手册（常用子命令逐个过）

**prog**

```bash
sudo bpftool prog show                       # 全部：id、类型、名字、tag
sudo bpftool prog show name xdp_parse        # 按名过滤
sudo bpftool prog show id 42                 # 单个（含 verifier 状态/加载者 pid）
sudo bpftool prog dump xlated id 42          # 验证后指令（含内核注释行）
sudo bpftool prog dump xlated id 42 linum    # 关联源码行（需 -g 编译）
sudo bpftool prog dump jited id 42           # JIT 本机码（需 CONFIG_BPF_JIT）
sudo bpftool prog pin id 42 /sys/fs/bpf/xdp_parse
sudo bpftool prog run id 42 data_in pkt.bin data_out out.bin repeat 10
                                             # 用户态直接喂包跑（test_run，4.4+）
```

**map**

```bash
sudo bpftool map show
sudo bpftool map show name message_map
sudo bpftool map dump name message_map               # 全量（原始字节+hex）
sudo bpftool map dump id 16
sudo bpftool map lookup keyed name m key 0x0100007f  # 指定 key（hex）
sudo bpftool map update name m key hex val hex ...   # 用户态写（构造测试）
sudo bpftool map delete name m key hex ...
sudo bpftool map getnext name m key hex              # 迭代游标
sudo bpftool map pin name m /sys/fs/bpf/m
sudo bpftool map peek name q                         # queue/stack
```

`dump` 输出的 value hex 是**布局排障的终极真相**——与 Go
`LookupBytes` 打印的 hex 对不上，就是布局/字节序问题（08 §3）。

**link / net / btf / perf / feature / iter**

```bash
sudo bpftool link show                        # link 化挂载、pinned 状态
sudo bpftool link pin id 7 /sys/fs/bpf/lk
sudo bpftool link detach id 7                 # 主动断链
sudo bpftool net show / detach dev eth0 xdp   # 网络挂载总览/卸载
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c
sudo bpftool btf dump file ruport_xdp.bpf.o format raw
sudo bpftool perf show                        # perf_event 类挂载（kprobe 等）
sudo bpftool feature probe full               # 见 09 §9.2
sudo bpftool iter pin ...                     # 见 §4.4
```

**通用 flags**：`-j`（JSON，可接 jq）、`-p`（pretty）、`-d`（debug）。

```bash
sudo bpftool -j prog show | jq '.[] | select(.name=="xdp_parse") | .run_time_ns'
```

### 5.2 Go 侧调试手段

```go
// ① 原始字节对照（排布局/字节序首选）
raw, _ := objs.MessageMap.LookupBytes(key)
log.Printf("raw: % x", raw)

// ② 不挂载单测程序（构造 context 输入）
out, err := objs.XdpParse.Run(&ebpf.RunOptions{
    Data:    frame,        // 完整以太帧
    DataOut: buf,
    Context: nil,          // XDP 无额外 context
    Repeat:  1,
})
ret, _ := out[0].(uint32)  // XDP_PASS=0 / DROP=1 ...

// ③ 打印 verifier 日志（成功也打）
coll, _ := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats}})
log.Print(coll.Programs["xdp_parse"].VerifierLog)

// ④ 系统调用层
// sudo strace -f -e bpf,netlink ./ruport
```

### 5.3 网络效果验证（ruport 类改包程序）

```bash
sudo tcpdump -ni eth0 tcp port 80 -e -x        # 改写前后对比端口字段
ss -tnp                                        # 本机连接表（源/目的端口）
sudo conntrack -L 2>/dev/null | grep <ip>      # 若装了 conntrack
```

注意：tc ingress 改写发生在**路由/本机投递之前**，tcpdump（af_packet）
抓到的是**改写后**的包；XDP 层的包则要在驱动层抓（tcpdump 看到的已是
XDP 处理后的结果——XDP_DROP 的包 tcpdump 根本看不到）。

## 6. 统计与性能层

```bash
# 开启 BPF 运行统计（5.8+，BPF_ENABLE_STATS）
echo 1 | sudo tee /proc/sys/kernel/bpf_stats_enabled
sudo bpftool prog show            # 多出 run_time_ns / run_cnt
# 用完关闭（有全局开销）
echo 0 | sudo tee /proc/sys/kernel/bpf_stats_enabled
```

- `run_cnt` 不涨 = 程序没被调用（挂载/过滤条件问题）；
- `run_time_ns/run_cnt` 平均单次耗时异常大 → dump xlated 看是否验证器
  没能优化掉多余检查、map 访问是否过频、是否该换 per-CPU；
- 深度剖析：`perf record -g` 采样（把 BPF JIT 代码算进内核符号）+ 火焰
  图；ringbuf 侧看 `Record.Remaining` 与丢样判断消费是否够快。

## 7. 系统层状态（权限/配置）

```bash
cat /proc/sys/kernel/unprivileged_bpf_disabled       # 0/1/2 语义见 09 §9.1
sudo cat /proc/sys/kernel/perf_event_paranoid        # <1 才好挂 kprobe 类
cat /proc/sys/net/core/bpf_jit_enable                # JIT 开关（x86 恒开）
grep bpf /sys/kernel/security/lsm                    # LSM 程序可用性
zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF    # BTF
```

## 8. 四条标准排障动线（checklist）

**A. 加载失败**
1. 读 error 里的 verifier 日志（默认自带；或显式 LogLevel）；
2. 日志为空 → 权限/配置（§7、09 §9.1）；
3. `strace -e bpf` 看 errno；
4. 按指令号回源码，对照 08 §1 修。

**B. 挂了没生效**
1. `bpftool net show` / `tc filter show` / `bpftool link show`——挂载在吗；
2. 开 `bpf_stats` 看 `run_cnt`——被调用吗；
3. 被调用没命中 → `bpf_printk` 打中间变量 + `bpftool map dump` 看状态
   （如 router_map 的学习字段）；
4. 残留冲突（EEXIST）→ 08 §4 清理脚本。

**C. 数据错乱**
1. `bpftool map dump` vs Go `LookupBytes` hex 对照；
2. 布局（pack/对齐）→ `bpftool btf dump file xx.o format c`；
3. 字节序 → 04 §7.3 三步口诀；
4. 时序（读取过早/被覆盖）→ trace_marker 打点对时间线。

**D. 性能差**
1. `bpf_stats` 定位耗时程序；
2. `prog dump xlated` 看生成指令；
3. map 换 per-CPU/减少查找；
4. printk 之类调试残留删干净。

---

版本/特性问题查 [09-kernel-versions.md](09-kernel-versions.md)；
症状速查回 [08-troubleshooting.md](08-troubleshooting.md)；
返回[索引](README.md)。
