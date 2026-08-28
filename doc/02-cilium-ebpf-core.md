# 02 · cilium/ebpf 核心对象与加载流程

目标：掌握 `CollectionSpec / Collection / Program / Map` 四个核心对象的
职责与生命周期，会用手写加载与 `LoadAndAssign` 两条路径，能拿到完整
verifier 日志，会重写全局变量、pin 对象、做能力探测。
所有 API 以 cilium/ebpf **v0.22.0** 为准。

---

## 1. 对象模型总览

```
 ELF 文件（.o）                          内核中的对象
 ┌──────────────────┐    LoadCollectionSpec    ┌──────────────────┐
 │ CollectionSpec   │◄─────────────────────────│   （无，纯静态）    │
 │  ├ ProgramSpec   │        （解析）           └──────────────────┘
 │  ├ MapSpec       │           │
 │  └ Variables     │           │ Load / LoadAndAssign（BPF_PROG_LOAD 等）
 └──────────────────┘           ▼
                        ┌──────────────────┐
                        │ Collection       │   Program（FD）  Map（FD）
                        │  或 XdpObjects   │   （LoadAndAssign 后放 struct）
                        └──────────────────┘
```

两套对象泾渭分明：

- **`Spec` 结尾 = 蓝图**：只是 ELF 里的静态描述，未进内核。可以在加载前
  修改（改类型、改常量、关 autoload）。
- **无 `Spec` = 实例**：已经 `BPF_PROG_LOAD`/`BPF_MAP_CREATE` 过，持有
  内核 FD，占内核内存，需要 `Close()`。

bpf2go 生成的 `LoadXdp()` 返回 `*CollectionSpec`（蓝图），
`LoadXdpObjects(&objs, nil)`（实例，填进 `XdpObjects`）——本仓库
`cmd/ruport/main.go` 直接调用的正是后者（大写 ident 下生成函数即为
导出，详见 03 章 §4 的命名规则）。

## 2. CollectionSpec：解析 ELF

```go
// 从 []byte / io.Reader / 磁盘文件三种来源解析
spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
spec, err := ebpf.LoadCollectionSpec("ruport_xdp.bpf.o")
```

解析失败常见原因：文件不是 clang `-target bpf` 产物（比如忘了 `-c` 直接
链接）、缺 `license` 段、map 定义用了不认识的格式。

`CollectionSpec` 的字段：

```go
type CollectionSpec struct {
    Name     string                        // 来自 .o 文件名（部分版本）
    Maps     map[string]*MapSpec           // ".maps" 段中的所有 map
    Programs map[string]*ProgramSpec       // 所有程序（按符号名索引）
    Variables map[string]*VariableSpec     // 全局变量（.rodata/.data）
    Types    *btf.Spec                     // 程序的 BTF（CO-RE 用）
    ByteOrder binary.ByteOrder             // 目标字节序（bpfel/bpfeb）
}
```

**按名字索引**：C 里 `SEC("xdp") int xdp_parse(...)` + map `message_map`
对应 Go 里 `spec.Programs["xdp_parse"]`、`spec.Maps["message_map"]`。

### 2.1 ProgramSpec：加载前改程序

```go
type ProgramSpec struct {
    Name         string
    Type         ProgramType   // 由 section 名推断："xdp"→XDP，"tc"→SCHED_CLS
    AttachType   AttachType
    AttachTo     string        // 部分挂载方式的锚点（如 tracepoint 名）
    Flags        uint32
    License      string
    Instructions asm.Instructions
    ByteOrder    binary.ByteOrder
    // ...
}
```

典型用途：

```go
spec.Programs["xdp_parse"].Type = ebpf.XDP     // 强制覆盖 section 名推断的类型
spec.Programs["tc_ingress"].AttachTo = "eth0"  // 部分挂载方式的锚点
```

**关于“只加载部分程序”**：v0.22 没有公开的 per-program autoload 开关
（libbpf 的 `bpf_program__set_autoload` 在 Go 侧无直接对应物）。等价
做法就是 `LoadAndAssign` + struct tag——**只有被 struct 引用的程序/map
才会加载**，大 .o 里没被引用的对象根本不会进内核；也可以从
`spec.Programs` 里删掉不需要的条目再加载。

### 2.2 MapSpec

见 04 章完整字段。此处只强调：`MapSpec.Contents` 可以在加载前填初值，
等价于 libbpf 的 ELF 内 map 初始化段。

## 3. 加载：三条路径

### 3.1 NewCollection（最原始）

```go
coll, err := ebpf.NewCollection(spec)
defer coll.Close()
prog := coll.Programs["xdp_parse"]
m    := coll.Maps["message_map"]
```

`coll.Close()` 会关掉**所有**程序和 map。取出的 `*Program/*Map` 只是
map 里的引用，不拥有 FD——`Close` 顺序错了容易 double close
（库内部有引用保护，但仍建议统一由 Collection 管）。

### 3.2 NewCollectionWithOptions（要控制加载选项时）

```go
coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{
        // 出错时自动重跑一次并带回完整 verifier 日志（推荐常开）
        // 详见 §5
        VerifierLogLevel: 0, // 默认：失败时自动补日志
    },
    Maps: ebpf.MapOptions{
        PinPath: "/sys/fs/bpf/ruport", // 自动 pin/复用兼容的已 pin map
    },
})
```

`CollectionOptions`（v0.22 实测字段）：

```go
type CollectionOptions struct {
    Maps     MapOptions                      // PinPath、LoadPinOptions
    Programs ProgramOptions                  // verifier 日志、BTF 注入
    MapReplacements map[string]*Map          // 复用已有 map 实例
    Cache    *btf.Cache                      // 跨多次加载复用内核 BTF 解析
}
```

### 3.3 LoadAndAssign（bpf2go 时代的主流，本项目在用）

```go
var objs XdpObjects
if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{ /*可 nil*/ }); err != nil {
    log.Fatal(err)
}
defer objs.Close()
```

规则：

- 传入的 struct（一般由 bpf2go 生成，也可手写）按 **struct tag**
  `ebpf:"xdp_parse"` 把内核对象绑定到字段；
- **只加载被引用到的程序和 map**，其余一概不进内核；
- 生成的 `XdpObjects` 自带 `Close()`，依次关闭 programs 和 maps；
- 同一 Spec 可以 `LoadAndAssign` 多次，得到互不相干的实例集。

本仓库 `cmd/ruport/main.go` 的用法（大写 ident 下 `LoadXdpObjects`
本身就是导出的填充式 API，直接调用）：

```go
var objs bpf.XdpObjects
if err := bpf.LoadXdpObjects(&objs, nil); err != nil {   // bpf2go 生成
    log.Fatal(err)
}
```

对应 libbpf 的 `ruport_xdp__open()` + `ruport_xdp__load()` 两步合一。

## 4. Program：已加载的程序

```go
p := objs.XdpParse

p.FD()                 // int，传给 netlink 等旧接口（TC 挂载用）
info, _ := p.Info()    // ProgramInfo：ID、类型、加载时间、tag、map_ids...
_ = p.Info().Tag       // 内容指纹（做缓存/比对用）

// 单测利器：不挂载、直接喂 context 运行一次
out, err := p.Run(&ebpf.RunOptions{
    Data:       ethFrame,       // 输入“包”
    DataOut:    make([]byte, 0, 1500),
    Repeat:     1,
})
// out[0] 是 XDP 动作（0=PASS,1=DROP,...）

p.Pin("/sys/fs/bpf/xdp_parse")   // 持久化到 bpffs
p2, _ := ebpf.LoadPinnedProgram("/sys/fs/bpf/xdp_parse", nil)
p.Close()
```

**生命周期铁律**：`Program` 被 GC 或 `Close()` 后，其内核 FD 释放；此时
如果没有任何挂载/引用保住它，程序就会被销毁。对 XDP link 而言 detach
也随之发生；但**经典 TC filter 会引用程序**，进程退出后 filter 仍在、
程序仍在跑——ruport 必须在退出路径里显式 `FilterDel`，原因见 05 章。

## 5. 拿到 verifier 日志（排障第一工具）

`ProgramOptions`（v0.22 实测字段）：

```go
type ProgramOptions struct {
    LogLevel       LogLevel  // 位图：LogLevelBranch|LogLevelStats|...
    LogSizeStart   uint32    // 日志缓冲初始大小，不够会自动翻倍
    LogDisabled    bool      // 彻底关闭（省一次重载）
    KernelTypes    *btf.Spec // 注入自定义内核 BTF（容器/离线场景）
    // ExtraRelocationTargets ...
}
```

默认行为：先**不带日志**加载一次，失败后再带 `LogLevelBranch` 重试并把
日志塞进错误——所以“什么都不配也有日志”是刻意的。要主动拿全量日志：

```go
coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{
        LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelStats,
        LogSizeStart: 1 << 20,
    },
})
// 成功时：coll.Programs["xdp_parse"].VerifierLog 里有全文
```

日志怎么读见 01 章 §4.4，错误样例大全见 08 章。

## 6. 全局变量（.rodata / .data）重写

C 侧声明 `const volatile int pid_to_hide_len = 0;` 或普通全局
`volatile bool enabled = false;`，编译后落在 `.rodata`/`.data` 段，
加载器会把它们做成**只读/读写 map**。Go 侧在加载前改初值：

```go
spec, _ := ebpf.LoadCollectionSpec("prog.bpf.o")

// 1) 常量（.rodata）：编译期优化掉的 const volatile
if err := spec.RewriteConstants(map[string]any{
    "pid_to_hide_len": 6,
}); err != nil { ... }

// 2) 运行期变量（.data）：加载后还能改
coll, _ := ebpf.NewCollection(spec)
v := coll.Variables["enabled"]
_ = v.Set(true)   // Set(any)
var cur bool
_ = v.Get(&cur)
```

这正是原 ruport pidhide 里 `skel->rodata->pid_to_hide_len = ...` 的
cilium/ebpf 对应物。注意 `RewriteConstants` 作用于 Spec（加载前），
`Variables.Set` 作用于实例（加载后）；常量被优化进指令时必须用前者。

## 7. Pin：让对象活过进程

FD 随进程消亡；把对象 pin 到 bpffs（`/sys/fs/bpf`，由内核挂载）就变成
路径引用，重启进程后可找回：

```go
// pin
_ = objs.MessageMap.Pin("/sys/fs/bpf/ruport_message_map")
_ = objs.XdpParse.Pin("/sys/fs/bpf/ruport_xdp_parse")

// 下次启动时恢复
m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/ruport_message_map", &ebpf.LoadPinOptions{})
p, err := ebpf.LoadPinnedProgram("/sys/fs/bpf/ruport_xdp_parse", nil)

// 或者让 Collection 自动 pin/复用：MapOptions.PinPath + MapSpec.Pinning
```

另一种批量做法：BTF map 定义里写 `__uint(pinning, LIBBPF_PIN_BY_NAME);`，
配合 `MapOptions.PinPath="/sys/fs/bpf/xxx"`，同名的已 pin map 会被复用，
类型不兼容则报错——适合“控制面重启但数据面不想丢状态”的场景。

清理 pin：`os.Remove("/sys/fs/bpf/xxx")`（bpffs 上的“文件”就是 pin）。

## 8. 能力探测：Features

不同内核功能参差，先探测再降级是库自带姿势（结果有缓存）：

```go
switch err := ebpf.HaveProgramType(ebpf.XDP); {
case nil:            // 支持
case errors.Is(err, ebpf.ErrNotSupported):
    // 内核/权限不支持，走降级路径
default:             // 探测本身出错（如权限）
}

_ = ebpf.HaveMapType(ebpf.RingBuf)
_ = ebpf.HaveBatchAPI()
link.HaveTCX()      // link 包也有：tcx、kprobe multi 等
```

返回值语义：`nil`=支持，`ebpf.ErrNotSupported`=确定不支持，
其他错误=探测不了（常见于权限不足，别当成“不支持”）。

## 9. memlock 与权限

- kernel **5.8+** 细分了 `CAP_BPF`/`CAP_PERFMON`/`CAP_NET_ADMIN` 等能力；
  root 天然全有。
- kernel **< 5.11**：加载 BPF 锁定的内存受 `RLIMIT_MEMLOCK` 约束，
  加载前调用一次：
  ```go
  import "github.com/cilium/ebpf/rlimit"
  if err := rlimit.RemoveMemlock(); err != nil { log.Fatal(err) }
  ```
  5.11+ 改为 memcg 计费，此调用变成无害空操作。ruport-go 每次启动都调，
  兼容两类内核。
- 加载报 `EPERM` 且 verifier 日志为空，先想权限：非 root、
  `kernel.unprivileged_bpf_disabled=2`（默认禁非特权）、容器缺 capability。

## 10. 手写一个完整加载器（不用 bpf2go）

便于理解 bpf2go 帮你省了什么（也适合小工具）：

```go
//go:build linux

package main

import (
    "log"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

type packetCountObjects struct {
    CountPackets *ebpf.Program `ebpf:"count_packets"`
    PktCnt       *ebpf.Map     `ebpf:"pkt_cnt"`
}

func main() {
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal(err)
    }

    spec, err := ebpf.LoadCollectionSpec("minimal.bpf.o")
    if err != nil {
        log.Fatalf("parse ELF: %v", err)
    }

    var objs packetCountObjects
    if err := spec.LoadAndAssign(&objs, nil); err != nil {
        log.Fatalf("load: %v", err)   // verifier 错误也会出现在这里
    }
    defer objs.Close()

    lk, err := link.AttachXDP(link.XDPOptions{
        Program: objs.CountPackets, Interface: 2, Flags: link.XDPGenericMode,
    })
    if err != nil {
        log.Fatalf("attach: %v", err)
    }
    defer lk.Close()

    var v uint64
    for range 10 {
        _ = objs.PktCnt.Lookup(uint32(0), &v)
        log.Printf("packets=%d", v)
        time.Sleep(time.Second)
    }
}
```

与之相比，bpf2go 把“分发 .o 文件 + 手写 struct tag”变成编译期生成、
`go:embed` 内嵌——下一章展开。

---

下一章：[03-bpf2go.md](03-bpf2go.md)——生成绑定的完整工作流与规则。
