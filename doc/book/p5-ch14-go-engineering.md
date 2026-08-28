# 第 14 章 Go 工程化：cilium/ebpf 与 bpf2go

> 前面各章的 Go 侧代码都是"教学姿势"：手写 struct tag、直接
> LoadCollectionSpec、.o 随文件夹摆放。本章把它们升级成工程姿势：
> 为什么选 cilium/ebpf（而不是 cgo 绑 libbpf）、核心对象模型与
> 加载路径、bpf2go 生成流（含本仓库真实踩坑）、生命周期责任矩阵、
> 以及一份生产化清单。读完本章，仓库根目录那条 `make` 流水线对你
> 将不再有秘密。

## 14.1 为什么用 Go 写加载器

eBPF 的"官方"加载器是 C 的 libbpf。Go 项目接入有三条路：

```
 路线A：cgo 绑定 libbpf ──▶ 需要在目标机部署 libbpf.so（或静态链），
                             交叉编译困难（cgo 必须有目标平台工具链），
                             Go"单二进制"优势尽失
 路线B：fork 子进程跑 libbpf 工具 ──▶ 进程模型/错误传递/生命周期都别扭
 路线C：cilium/ebpf（纯 Go 重写 libbpf 职责）──▶ 零 cgo、单二进制、
                             GOOS=linux 交叉编译即得 ✓
```

cilium/ebpf 用纯 Go 实现了 libbpf 的全部核心职责：解析 ELF、
建 map、map/CO-RE 重定位、BPF_PROG_LOAD、各类挂载、ringbuf/perf
读取。本仓库锁定的 v0.22.0 的所有 API，本书写作时已逐一对照源码
核实。代价是它永远比内核新特性慢半拍（新 attach 类型等），好在
降级路径清晰（15.2）。

## 14.2 对象模型与加载路径

核心对象只有两层，全书已反复使用，此处正式定型：

```
 Spec（蓝图，纯内存）              实例（内核对象，持 FD）
 ┌─────────────────────┐          ┌──────────────────┐
 │ CollectionSpec      │  Load    │ Collection        │
 │  Programs[name]     │ ───────▶ │  Programs[name]   │
 │  Maps[name]         │ (验证+JIT│  Maps[name]       │
 │  Variables[name]    │  在此发生)│                  │
 └─────────────────────┘          └──────────────────┘
  可修改：改类型/改常量/挑着加载      用完必须 Close()
```

三条加载路径（按推荐度）：

```go
// ① LoadAndAssign：按 struct tag 只加载被引用的对象（本书主线）
var objs xxxObjects
spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{...})
defer objs.Close()

// ② NewCollection：全部加载，从 map 里按名取（教学用，第2章）
coll, _ := ebpf.NewCollection(spec)

// ③ bpf2go 生成的 LoadXxxObjects：①的生成器版（14.3）
var objs bpf.XdpObjects
bpf.LoadXdpObjects(&objs, nil)
```

加载期的三个高价值选项：

```go
ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{
        // verifier 日志（第3章）：默认失败才带；显式开启则成功也有
        LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats,
    },
    Maps: ebpf.MapOptions{
        PinPath: "/sys/fs/bpf/ruport",   // 自动 pin/复用同名 map
    },
}
```

**全局变量**（C 侧 `const volatile`/普通全局，5.1+）在加载前后
都能改——这正是原 ruport pidhide 里 `skel->rodata->pid_to_hide=...`
的 Go 对应物：

```go
spec.RewriteConstants(map[string]any{   // 加载前（.rodata 常量）
    "pid_to_hide_len": 6,
})
coll.Variables["enabled"].Set(true)     // 加载后（.data 变量）
```

**pin 与接管**：`objs.X.Pin("/sys/fs/bpf/xx")` 把对象变成路径引用，
下次启动 `ebpf.LoadPinnedMap(path, nil)` 找回——跨进程共享状态的
标准做法（第 2 章"FD 关即销毁"的反面）。

## 14.3 bpf2go：skeleton 的 Go 答案

手写 `LoadCollectionSpec + struct tag` 有两个工程缺陷：`.o` 要
随二进制分发、struct 手写易错（第 4 章的布局坑）。bpf2go 一次
解决：**编译 C、把 .o 嵌进 go:embed、生成全部绑定代码**。

### 14.3.1 流水线全景

```
 bpf/ruport_xdp.bpf.c
      │ clang -target bpf（bpf2go 内部调用）
      ▼
 ruport_xdp.bpf.o ──go:embed──▶ Xdp_bpfel.o 嵌入生成文件
      │                            │
      │  bpf2go 解析 ELF           ▼
      ▼                     Xdp_bpfel.go（含 //go:build 标签）
 生成：LoadXdp()/LoadXdpObjects(obj,opts)
       XdpObjects/XdpPrograms/XdpMaps（struct tag 已就位）
       XdpMessage（-type Message 按BTF生成，布局零手写）★
```

### 14.3.2 本仓库 Makefile 逐行（真实版）

```make
# 系统头搜索路径：让 clang -target bpf 找到 /usr/include 及多架构目录
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{s| \(/.*\)|-idirafter \1|p}')
BPF_CFLAGS := -O2 -g -Wall -Werror

generate:
	cd internal/bpf && $(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) -cflags "$(BPF_CFLAGS) $(CLANG_BPF_SYS_INCLUDES)" \
		-go-package bpf -type Message Xdp ../../bpf/ruport_xdp.bpf.c
	                     ^^^^^^^^^^^^^^^^ 大写ident → 生成【导出的】加载器
```

**真实踩坑实录**（本仓库开发日志里的三颗子弹，值得替你疼过）：

1. **`-go-package bpf` 不能省**：`go run` 直调 bpf2go 时没有
   go generate 提供的 `GOPACKAGE` 环境变量，缺它直接报
   `missing package...`；
2. **ident 大小写决定加载器是否导出**：大写 `Xdp` 生成
   `LoadXdpObjects(obj any, opts) error`（导出，直接调）；小写
   `xdp` 生成 `loadXdpObjects`（未导出，还得手写封装）。本仓库
   早期按小写样例推断"加载器必未导出"而手写封装，与大写 ident
   的生成物重名冲突（Linux 实机报 redeclared）——**教训：以自己
   ident 实际生成的文件为准**；
3. **`-Werror` 遇上死变量**：新版 clang 把"赋值未使用"升级为
   错误，原 ruport 遗留的死变量当场拦下（修复记录见 git log）。

### 14.3.3 `-type` 生成规则速记

- packed 结构逐字段平铺（无 padding）；自然对齐结构自动插入
  `_ [N]byte "padding"`；
- `char ext[100]` → `Ext [100]uint8`；位域**不支持**；
- `__be16/__be32` 就是 u16/u32——**字节序语义不会替你转换**
  （第 4 章三步口诀依然是你的事）。

生成物入库与否的取舍：入库则 clone 即可 `go build`（无 clang
环境也能编）；不入库则仓库干净但每台构建机都要 `make generate`
（本仓库选后者，README 写明）。

## 14.4 生命周期管理：责任矩阵

第 2/8/9 章零散踩过的生命周期问题，此处一张矩阵收口——
**谁负责清理什么**：

```
 对象/挂载         进程正常退出          进程崩溃(kill -9)       清理责任
 ─────────────────────────────────────────────────────────────────────
 XDP link          link FD 关闭=自动摘除  内核回收 FD=自动摘除      defer 即可 ✓
 cgroup link       同上                  同上                     ✓
 tc 经典 filter    ─                     ★残留！filter 引用程序   必须显式 FilterDel
                   │                      （下次 FilterAdd 撞      + 启动前清残留
                   │                       EEXIST、改写继续生效）
 ringbuf.Reader    rd.Close() 唤醒读循环  FD 回收                 ✓
 map/prog(FD引用)  最后 FD 关闭=销毁      同左                    ✓（除非被 pin/被引用）
 pinned 对象       持续存活               持续存活                 rm /sys/fs/bpf/xxx
```

两条衍生纪律：

1. **清理顺序**：先删引用方（tc filter），再关被引用方（程序 FD），
   最后 Close 对象——ruport main.go 的退出路径即按此排布；
2. **崩溃兜底**：经典 tc 挂载的程序应提供"启动时清理残留"或
   uninstall 子命令（第 15 章的动线 B 会再遇到）。

**热更新**：`link.Update(newProg)` 挂载关系不动换实现，零闪断——
策略常变的防火墙/代理应默认这个姿势，而不是反复 attach/detach。

## 14.5 生产化清单

从 demo 到生产的 checklist（每条在本书都有出处）：

1. **能力探测与降级**（15.2）：
   ```go
   if err := features.HaveMapType(ebpf.RingBuf);
       errors.Is(err, ebpf.ErrNotSupported) {
       // 退到 perf event array（第6章的两代通道）
   }
   ```
2. **verifier 日志兜底**：`ProgramOptions.LogLevel` 显式开启，
   生产排障时拿全量日志（第 3 章）；
3. **单测**：`Program.Run(&ebpf.RunOptions{Data: frame})` 不挂载
   直接喂包跑程序——网络程序的核心逻辑可以进 CI（第 7 章防火墙
   规则就能这么测）；
4. **构建链固化**：Makefile 一条命令（本仓库模式）；生成物策略
   明示；CI 里至少跑一次真实 `make`；
5. **运行可观测**：`bpftool prog/map show` 做健康检查（程序在吗/
   map 在吗/挂载在吗——第 15 章动线 B）；
6. **权限最小化**：root 起步，收紧到 `CAP_BPF + CAP_NET_ADMIN`
   （+tracing 场景 `CAP_PERFMON`）；5.11+ 无需 memlock 操作；
7. **退出三件事**：信号处理 → 按责任矩阵清理 → flush 日志。

## 14.6 小结与练习

**小结**：cilium/ebpf 用纯 Go 重写 libbpf 职责，换来单二进制与
交叉编译；对象模型=Spec（蓝图可改）→实例（内核持 FD 必关）；
bpf2go 把"编译+嵌入+绑定"变成构建期一步，大写 ident 生成导出
加载器、`-type` 按BTF生成零手写结构体；生命周期责任矩阵只有
经典 tc filter 一格要你亲自动手；生产化清单七条照抄即可起步。

**练习**：
1. 把第 7 章防火墙改造成 bpf2go 工程（Makefile 仿本仓库），体会
   "手写 struct → 生成"的差别；
2. 给它加 `Program.Run` 单测：构造一个命中黑名单的以太帧与一个
   不命中的，断言返回值分别为 XDP_DROP/XDP_PASS；
3. 实现"启动清残留"：用 netlink 列出现有 filter（`FilterList`），
   删除属于自己的 handle 再挂载——然后 kill -9 自己验证；
4. 思考题：为什么 `link.Update` 能零闪断而 attach/detach 不能？
   （从 14.4 矩阵里"挂载关系是内核对象"推演。）

---

工程化齐了。最后一章补上贯穿全书的两块方法论：版本兼容与调试
体系——然后就可以进军 ruport 了。
