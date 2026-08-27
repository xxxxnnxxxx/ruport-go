# 03 · bpf2go 工作流

目标：吃透 bpf2go 的命令行、生成物解剖、`-type` 结构体生成规则，以及本
仓库 Makefile 每一行为什么那么写。bpf2go 在 cilium/ebpf 生态中的地位等
于 libbpf 世界的 `bpftool gen skeleton`：**把“编译 + 嵌入 + 绑定”变成
构建期的一步**。

---

## 1. 它做了什么

一次 bpf2go 调用完成四件事：

1. 调用 clang 把 `.bpf.c` 编译成 BPF 目标的 `.o`（可能多个端序目标）；
2. 用 `go:embed` 把 `.o` 字节嵌进一个 Go 源文件；
3. 解析 `.o`，为其中的程序/map 生成带 struct tag 的 Go 类型与
   `load<Ident>` 系列加载函数；
4. 对 `-type` 指定的 C 结构体生成等价 Go 结构体。

产物是形如 `Xdp_bpfel.go` + `Xdp_bpfel.o` 的成对文件（`bpfeb` 同理），
`//go:build` 标签保证只在对应架构/端序编译。

## 2. 命令行全参（v0.22.0，`bpf2go -h` 实测）

```
bpf2go [flags] <ident> <file.c>
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-cc` | `clang`（环境 `BPF2GO_CC`） | 编译器，可写 "ccache clang" |
| `-cflags` | ""（环境 `BPF2GO_CFLAGS`） | 传给 clang 的参数（带引号的字符串） |
| `-strip` | ""（环境 `BPF2GO_STRIP`） | strip 工具（如 `llvm-strip`） |
| `-no-strip` | false | 不 strip DWARF（**默认会自动 strip**） |
| `-target` | `bpfel,bpfeb` | 编译目标（逗号分隔）；`bpfel_x86` 等可缩窄架构 |
| `-type` | 无 | 指定 C 类型名生成 Go 声明，**可重复** |
| `-no-global-types` | false | 跳过 map key/value 等类型的自动生成 |
| `-tags` | 无 | 生成文件追加 Go build tags |
| `-go-package` | 取 `GOPACKAGE` env | 输出文件的包名 |
| `-output-dir` | 当前目录 | 输出目录 |
| `-output-stem` | 同 ident | 生成文件名主干 |
| `-output-suffix` | 由 `$GOFILE` 推断 | 生成文件名后缀（`_test` 等） |
| `-makebase` | 无（环境 `BPF2GO_MAKEBASE`） | 写 make 依赖信息文件，配合增量编译 |
| `-V/-verbose` | false | 详细输出 |

**两个高频踩坑点**（本仓库踩过第一个）：

1. **`-go-package` / `GOPACKAGE`**：通过 `go generate` 运行时，go 工具链
   会设置 `GOPACKAGE`；但用 `make` 里 `go run github.com/cilium/ebpf/cmd/bpf2go`
   直接跑时没有这个环境变量，必须显式 `-go-package bpf`，否则报
   `missing package, you should either set the go-package flag or the GOPACKAGE env`。
2. **默认 target 是两个端序都编**：在 x86 上也会产出 `Xdp_bpfeb.*`（供
   s390x 交叉编译用）。想只编小端：`-target bpfel`。

## 3. 两种集成方式

### 3.1 go:generate（官方推荐）

```go
// internal/bpf/generate.go
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang \
//    -cflags "-O2 -g -Wall" -type Message Xdp ../../bpf/ruport_xdp.bpf.c
```

然后 `go generate ./...`。`$GOPACKAGE`/`$GOFILE` 由工具链注入，
无需 `-go-package`。cflags 里的系统头路径问题见 §5。

### 3.2 Makefile 直调（本仓库采用）

```make
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{s| \(/.*\)|-idirafter \1|p}')

generate: tidy
	cd internal/bpf && $(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) -cflags "$(BPF_CFLAGS) $(CLANG_BPF_SYS_INCLUDES)" \
		-go-package bpf -type Message Xdp ../../bpf/ruport_xdp.bpf.c
	cd internal/bpf && $(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) -cflags "$(BPF_CFLAGS) $(CLANG_BPF_SYS_INCLUDES)" \
		-go-package bpf -type Router Tc ../../bpf/ruport_tc.bpf.c
```

选择 Makefile 而非 go:generate 的原因：

- 系统头搜索路径（`-idirafter` 列表）需要 shell 动态推导，塞进
  go:generate 行里既难读又受制于变量展开；
- 生成顺序可与 `tidy`、`go build` 显式串联，CI 一条 `make` 到底；
- 本仓库沿用原 ruport Makefile 的同款 include 推导逻辑，行为可对照。

## 4. 生成文件解剖

对 `bpf2go ... -type Message Xdp ruport_xdp.bpf.c`，生成
`Xdp_bpfel.go`（节选自 v0.22 模板结构）：

```go
//go:build (amd64 || arm64 || ...) && linux

package bpf

import (
    "bytes"
    _ "embed"
    "fmt"
    "io"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/asm"
    "github.com/cilium/ebpf/internal/sys"
    "github.com/cilium/ebpf/internal/btf"
    "structs" // 布局标记用（go 1.23+ 的 structs.HostLayout）
)

//go:embed xdp_bpfel.o          // ← .o 已嵌入，运行期无需分发文件
var _XdpBytes []byte

// -type Message 生成的结构体
type XdpMessage struct {
    Ins        uint16
    Cip        uint32
    ...
    Ext        [100]uint8
}

// 对象名常量（Collection 里按名查找用）
const (
    XdpProgramXdpParse = "xdp_parse"
    XdpMapMessageMap   = "message_map"
)

// 返回嵌入 ELF 解析出的 Spec
func loadXdp() (*ebpf.CollectionSpec, error) { ... }

// 填充式加载：等价 spec.LoadAndAssign(obj, opts)
func loadXdpObjects(obj any, opts *ebpf.CollectionOptions) error { ... }

type XdpPrograms struct {
    XdpParse *ebpf.Program `ebpf:"xdp_parse"`
}
type XdpMaps struct {
    MessageMap *ebpf.Map `ebpf:"message_map"`
}
type XdpObjects struct {
    XdpPrograms
    XdpMaps
}
func (o *XdpObjects) Close() error   // 关闭全部 programs + maps

// Spec 阶段的镜像（Assign 用，本仓库未用）
type XdpSpecs struct { XdpProgramSpecs; XdpMapSpecs }
```

**命名规则**：ident 首字母大写 → 所有导出符号（`XdpObjects`）；
小写则全部未导出。`loadXdpObjects` 本身始终小写——所以跨包使用必须像
本仓库 `internal/bpf/loader.go` 那样手写一层导出封装：

```go
func LoadXdpObjects(opts *ebpf.CollectionOptions) (*XdpObjects, error) {
    var objs XdpObjects
    if err := loadXdpObjects(&objs, opts); err != nil {
        return nil, err
    }
    return &objs, nil
}
```

**字段名规则**：C `xdp_parse` → Go `XdpParse`；`message_map` →
`MessageMap`；结构体成员 `connport` → `Connport`。蛇形转驼峰，保大小写
信息有限，遇到 `cport` 这种词生成 `Cport`（不是 `CPort`），写 Go 代码时
以生成物为准（`go doc` 或直接看文件）。

## 5. clang、头文件与 `-idirafter`

BPF 目标编译不链接 libc、不用系统默认 include 路径的 gcc 体系，但
`<linux/bpf.h>`、`<bpf/bpf_helpers.h>`（来自 libbpf-dev）仍是必须的。
clang 对 `--target=bpf` 仍会搜索其内建路径，但发行版的多 ARCH 头
（`/usr/include/x86_64-linux-gnu/...`）经常漏掉，表现为：

```
fatal error: 'linux/bpf.h' file not found
```

解法即 Makefile 那行：让 clang 以本机 C 目标打印搜索路径，全部转成
`-idirafter` 追加：

```
clang -v -E - </dev/null   # 打印 "<...> search starts here:" 列表
```

如果项目用了 vmlinux.h，把它放进 `bpf/headers/` 并加
`-I../../bpf/headers` 即可（ruport 的 xdp/tc 只用 UAPI 头，未用）。

`-cflags` 里的推荐组合：`-O2 -g -Wall -Werror`。`-g` 保留 BTF/调试信息
供 CO-RE 与 `-type` 生成（bpf2go 默认再 strip DWARF 只留 BTF）；
`-Werror` 在构建期暴露未初始化变量等会被验证器拒的问题。

## 6. `-type` 结构体生成规则（重点）

bpf2go 依据 `.o` 里的 **BTF** 把 C 类型翻成 Go，规则要点：

| C 构造 | Go 生成物 | 备注 |
|---|---|---|
| `struct { u16 a; u32 b; }`（自然对齐） | `A uint16; _ [2]byte; B uint32` | 自动插 padding，保证二进制一致 |
| `#pragma pack(1)` / `__attribute__((packed))` | 无 padding 字段，逐个排列 | ruport 的 `Message/Router` 即此 |
| 固定数组 `char ext[100]` | `Ext [100]uint8` | |
| `union` | `[N]uint8` 或匿名 struct | 一般不推荐跨边界用 union |
| `enum` | 具名 uint 常量 | |
| 位域 bitfield | **不支持** | 必须改数组/整数手工拆位 |
| `volatile const` 全局 | 不进 `-type`，走 Variables/RewriteConstants | 见 02 章 §6 |

**为什么必须逐字节一致**：map 的 key/value 在内核看来只是
`key_size/value_size` 字节的裸内存；Go 侧结构体经过
`encoding/binary` 风格的 marshal 写入。两端布局差一个字节，轻则读出
乱码，重则 key 永远对不上（hash map 静默查不到）。三种保证手段：

1. **首选 `-type` 自动生成**（本仓库做法）；
2. 手写时用 `_ [N]byte "padding"` 占位并算清偏移；
3. 完全绕开结构体，手写 `binary.Write(buf, binary.LittleEndian, ...)`。

**字节序补充**：`__be16/__be32` 在 BTF 里就是 u16/u32，生成的 Go 字段
不会替你转换——网络字节序字段在 Go 里拿到的是“内存原样解释”的整数，
小端机器上要自己做 `ntohs/ntohl` 等价转换（ruport-go 的
`toHostPort/ip2str` 就是干这个，详见 04 章 §8）。

## 7. 生成物要不要进 git？

| 方案 | 优点 | 缺点 |
|---|---|---|
| 提交生成物（本仓库 **未** 采用，已 gitignore） | clone 即可 `go build`，无需 clang | diff 噪音、易忘再生成导致陈旧 |
| 不提交（本仓库采用） | 仓库干净，C 改动必经 `make` | 新环境必须先 `make generate`；无 clang 机器编不了 |

配套约定：`.gitignore` 里的
`internal/bpf/*_bpfel.go|*_bpfel.o|*_bpfeb.*` 与 Makefile `clean`
规则一一对应；README 写明“先 make 再 build”。
（折中方案：CI 里生成后回填 PR，或提供 `make generate-committed`。）

## 8. 增量构建提示

- `-makebase .` 让 bpf2go 写出 `.d` 依赖文件，配合 make 的 `-include`
  实现“改了 .c/.h 自动重新生成”；
- 简单项目可无脑 `make generate`（clang 全量编两个 .o 通常 <1s）；
- 想本地调试 BPF 汇编：在 `-cflags` 里临时加 `-S` 或 clang `-emit-llvm`
  自行观察，不要把中间产物提交。

## 9. 与 libbpf skeleton 的对照表

| libbpf（原 ruport） | bpf2go（ruport-go） |
|---|---|
| `ruport_xdp__open_and_load()` | `loadXdpObjects(&objs, nil)` |
| `skel->progs.xdp_parse` / `bpf_program__fd()` | `objs.XdpParse` / `.FD()` |
| `skel->maps.message_map` / `bpf_map__fd()` | `objs.MessageMap` |
| `skel->rodata->xxx = y` | `spec.RewriteConstants` 后再加载 |
| `ruport_xdp__destroy(skel)` | `objs.Close()` |
| 分发 `.o` 与二进制 | `.o` 内嵌二进制，单文件部署 |

---

下一章：[04-maps.md](04-maps.md)——map 的完整 API、迭代/批量/per-CPU/
ringbuf，以及内核↔用户结构体一致性专题。
