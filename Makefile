# ruport-go 构建脚本
#
# 依赖（Debian/Ubuntu）：
#   go >= 1.24, clang, libbpf-dev(提供 bpf/bpf_helpers.h 等头文件), make
#
# 流程：tidy -> generate(bpf2go 编译 bpf/*.bpf.c 并生成 Go 绑定) -> build
# 产物：当前目录下的 ruport（控制程序）与 c3（指令发送端）

GO ?= go
CLANG ?= clang

# BPF 目标编译时需要的系统头文件搜索路径（与原 ruport 项目 Makefile 一致）
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{s| \(/.*\)|-idirafter \1|p}')

BPF_CFLAGS := -O2 -g -Wall -Werror

.PHONY: all generate build tidy clean

all: build

tidy:
	$(GO) mod tidy

# 用 bpf2go 编译 eBPF C 源码并生成 Go 绑定（等价原项目的 skeleton 生成步骤）
# 注：通过 go run 直接调用时无 go generate 提供的 GOPACKAGE 环境变量，
# 必须显式指定 -go-package（即 internal/bpf 的包名 bpf）
generate: tidy
	cd internal/bpf && $(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) -cflags "$(BPF_CFLAGS) $(CLANG_BPF_SYS_INCLUDES)" \
		-go-package bpf -type Message Xdp ../../bpf/ruport_xdp.bpf.c
	cd internal/bpf && $(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) -cflags "$(BPF_CFLAGS) $(CLANG_BPF_SYS_INCLUDES)" \
		-go-package bpf -type Router Tc ../../bpf/ruport_tc.bpf.c

build: generate
	$(GO) build -o ruport ./cmd/ruport
	$(GO) build -o c3 ./cmd/c3

clean:
	rm -f ruport c3
	rm -f internal/bpf/*_bpfel.go internal/bpf/*_bpfel.o
	rm -f internal/bpf/*_bpfeb.go internal/bpf/*_bpfeb.o
