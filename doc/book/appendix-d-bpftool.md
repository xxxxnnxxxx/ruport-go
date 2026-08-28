# 附录 D · bpftool 命令速查

> 定位：你在内核侧的眼睛。通用 flag：`-j` JSON、`-p` pretty、
> `-d` 调试。调试方法论见第 15 章。

## prog（程序）

```bash
bpftool prog show                                  # 全部：id/type/name/tag
bpftool prog show name xdp_parse                   # 按名过滤
bpftool prog dump xlated id <ID>                   # 验证后指令（含内核注释）
bpftool prog dump xlated id <ID> linum             # 关联源码行
bpftool prog dump jited  id <ID>                   # JIT 本机码
bpftool prog pin id <ID> /sys/fs/bpf/xx
bpftool prog load file.o /sys/fs/bpf/xx            # 命令行加载（无需自写loader）
bpftool prog run id <ID> data_in in.bin data_out out.bin repeat 10   # test_run
```

## map（第 4/13 章实验的主力）

```bash
bpftool map show                                   # / show name router_map
bpftool map dump name <M>                          # 全量原始字节（布局对账神器）
bpftool map dump id <ID>
bpftool map lookup keyed name <M> key hex 0100007f # 指定 key（hex）
bpftool map update name <M> key hex .. value hex ..
bpftool map delete name <M> key hex ..
bpftool map getnext name <M> key hex ..            # 迭代游标
bpftool map peek name <Q>                          # queue/stack
bpftool map pin name <M> /sys/fs/bpf/xx
bpftool map create name xx type hash key 8 value 16 entries 1024
```

## link / net / cgroup / perf（挂载可见性）

```bash
bpftool link show                                  # link 化挂载 + pinned 路径
bpftool link pin id <ID> /sys/fs/bpf/xx
bpftool link detach id <ID>
bpftool net show                                   # xdp/tc/flow总览（动线B第一步）
bpftool net detach dev eth0 xdp
bpftool cgroup tree /sys/fs/cgroup                 # cgroup 挂载树
bpftool perf show                                  # perf_event 类挂载（kprobe等）
```

## btf / feature / iter

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c        # > vmlinux.h
bpftool btf dump file prog.o format c                          # 自查 .o 类型
bpftool btf dump file /sys/kernel/btf/vmlinux format raw | head
bpftool feature probe                             # 能力摘要
bpftool feature probe full                        # 全量
bpftool feature probe map_type name ringbuf       # 单点：map/prog/helper
bpftool feature probe macro                       # 输出 C 宏（可 include）
bpftool iter pin <bpf.o> <link-name> /sys/fs/bpf/xx && cat /sys/fs/bpf/xx   # iter dump
```

## 高频组合拳

```bash
# 我的程序健康吗（分诊三连，第15章）
sudo bpftool prog show && sudo bpftool map show && sudo bpftool net show

# 性能定位（5.8+）
echo 1 | sudo tee /proc/sys/kernel/bpf_stats_enabled
sudo bpftool prog show     # 看 run_time_ns / run_cnt

# JSON + jq
sudo bpftool -j prog show | jq '.[] | select(.name=="xdp_parse")'
```
