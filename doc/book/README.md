# 《eBPF 从入门到精通》

基于 cilium/ebpf 与 ruport-go 实战的系统学习用书。
**按学习旅程组织**（问题驱动、机制按需引入），全部速查表在附录。

> **写作契约**：全书权威大纲见 [OUTLINE.md](OUTLINE.md)
> （含写作铁律、逐章小节、素材映射），写作过程严格对照执行，
> 防止跑偏；修改大纲需经确认。

## 目录与进度

- [x] 序言（定位/三条读法/环境/约定）—— [00-preface.md](00-preface.md)

**第一篇 走进 eBPF**
- [x] 第 1 章 内核可编程性的漫长求索（需求四路/安全模型对比/时间线/三条轴线）—— [p1-ch01-history.md](p1-ch01-history.md)
- [x] 第 2 章 第一个程序：从零跑起来（XDP 计数器全闭环/全旅程总地图）—— [p1-ch02-first-program.md](p1-ch02-first-program.md)
- [x] 第 3 章 与验证器初遇（日志解剖/状态推演/包访问三模式）—— [p1-ch03-verifier.md](p1-ch03-verifier.md)

**第二篇 数据之道**
- [x] 第 4 章 让内核把数据交出来（hash-array 行为差/两侧 API/布局字节序三坑）—— [p2-ch04-maps.md](p2-ch04-maps.md)
- [x] 第 5 章 更快、更大、更稳（perCPU/LRU/迭代批量/queue-lpm）—— [p2-ch05-maps-advanced.md](p2-ch05-maps-advanced.md)
- [x] 第 6 章 别再轮询了：事件驱动（ringbuf + openat 监控完整项目）—— [p2-ch06-ringbuf.md](p2-ch06-ringbuf.md)

**第三篇 网络即战场**
- [x] 第 7 章 XDP：最早的那一刀（收包全景地图/迷你防火墙）—— [p3-ch07-xdp.md](p3-ch07-xdp.md)
- [x] 第 8 章 TC：包的手术台（端口改写/增量校验和/端口复用雏形）—— [p3-ch08-tc.md](p3-ch08-tc.md)
- [x] 第 9 章 cgroup 与 socket：容器时代的钩子 —— [p3-ch09-cgroup-socket.md](p3-ch09-cgroup-socket.md)

**第四篇 观测的艺术**
- [x] 第 10 章 看见内核：tracepoint 与 kprobe（断点时序/配对 map 耗时统计）—— [p4-ch10-kprobe.md](p4-ch10-kprobe.md)
- [x] 第 11 章 fentry 与 trampoline（翻译官原理/四兄弟/版本二对比）—— [p4-ch11-fentry.md](p4-ch11-fentry.md)

**第五篇 精通之路**
- [x] 第 12 章 BTF 与 CO-RE（三件套精确原理/vmlinux.h 取舍）—— [p5-ch12-btf-core.md](p5-ch12-btf-core.md)
- [x] 第 13 章 map 的内核实现（hashtab 源码走读/bpftool 验证实验）—— [p5-ch13-map-internals.md](p5-ch13-map-internals.md)
- [x] 第 14 章 Go 工程化：cilium/ebpf 与 bpf2go（生命周期责任矩阵/生产化清单）—— [p5-ch14-go-engineering.md](p5-ch14-go-engineering.md)
- [x] 第 15 章 版本兼容与调试方法论（features 探测/五阶段分诊/四条动线）—— [p5-ch15-compat-debug.md](p5-ch15-compat-debug.md)

**第六篇 实战：ruport-go**（批次 4，待写）
- [x] 第 16 章 从需求到架构（约束映射/三件套推演/数据契约与端口学习）—— [p6-ch16-design.md](p6-ch16-design.md)
- [x] 第 17 章 逐模块精读与端到端联调（含扩展练习与全书结语）—— [p6-ch17-ruport-walkthrough.md](p6-ch17-ruport-walkthrough.md)

**附录**
- [x] 附录 A 程序类型速查表 —— [appendix-a-progtypes.md](appendix-a-progtypes.md)
- [x] 附录 B map 类型速查表 —— [appendix-b-maptypes.md](appendix-b-maptypes.md)
- [x] 附录 C helper 分组速查表 —— [appendix-c-helpers.md](appendix-c-helpers.md)
- [x] 附录 D bpftool 命令速查 —— [appendix-d-bpftool.md](appendix-d-bpftool.md)
- [x] 附录 E 内核版本-特性矩阵 —— [appendix-e-versions.md](appendix-e-versions.md)
- [x] 附录 F 常见报错字典 —— [appendix-f-errors.md](appendix-f-errors.md)
- [x] 附录 G 参考资料与致谢 —— [appendix-g-references.md](appendix-g-references.md)

> **成书状态**：序言 + 六篇 17 章 + 附录 A-G 全部完成（四批交付）。
> 旧的专题文档（doc/00~14）在成书期间作为素材池与速查并存，
> 处置方案待确认后执行（见完成日志）。
