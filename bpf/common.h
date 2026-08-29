// ruport-go eBPF 公共类型定义，与原 ruport 项目 types.h 保持一致。
#ifndef __RUPORT_COMMON_H_
#define __RUPORT_COMMON_H_

#include <linux/types.h>

#define LEN_DEFAULT_BUF 100
#define MAX_MAP_ENTRIES 1024

#pragma pack(1)

struct Message {
  __be16 ins;       // 指令
  __be32 cip;       // 控制服务器IP
  __be16 cport;     // 控制服务器端口
  __be16 connport;  // 通讯端口，通过这个端口出网
  __be16 nativeport;  // 本地端口，实际提供功能的端口
  unsigned char ext[LEN_DEFAULT_BUF];  // 附带的缓存数据
};

struct Router {
  __be32 cip;         // 控制端IP
  __be16 cport;       // 控制端口
  __be16 connport;    // 通讯端口，通过这个端口出网
  __be16 nativeport;  // 本地端口，实际提供功能的端口
};

// netns 隐藏模式的全局配置（config_map，key 恒为 0，由用户态注入）：
// nativeip 为 0 表示传统模式（只改端口）；非 0 时 ingress 做 DNAT 到
// netns 内服务地址，egress 对来自 nativeip 的回包做 SNAT 回 hostip。
struct Config {
  __be32 nativeip;    // netns 内服务地址（如 10.0.0.2）
  __be32 hostip;      // 宿主对外地址（回包 SNAT 的源 IP）
};

#pragma pack()

#endif
