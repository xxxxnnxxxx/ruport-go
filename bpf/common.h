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

#pragma pack()

#endif
