// ruport-go TC 端口复用改写程序，逻辑与原 ruport 项目 ruport.tc.c 保持一致。
// 由 Makefile 调用 cilium/ebpf 的 bpf2go 编译（取代原 bpftool skeleton 流程）。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

#include <stdbool.h>

#include "common.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __be64);
  __type(value, struct Router);
  __uint(max_entries, MAX_MAP_ENTRIES);
} router_map SEC(".maps");

SEC("tc") // rx
int tc_ingress(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;    // IP header offset
    const int l4_off = l3_off + 20; // TCP header offset: l3_off + sizeof(struct iphdr)
    __be32 sum;                     // IP checksum

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data_end < data + l4_off) { // not our packet
        return TC_ACT_OK;
    }

    struct iphdr *ip4 = (struct iphdr *)(data + l3_off);
    if (ip4->protocol != IPPROTO_TCP /* || tcp->dport == 80 */) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = (struct tcphdr *)(data + l4_off);
    if ((void *)(tcph + 1) > data_end) //
      return TC_ACT_OK;

    __be32 sourceIp = ip4->saddr;
    __be16 sourcePort = tcph->source;
    __be16 destPort = tcph->dest;

    __be64 key = (__be64)(((__be64)sourceIp) << 16) + (__be64)sourcePort;

    struct Router *value = bpf_map_lookup_elem(&router_map, &key);
    if (value != 0) {
        /*
        来源数据，保证是控制服务器来的数据
        sourceIP和sourcePort都是控制服务器的地址，并且于之通讯的被控端端口
        并且通讯的目的端口不能为空
        */
        if (sourceIp == value->cip &&
            sourcePort == value->cport &&
            value->nativeport != 0) {

            const __be32 client_port = value->nativeport;
            // 旧端口先零扩展到局部变量再参与 diff：直接从包内 &tcph->dest
            // 读 4 字节会把紧随其后的序列号高 16 位卷进增量，而下面只改写
            // 2 字节端口，校验和会因此出错（对端静默丢弃）
            const __be32 old_port = tcph->dest;
            // SNAT: pod_ip -> cluster_ip, then update L3 and L4 header
            sum = bpf_csum_diff((void *)&old_port, 4, (void *)&client_port, 4, 0);
            bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, dest), (void *)&client_port, 2, 0);
            bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);

            if (value->connport == 0) {
                struct Router tmp;
                __builtin_memcpy(&tmp, value, sizeof(struct Router));
                tmp.connport = destPort;
                bpf_map_update_elem(&router_map, &key, &tmp, BPF_ANY);
            }
        }
    }

    return TC_ACT_OK;
}

SEC("tc") // tx
int tc_egress(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;    // IP header offset
    const int l4_off = l3_off + 20; // TCP header offset: l3_off + sizeof(struct iphdr)

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data_end < data + l4_off) { // not our packet
        return TC_ACT_OK;
    }

    struct iphdr *ip4 = (struct iphdr *)(data + l3_off);
    if (ip4->protocol != IPPROTO_TCP /* || tcp->dport == 80 */) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcph = (struct tcphdr *)(data + l4_off);
    if ((void *)(tcph + 1) > data_end) //
      return TC_ACT_OK;

    __be16 sourcePort = tcph->source;
    __be32 destIp = ip4->daddr;
    __be16 destPort = tcph->dest;

    __be64 key = (__be64)(((__be64)destIp) << 16) + (__be64)destPort;
    struct Router *value = bpf_map_lookup_elem(&router_map, &key);
    if (value != 0) {
        /*
        出网数据，必须保证destIP destPort 是控制端IP和端口，
        出网端口必须指定
        */
        if (destIp == value->cip &&
            destPort == value->cport &&
            value->connport != 0) {

            const __be32 sourceport = value->connport;
            // SNAT: pod_ip -> cluster_ip, then update L3 and L4 header
            bpf_skb_store_bytes(skb, l4_off + offsetof(struct tcphdr, source), (void *)&sourceport, 2, 0);
            // 此处刻意不修 TCP 校验和：本机产生的回包在 TX 校验和卸载开启
            // （默认）时为 CHECKSUM_PARTIAL，字段里只有伪头种子，网卡发送时
            // 会对改写后的新端口重新求和；若再调 bpf_l4_csum_replace 做增量
            // 修正，端口差值会被重复计入（实测回包校验和恒差 0x3A=80-22，
            // 客户端静默丢弃 SYN-ACK）。UAPI 的 struct __sk_buff 不暴露校验
            // 和状态，无法分支判断，故统一不动校验和字段。
            // 运行要求：TX 校验和卸载保持开启（勿 ethtool -K <if> tx off）。

            if (value->nativeport == 0) {
                struct Router tmp;
                __builtin_memcpy(&tmp, value, sizeof(struct Router));
                tmp.nativeport = sourcePort;
                bpf_map_update_elem(&router_map, &key, &tmp, BPF_ANY);
            }
        }
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
