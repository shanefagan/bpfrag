/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * bpfrag - a "vmlinux.h lite" for the BPF side.
 *
 * Copyright (C) 2025-2026 Shane Fagan
 *
 * We deliberately avoid a generated vmlinux.h and the kernel uapi headers so
 * the BPF object builds with nothing but clang and the libbpf headers that
 * libbpf-cargo ships. Kernel-internal structs are declared with only the
 * fields we touch and marked preserve_access_index, so libbpf relocates the
 * field offsets against the running kernel's BTF at load time (CO-RE).
 */
#ifndef __BPFRAG_VMLINUX_LITE_H
#define __BPFRAG_VMLINUX_LITE_H

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef _Bool bool;
#define true 1
#define false 0

/* uapi: enum bpf_map_type (subset) */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 10
#define BPF_MAP_TYPE_RINGBUF 27

/* uapi: map update flags */
#define BPF_ANY 0
#define BPF_NOEXIST 1

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_HLEN 14
/* tcx verdict: carry on to the next tcx program and then any classic tc
 * filters (a CAKE setup's IFB redirect, say). TC_ACT_OK would be TCX_PASS,
 * which accepts the packet and skips all of those. */
#define TCX_NEXT -1
#define TC_PRIO_INTERACTIVE 6
#define TC_PRIO_BULK 2
#define MSG_PEEK 0x2
#define MSG_ERRQUEUE 0x2000

/*
 * uapi: struct __sk_buff. This is the stable BPF context ABI, accesses are
 * rewritten by the verifier, so the layout must match uapi exactly. We only
 * need the prefix up to data_end.
 */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
};

/* Forward declarations referenced by bpf_helper_defs.h */
struct bpf_sock;
struct bpf_sock_tuple;
struct bpf_map;
struct pt_regs;

/* ---- Kernel internal types (CO-RE relocated) ---------------------------- */
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct net_device {
	int ifindex;
};

struct dst_entry {
	/* lives in an anonymous union on newer kernels; CO-RE finds it */
	struct net_device *dev;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be32 u6_addr32[4];
	} in6_u;
};

struct sock_common {
	/* these live inside anonymous unions/structs in the kernel */
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	/* only with CONFIG_IPV6: check bpf_core_field_exists() first */
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
	struct dst_entry *sk_dst_cache;
};

struct task_struct {
	int pid;
	int tgid;
};

#pragma clang attribute pop

/* ---- Wire formats (NOT relocated) --------------------------------------- */

struct iphdr {
	__u8 ver_ihl; /* version:4 ihl:4 (network order nibble layout) */
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__be32 saddr;
	__be32 daddr;
};

struct ipv6hdr {
	__u8 vtc_flow[4]; /* version:4 traffic class:8 flow label:20 */
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
};

/* the first four bytes of a TCP or UDP header */
struct l4ports {
	__be16 source;
	__be16 dest;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__u16 check;
};

#endif /* __BPFRAG_VMLINUX_LITE_H */
