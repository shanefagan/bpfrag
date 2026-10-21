// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * bpfrag - eBPF side.
 *
 * Copyright (C) 2025-2026 Shane Fagan
 *
 * Keep the kernel side dumb and cheap: count UDP datagrams per process, tell
 * userspace when a watched game exits, and rewrite DSCP on packets leaving a
 * game's UDP ports. All the "is this a match, which tier" decisions live in
 * the Rust side, where they are easy to test and cannot upset the verifier.
 *
 * Hooks:
 *   raw_tp/sock_send_length, raw_tp/sock_recv_length  primary (kernel >= 6.4)
 *   fexit/udp{,v6}_{send,recv}msg                     fallback (>= 5.17)
 *   raw_tp/sched_process_exit                         game exit -> revert now
 *   tc egress (tcx link, or legacy cls_bpf)           DSCP marking
 */
#include "vmlinux_lite.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "intf.h"

/* Dual licensed: the kernel needs a GPL-compatible string for GPL-only
 * helpers such as bpf_probe_read_kernel(), which BPF_CORE_READ uses. */
char _license[] SEC("license") = "Dual MIT/GPL";

/* Tunables, set by userspace before load (frozen afterwards). */
const volatile __u8 dscp = 32;			/* CS4: RFC 4594 real-time interactive */
const volatile bool dscp_override = false;	/* rewrite app-chosen DSCP too */
const volatile bool set_priority = true;	/* skb->priority = TC_PRIO_INTERACTIVE */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_STATS);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);
	__type(value, struct proc_stats);
} proc_stats SEC(".maps");

/* tgids userspace wants exit notifications for */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_WATCH);
	__type(key, __u32);
	__type(value, __u8);
} watch_tgids SEC(".maps");

/* tgids whose egress UDP gets DSCP marked */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_WATCH);
	__type(key, __u32);
	__type(value, __u8);
} mark_tgids SEC(".maps");

/* local UDP port -> owning game, learned from the send hook */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PORTS);
	__type(key, __u32);
	__type(value, struct port_mark);
} mark_ports SEC(".maps");

/* ifindex -> L2 header length (14 Ethernet/Wi-Fi, 0 for wg/tun/ppp) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_IFACES);
	__type(key, __u32);
	__type(value, __u32);
} if_l2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} events SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);

	if (v)
		(*v)++;
}

static __always_inline void account(struct sock *sk, long ret, bool tx)
{
	struct proc_stats *st;
	unsigned short family;
	__u16 proto;
	__u32 tgid;

	if (ret <= 0 || !sk)
		return;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return;
	proto = BPF_CORE_READ(sk, sk_protocol);
	if (proto != IPPROTO_UDP)
		return;

	tgid = bpf_get_current_pid_tgid() >> 32;
	if (!tgid)
		return;

	st = bpf_map_lookup_elem(&proc_stats, &tgid);
	if (!st) {
		struct proc_stats zero = {};

		bpf_map_update_elem(&proc_stats, &tgid, &zero, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&proc_stats, &tgid);
		if (!st)
			return;
	}

	/* per-CPU value: plain increments are safe */
	if (!tx) {
		st->rx_pkts++;
		st->rx_bytes += ret;
		return;
	}

	/*
	 * Connected sockets cache their route; remember the device. Routes
	 * rarely change, so refresh every 64th send rather than every send.
	 */
	if ((st->tx_pkts & 63) == 0) {
		struct dst_entry *dst = BPF_CORE_READ(sk, sk_dst_cache);

		if (dst) {
			int ifindex = BPF_CORE_READ(dst, dev, ifindex);

			if (ifindex > 0)
				st->ifindex = ifindex;
		}
	}
	st->tx_pkts++;
	st->tx_bytes += ret;

	/* learn the local port of a game socket so tc can mark it */
	if (bpf_map_lookup_elem(&mark_tgids, &tgid)) {
		__u32 port = BPF_CORE_READ(sk, __sk_common.skc_num);
		struct port_mark *cur;

		if (!port)
			return;
		cur = bpf_map_lookup_elem(&mark_ports, &port);
		if (cur && cur->tgid == tgid)
			return; /* already known: a lookup is far cheaper than an update */

		struct port_mark pm = {
			.tgid = tgid,
			.last_ns = bpf_ktime_get_ns(),
		};
		bpf_map_update_elem(&mark_ports, &port, &pm, BPF_ANY);
	}
}

/* ---- primary: generic socket tracepoints (>= 6.4) ------------------------ */

SEC("raw_tp/sock_send_length")
int BPF_PROG(bpfrag_send_tp, struct sock *sk, int ret, int flags)
{
	account(sk, ret, true);
	return 0;
}

SEC("raw_tp/sock_recv_length")
int BPF_PROG(bpfrag_recv_tp, struct sock *sk, int ret, int flags)
{
	if (flags & (MSG_PEEK | MSG_ERRQUEUE))
		return 0;
	account(sk, ret, false);
	return 0;
}

/*
 * ---- fallback: fexit on the UDP functions (5.17 .. 6.3) -------------------
 * bpf_get_func_arg()/bpf_get_func_ret() keep us independent of the argument
 * count, which changed for udp_recvmsg in 5.19.
 */

static __always_inline int fexit_common(void *ctx, bool tx)
{
	__u64 sk = 0, ret = 0;

	if (bpf_get_func_arg(ctx, 0, &sk))
		return 0;
	if (bpf_get_func_ret(ctx, &ret))
		return 0;
	account((struct sock *)sk, (long)(int)ret, tx);
	return 0;
}

SEC("fexit/udp_sendmsg")
int bpfrag_udp_sendmsg(void *ctx) { return fexit_common(ctx, true); }

SEC("fexit/udpv6_sendmsg")
int bpfrag_udpv6_sendmsg(void *ctx) { return fexit_common(ctx, true); }

SEC("fexit/udp_recvmsg")
int bpfrag_udp_recvmsg(void *ctx) { return fexit_common(ctx, false); }

SEC("fexit/udpv6_recvmsg")
int bpfrag_udpv6_recvmsg(void *ctx) { return fexit_common(ctx, false); }

/* ---- process exit -------------------------------------------------------- */

SEC("raw_tp/sched_process_exit")
int BPF_PROG(bpfrag_exit, struct task_struct *p)
{
	struct event *e;
	__u32 tgid, pid;

	pid = BPF_CORE_READ(p, pid);
	tgid = BPF_CORE_READ(p, tgid);
	if (pid != tgid)
		return 0; /* only the thread-group leader */

	bpf_map_delete_elem(&proc_stats, &tgid);

	if (!bpf_map_lookup_elem(&watch_tgids, &tgid))
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_EVENTS_DROPPED);
		return 0;
	}
	e->kind = EVENT_EXIT;
	e->tgid = tgid;
	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EXITS);
	return 0;
}

/* ---- tc egress: DSCP marking --------------------------------------------- */

/*
 * Is this a game's port? Also records which device the game's packets
 * actually leave on, so userspace can aim per-interface knobs at it.
 */
static __always_inline bool is_game_port(__be16 sport, __u32 ifindex)
{
	__u32 port = bpf_ntohs(sport);
	struct port_mark *pm = bpf_map_lookup_elem(&mark_ports, &port);

	if (!pm)
		return false;
	/*
	 * Only while the owner is still marked: the moment userspace drops
	 * the game from mark_tgids (or a stale legacy filter outlives a crash)
	 * marking stops, even before mark_ports is cleaned up.
	 */
	if (!bpf_map_lookup_elem(&mark_tgids, &pm->tgid))
		return false;
	pm->ifindex = ifindex;
	pm->last_ns = bpf_ktime_get_ns();
	return true;
}

/* returns false if the app already chose a DSCP and we respect that */
static __always_inline bool want_rewrite(__u8 old_tc)
{
	if (dscp_override || !(old_tc >> 2))
		return true;
	stat_inc(STAT_DSCP_KEPT);
	return false;
}

SEC("tc")
int bpfrag_dscp(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 ifindex = skb->ifindex;
	__u32 *l2p, l2;

	l2p = bpf_map_lookup_elem(&if_l2, &ifindex);
	if (!l2p)
		return TC_ACT_OK;
	l2 = *l2p ? ETH_HLEN : 0;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + l2;
		struct udphdr *udp;
		__u8 old_tos, new_tos;
		__u32 ihl;

		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;
		if (ip->protocol != IPPROTO_UDP)
			return TC_ACT_OK;
		if (ip->frag_off & bpf_htons(0x1fff))
			return TC_ACT_OK; /* non-first fragment, no UDP header */
		ihl = (ip->ver_ihl & 0x0f) * 4;
		if (ihl < sizeof(struct iphdr))
			return TC_ACT_OK;
		udp = (void *)ip + ihl;
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		if (!is_game_port(udp->source, ifindex))
			return TC_ACT_OK;
		stat_inc(STAT_TC_SEEN);

		old_tos = ip->tos;
		if (!want_rewrite(old_tos))
			return TC_ACT_OK;
		new_tos = (dscp << 2) | (old_tos & 0x3); /* keep ECN bits */
		if (new_tos != old_tos) {
			bpf_l3_csum_replace(skb, l2 + __builtin_offsetof(struct iphdr, check),
					    bpf_htons(old_tos), bpf_htons(new_tos), 2);
			bpf_skb_store_bytes(skb, l2 + __builtin_offsetof(struct iphdr, tos),
					    &new_tos, 1, 0);
		}
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + l2;
		struct udphdr *udp;
		__u8 b0, b1, old_tc, new_tc;
		__u8 nb[2];

		if ((void *)(ip6 + 1) > data_end)
			return TC_ACT_OK;
		if (ip6->nexthdr != IPPROTO_UDP)
			return TC_ACT_OK; /* extension headers: not worth it */
		udp = (void *)(ip6 + 1);
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		if (!is_game_port(udp->source, ifindex))
			return TC_ACT_OK;
		stat_inc(STAT_TC_SEEN);

		b0 = ip6->vtc_flow[0];
		b1 = ip6->vtc_flow[1];
		old_tc = ((b0 & 0x0f) << 4) | (b1 >> 4);
		if (!want_rewrite(old_tc))
			return TC_ACT_OK;
		new_tc = (dscp << 2) | (old_tc & 0x3);
		if (new_tc != old_tc) {
			/* traffic class is not covered by any checksum */
			nb[0] = (b0 & 0xf0) | (new_tc >> 4);
			nb[1] = (b1 & 0x0f) | ((new_tc & 0x0f) << 4);
			bpf_skb_store_bytes(skb, l2, nb, 2, 0);
		}
	} else {
		return TC_ACT_OK;
	}

	/* pfifo_fast & friends: send it through the interactive band */
	if (set_priority && skb->priority == 0)
		skb->priority = TC_PRIO_INTERACTIVE;

	stat_inc(STAT_DSCP_MARKED);
	return TC_ACT_OK;
}
