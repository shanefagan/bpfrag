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
 * Hooks (kernel 6.6+):
 *   raw_tp/sock_send_length, raw_tp/sock_recv_length  UDP counting per process
 *   raw_tp/sched_process_exit                         game exit -> revert now
 *   tc egress (tcx link)                              DSCP marking
 *   tc ingress (tcx link)                             arrival gaps per game port
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

/* the current game: its ports are learned, marked and measured */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_WATCH);
	__type(key, __u32);
	__type(value, __u8);
} game_tgids SEC(".maps");

/* local UDP port -> owning game, learned from the send hook */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PORTS);
	__type(key, __u32);
	__type(value, struct game_port);
} game_ports SEC(".maps");

/*
 * ifindex -> interface the marker is attached to: its L2 header length and
 * a count of game packets leaving through it, so userspace can tell which
 * link the game really uses.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_IFACES);
	__type(key, __u32);
	__type(value, struct mark_iface);
} mark_ifaces SEC(".maps");

/* ifindex -> interface the arrival meter is attached to (l2_len only) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_IFACES);
	__type(key, __u32);
	__type(value, struct mark_iface);
} rx_ifaces SEC(".maps");

/* local game port -> arrival gaps (cleared by userspace per match) */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PORTS);
	__type(key, __u32);
	__type(value, struct port_rx);
} port_rx SEC(".maps");

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
	if (bpf_map_lookup_elem(&game_tgids, &tgid)) {
		__u32 port = BPF_CORE_READ(sk, __sk_common.skc_num);
		struct game_port *cur;

		if (!port)
			return;
		cur = bpf_map_lookup_elem(&game_ports, &port);
		if (cur && cur->tgid == tgid)
			return; /* already known: a lookup is far cheaper than an update */

		struct game_port pm = {
			.tgid = tgid,
		};
		bpf_map_update_elem(&game_ports, &port, &pm, BPF_ANY);
	}
}

/* ---- UDP counting: generic socket tracepoints ---------------------------- */

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
 * Is this local port the current game's? Only while its owner is still in
 * game_tgids: the moment userspace drops the game this stops matching, even
 * before game_ports is cleaned.
 */
static __always_inline bool game_owns(__u32 port)
{
	struct game_port *pm = bpf_map_lookup_elem(&game_ports, &port);

	return pm && bpf_map_lookup_elem(&game_tgids, &pm->tgid);
}

/* Is this a game's port? Counts the packet against the interface if so. */
static __always_inline bool is_game_port(__be16 sport, struct mark_iface *mi)
{
	if (!game_owns(bpf_ntohs(sport)))
		return false;
	__sync_fetch_and_add(&mi->game_pkts, 1);
	stat_inc(STAT_TC_SEEN);
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
	struct mark_iface *mi;
	__u32 l2;

	mi = bpf_map_lookup_elem(&mark_ifaces, &ifindex);
	if (!mi)
		return TC_ACT_OK;
	/* zero or Ethernet, so packet offsets stay constants for the verifier */
	l2 = mi->l2_len ? ETH_HLEN : 0;

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
		if (!is_game_port(udp->source, mi))
			return TC_ACT_OK;

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
		if (!is_game_port(udp->source, mi))
			return TC_ACT_OK;

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

/* ---- tc ingress: arrival gaps on the game's ports ------------------------ */

static __always_inline void record_arrival(__u32 port)
{
	struct port_rx *pr = bpf_map_lookup_elem(&port_rx, &port);
	__u64 now = bpf_ktime_get_ns(), last, gap, ms;

	if (!pr) {
		struct port_rx zero = {};

		bpf_map_update_elem(&port_rx, &port, &zero, BPF_NOEXIST);
		pr = bpf_map_lookup_elem(&port_rx, &port);
		if (!pr)
			return;
	}
	__sync_fetch_and_add(&pr->pkts, 1);
	last = pr->last_ns;
	pr->last_ns = now;
	if (!last || now <= last)
		return;
	gap = now - last;
	ms = gap / 1000000;
	if (ms >= GAP_IDLE_MS)
		return; /* the flow paused; not a stall */
	if (ms >= GAP_STALL_MS)
		pr->stalls++;
	if (gap > pr->max_gap_ns)
		pr->max_gap_ns = gap;
	if (ms >= GAP_BUCKETS - 1)
		ms = GAP_BUCKETS - 1;
	pr->hist[ms & (GAP_BUCKETS - 1)]++;
}

SEC("tc")
int bpfrag_rx(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 ifindex = skb->ifindex;
	struct mark_iface *mi;
	struct udphdr *udp;
	__u32 l2, port;

	mi = bpf_map_lookup_elem(&rx_ifaces, &ifindex);
	if (!mi)
		return TC_ACT_OK;
	l2 = mi->l2_len ? ETH_HLEN : 0;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + l2;
		__u32 ihl;

		if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_UDP)
			return TC_ACT_OK;
		if (ip->frag_off & bpf_htons(0x1fff))
			return TC_ACT_OK;
		ihl = (ip->ver_ihl & 0x0f) * 4;
		if (ihl < sizeof(struct iphdr))
			return TC_ACT_OK;
		udp = (void *)ip + ihl;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + l2;

		if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_UDP)
			return TC_ACT_OK;
		udp = (void *)(ip6 + 1);
	} else {
		return TC_ACT_OK;
	}
	if ((void *)(udp + 1) > data_end)
		return TC_ACT_OK;
	port = bpf_ntohs(udp->dest);
	if (!game_owns(port))
		return TC_ACT_OK;
	record_arrival(port);
	return TC_ACT_OK;
}
