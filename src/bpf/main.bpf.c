// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * bpfrag - eBPF side.
 *
 * Copyright (C) 2025-2026 Shane Fagan
 *
 * Keep the kernel side dumb and cheap: count traffic per process, tell
 * userspace when a watched game exits, rewrite DSCP on packets leaving a
 * game's UDP ports, and demote the flows of processes userspace has
 * declared bulk. All the "is this a match, which tier" decisions live in
 * the Rust side, where they are easy to test and cannot upset the verifier.
 *
 * Hooks (kernel 6.6+):
 *   raw_tp/sock_send_length, raw_tp/sock_recv_length  UDP and TCP counting per process
 *   raw_tp/sched_process_exit                         game exit -> revert now
 *   tc egress (tcx link)                              DSCP marking
 *   tc ingress (tcx link)                             arrival gaps per game port,
 *                                                     bulk flows demoted
 *
 * The tc programs only observe or rewrite, and always return TCX_NEXT so
 * whatever else is on the interface (other tcx programs, classic filters
 * such as a CAKE setup's redirect to its IFB) still sees every packet.
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
const volatile __u8 bulk_dscp = 1;		/* LE: RFC 8622 lower effort */

/*
 * Runtime switches, written by userspace through the skeleton's mmapped
 * .bss (as sched_ext schedulers do): plain memory reads on the hot paths,
 * no map lookup. TCP is only counted while a match is on, and bulk flows
 * are only learned and looked up while some process is bulk.
 */
volatile bool count_tcp = false;
volatile bool bulk_on = false;

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

/* processes userspace declared bulk for this match */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_WATCH);
	__type(key, __u32);
	__type(value, __u8);
} bulk_tgids SEC(".maps");

/* their sockets, learned in the counting hooks, matched by the tc programs */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_BULK_FLOWS);
	__type(key, struct flow_key);
	__type(value, struct bulk_flow);
} bulk_flows SEC(".maps");



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

/*
 * Remember a bulk process's socket so the tc programs can find its packets.
 * IPv4-mapped IPv6 sockets send IPv4 packets, so they are keyed as IPv4.
 */
static __always_inline void learn_bulk_flow(struct sock *sk, unsigned short family,
					    __u16 proto, __u32 tgid)
{
	struct bulk_flow v = { .tgid = tgid };
	struct flow_key k = {};

	k.proto = proto;
	k.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	k.rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (!k.lport)
		return;
	if (!k.rport) {
		/* unconnected: protocol and local port only */
		if (proto != IPPROTO_UDP)
			return;
	} else if (family == AF_INET6 &&
		   bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) {
		struct in6_addr d = {}, l = {};

		BPF_CORE_READ_INTO(&d, sk, __sk_common.skc_v6_daddr);
		if (d.in6_u.u6_addr32[0] == 0 && d.in6_u.u6_addr32[1] == 0 &&
		    d.in6_u.u6_addr32[2] == bpf_htonl(0x0000ffff)) {
			k.family = AF_INET;
			k.raddr[0] = d.in6_u.u6_addr32[3];
			k.laddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		} else {
			BPF_CORE_READ_INTO(&l, sk, __sk_common.skc_v6_rcv_saddr);
			k.family = AF_INET6;
			__builtin_memcpy(k.raddr, d.in6_u.u6_addr32, 16);
			__builtin_memcpy(k.laddr, l.in6_u.u6_addr32, 16);
		}
	} else if (family == AF_INET) {
		k.family = AF_INET;
		k.raddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		k.laddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	} else {
		return;
	}
	if (bpf_map_lookup_elem(&bulk_flows, &k))
		return; /* known: a lookup is far cheaper than an update */
	bpf_map_update_elem(&bulk_flows, &k, &v, BPF_ANY);
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
	if (proto == IPPROTO_TCP) {
		if (!count_tcp)
			return; /* no match on: nothing needs it */
	} else if (proto != IPPROTO_UDP) {
		return;
	}

	tgid = bpf_get_current_pid_tgid() >> 32;
	if (!tgid)
		return;
	if (bulk_on && bpf_map_lookup_elem(&bulk_tgids, &tgid))
		learn_bulk_flow(sk, family, proto, tgid);

	st = bpf_map_lookup_elem(&proc_stats, &tgid);
	if (!st) {
		struct proc_stats zero = {};

		bpf_map_update_elem(&proc_stats, &tgid, &zero, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&proc_stats, &tgid);
		if (!st)
			return;
	}

	/* per-CPU value: plain increments are safe */
	if (proto == IPPROTO_TCP) {
		if (tx)
			st->tcp_tx_bytes += ret;
		else
			st->tcp_rx_bytes += ret;
		return;
	}
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

/* ---- counting: generic socket tracepoints -------------------------------- */

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

/* Set an IPv4 packet's DSCP, keeping ECN, and fix the header checksum. */
static __always_inline void set_dscp4(struct __sk_buff *skb, __u32 l2, __u8 old_tos, __u8 val)
{
	__u8 new_tos = (val << 2) | (old_tos & 0x3);

	if (new_tos == old_tos)
		return;
	bpf_l3_csum_replace(skb, l2 + __builtin_offsetof(struct iphdr, check),
			    bpf_htons(old_tos), bpf_htons(new_tos), 2);
	bpf_skb_store_bytes(skb, l2 + __builtin_offsetof(struct iphdr, tos), &new_tos, 1, 0);
}

/* Set an IPv6 packet's traffic class (b0, b1: its first two bytes), keeping
 * ECN and the flow label. No checksum covers it. */
static __always_inline void set_dscp6(struct __sk_buff *skb, __u32 l2, __u8 b0, __u8 b1, __u8 val)
{
	__u8 old_tc = ((b0 & 0x0f) << 4) | (b1 >> 4);
	__u8 new_tc = (val << 2) | (old_tc & 0x3);
	__u8 nb[2];

	if (new_tc == old_tc)
		return;
	nb[0] = (b0 & 0xf0) | (new_tc >> 4);
	nb[1] = (b1 & 0x0f) | ((new_tc & 0x0f) << 4);
	bpf_skb_store_bytes(skb, l2, nb, 2, 0);
}

static __always_inline bool bulk_active(void)
{
	return bulk_on;
}

/* Is this a bulk process's flow? Tries the exact socket, then (for UDP) an
 * unconnected socket on the same local port. */
static __always_inline bool is_bulk_flow(struct flow_key *k)
{
	struct flow_key any = {};

	if (bpf_map_lookup_elem(&bulk_flows, k))
		return true;
	if (k->proto != IPPROTO_UDP)
		return false;
	any.proto = IPPROTO_UDP;
	any.lport = k->lport;
	return bpf_map_lookup_elem(&bulk_flows, &any) != NULL;
}

/* A game packet was marked: the interactive band for pfifo_fast & friends. */
static __always_inline int game_marked(struct __sk_buff *skb)
{
	if (set_priority && skb->priority == 0)
		skb->priority = TC_PRIO_INTERACTIVE;
	stat_inc(STAT_DSCP_MARKED);
	return TCX_NEXT;
}

static __always_inline int bulk_marked(struct __sk_buff *skb)
{
	if (set_priority && skb->priority == 0)
		skb->priority = TC_PRIO_BULK;
	stat_inc(STAT_BULK_MARKED);
	return TCX_NEXT;
}

/*
 * Egress: game packets (UDP from the game's ports) get the game's DSCP;
 * packets of a bulk process's flows get the bulk DSCP. Bulk packets an app
 * already marked are always left alone.
 */
SEC("tc")
int bpfrag_dscp(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 ifindex = skb->ifindex;
	struct flow_key k = {};
	struct mark_iface *mi;
	struct l4ports *pt;
	__u32 l2;
	__u8 proto;

	mi = bpf_map_lookup_elem(&mark_ifaces, &ifindex);
	if (!mi)
		return TCX_NEXT;
	/* zero or Ethernet, so packet offsets stay constants for the verifier */
	l2 = mi->l2_len ? ETH_HLEN : 0;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + l2;
		__u8 old_tos;
		__u32 ihl;

		if ((void *)(ip + 1) > data_end)
			return TCX_NEXT;
		proto = ip->protocol;
		if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
			return TCX_NEXT;
		if (ip->frag_off & bpf_htons(0x1fff))
			return TCX_NEXT; /* non-first fragment, no ports */
		ihl = (ip->ver_ihl & 0x0f) * 4;
		if (ihl < sizeof(struct iphdr))
			return TCX_NEXT;
		pt = (void *)ip + ihl;
		if ((void *)(pt + 1) > data_end)
			return TCX_NEXT;
		old_tos = ip->tos;
		if (proto == IPPROTO_UDP && is_game_port(pt->source, mi)) {
			if (!want_rewrite(old_tos))
				return TCX_NEXT;
			set_dscp4(skb, l2, old_tos, dscp);
			return game_marked(skb);
		}
		if (!bulk_active() || (old_tos >> 2))
			return TCX_NEXT;
		k.family = AF_INET;
		k.proto = proto;
		k.lport = bpf_ntohs(pt->source);
		k.rport = bpf_ntohs(pt->dest);
		k.laddr[0] = ip->saddr;
		k.raddr[0] = ip->daddr;
		if (!is_bulk_flow(&k))
			return TCX_NEXT;
		set_dscp4(skb, l2, old_tos, bulk_dscp);
		return bulk_marked(skb);
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + l2;
		__u8 b0, b1, old_tc;

		if ((void *)(ip6 + 1) > data_end)
			return TCX_NEXT;
		proto = ip6->nexthdr;
		if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
			return TCX_NEXT; /* extension headers: not worth it */
		pt = (void *)(ip6 + 1);
		if ((void *)(pt + 1) > data_end)
			return TCX_NEXT;
		b0 = ip6->vtc_flow[0];
		b1 = ip6->vtc_flow[1];
		old_tc = ((b0 & 0x0f) << 4) | (b1 >> 4);
		if (proto == IPPROTO_UDP && is_game_port(pt->source, mi)) {
			if (!want_rewrite(old_tc))
				return TCX_NEXT;
			set_dscp6(skb, l2, b0, b1, dscp);
			return game_marked(skb);
		}
		if (!bulk_active() || (old_tc >> 2))
			return TCX_NEXT;
		k.family = AF_INET6;
		k.proto = proto;
		k.lport = bpf_ntohs(pt->source);
		k.rport = bpf_ntohs(pt->dest);
		__builtin_memcpy(k.laddr, ip6->saddr, 16);
		__builtin_memcpy(k.raddr, ip6->daddr, 16);
		if (!is_bulk_flow(&k))
			return TCX_NEXT;
		set_dscp6(skb, l2, b0, b1, bulk_dscp);
		return bulk_marked(skb);
	}
	return TCX_NEXT;
}

/* ---- tc ingress: arrival gaps, bulk downloads ---------------------------- */

static __always_inline void count_gap(struct port_rx *pr, __u64 gap)
{
	__u64 ms = gap / 1000000;

	if (ms >= GAP_STALL_MS)
		pr->stalls++;
	if (gap > pr->max_gap_ns)
		pr->max_gap_ns = gap;
	if (ms >= GAP_BUCKETS - 1)
		ms = GAP_BUCKETS - 1;
	pr->hist[ms & (GAP_BUCKETS - 1)]++;
}

static __always_inline void record_arrival(__u32 port, __u32 napi_id)
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
	/* The receive queue's NAPI instance (0 if none, e.g. veth). It only
	 * changes if RSS moves the flow, so the latest one is the answer. */
	if (napi_id && pr->napi_id != napi_id)
		pr->napi_id = napi_id;
	last = pr->last_ns;
	pr->last_ns = now;
	if (!last || now <= last)
		return;
	gap = now - last;
	ms = gap / 1000000;
	/*
	 * A stall is the flow going quiet and then coming back at game rate.
	 * From the first slow gap, hold everything until GAP_RESUME fast gaps
	 * in a row say the game's tick rate is back, then count the quiet
	 * stretch as one gap. If it lasted GAP_IDLE_MS or more it was a lobby,
	 * a menu or loading (games keep sending keepalives there, Deadlock
	 * about one a second), and isn't counted at all.
	 */
	if (ms >= GAP_STALL_MS) {
		pr->held_ns += pr->resume_ns + gap;
		pr->resume_ns = 0;
		pr->resume_n = 0;
		return;
	}
	if (!pr->held_ns) {
		count_gap(pr, gap);
		return;
	}
	pr->resume_ns += gap;
	if (++pr->resume_n < GAP_RESUME)
		return;
	if (pr->held_ns < (__u64)GAP_IDLE_MS * 1000000)
		count_gap(pr, pr->held_ns);
	pr->held_ns = 0;
	pr->resume_ns = 0;
	pr->resume_n = 0;
}

/*
 * Ingress: time arrivals on the game's ports, and demote incoming packets of
 * bulk flows. This runs before classic tc filters, so a desktop CAKE setup's
 * redirect to its IFB sees the new mark and puts the download in its Bulk
 * tin. Packets the sender marked are left alone, as on egress.
 */
SEC("tc")
int bpfrag_rx(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 ifindex = skb->ifindex;
	struct flow_key k = {};
	struct mark_iface *mi;
	struct l4ports *pt;
	__u32 l2;
	__u8 proto;

	mi = bpf_map_lookup_elem(&rx_ifaces, &ifindex);
	if (!mi)
		return TCX_NEXT;
	l2 = mi->l2_len ? ETH_HLEN : 0;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + l2;
		__u8 old_tos;
		__u32 ihl;

		if ((void *)(ip + 1) > data_end)
			return TCX_NEXT;
		proto = ip->protocol;
		if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
			return TCX_NEXT;
		if (ip->frag_off & bpf_htons(0x1fff))
			return TCX_NEXT;
		ihl = (ip->ver_ihl & 0x0f) * 4;
		if (ihl < sizeof(struct iphdr))
			return TCX_NEXT;
		pt = (void *)ip + ihl;
		if ((void *)(pt + 1) > data_end)
			return TCX_NEXT;
		if (proto == IPPROTO_UDP && game_owns(bpf_ntohs(pt->dest))) {
			record_arrival(bpf_ntohs(pt->dest), skb->napi_id);
			return TCX_NEXT;
		}
		old_tos = ip->tos;
		if (!bulk_active() || (old_tos >> 2))
			return TCX_NEXT;
		k.family = AF_INET;
		k.proto = proto;
		k.lport = bpf_ntohs(pt->dest);
		k.rport = bpf_ntohs(pt->source);
		k.laddr[0] = ip->daddr;
		k.raddr[0] = ip->saddr;
		if (!is_bulk_flow(&k))
			return TCX_NEXT;
		set_dscp4(skb, l2, old_tos, bulk_dscp);
		stat_inc(STAT_BULK_MARKED);
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + l2;
		__u8 b0, b1;

		if ((void *)(ip6 + 1) > data_end)
			return TCX_NEXT;
		proto = ip6->nexthdr;
		if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
			return TCX_NEXT;
		pt = (void *)(ip6 + 1);
		if ((void *)(pt + 1) > data_end)
			return TCX_NEXT;
		if (proto == IPPROTO_UDP && game_owns(bpf_ntohs(pt->dest))) {
			record_arrival(bpf_ntohs(pt->dest), skb->napi_id);
			return TCX_NEXT;
		}
		b0 = ip6->vtc_flow[0];
		b1 = ip6->vtc_flow[1];
		if (!bulk_active() || ((((b0 & 0x0f) << 4) | (b1 >> 4)) >> 2))
			return TCX_NEXT;
		k.family = AF_INET6;
		k.proto = proto;
		k.lport = bpf_ntohs(pt->dest);
		k.rport = bpf_ntohs(pt->source);
		__builtin_memcpy(k.laddr, ip6->daddr, 16);
		__builtin_memcpy(k.raddr, ip6->saddr, 16);
		if (!is_bulk_flow(&k))
			return TCX_NEXT;
		set_dscp6(skb, l2, b0, b1, bulk_dscp);
		stat_inc(STAT_BULK_MARKED);
	}
	return TCX_NEXT;
}
