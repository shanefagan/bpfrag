/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * bpfrag - interface shared between the BPF programs and the Rust side.
 * build.rs runs bindgen over this file (-> bpf_intf.rs), so both sides use
 * one definition and there is no hand-written mirror to drift.
 *
 * Copyright (C) 2025-2026 Shane Fagan
 */
#ifndef __BPFRAG_INTF_H
#define __BPFRAG_INTF_H

enum consts {
	MAX_PROCS = 8192,	/* tracked processes using UDP or TCP */
	MAX_WATCH = 64,		/* processes we want exit events for */
	MAX_PORTS = 1024,	/* game UDP ports being DSCP marked */
	MAX_IFACES = 64,
	MAX_BULK_FLOWS = 16384,	/* sockets of bulk processes being demoted */
	GAP_BUCKETS = 64,	/* 1 ms each; the last one is ">= 63 ms" */
	GAP_STALL_MS = 100,	/* a gap this long is a stall the player feels... */
	GAP_IDLE_MS = 2000,	/* ...up to this; longer means the flow paused */
	GAP_RESUME = 4,		/* fast gaps in a row that end a quiet stretch */
};

/* Global counters, one slot per CPU (summed by userspace). */
enum stat_idx {
	STAT_TC_SEEN,		/* packets that hit the DSCP marker */
	STAT_DSCP_MARKED,	/* packets whose DSCP we rewrote */
	STAT_DSCP_KEPT,		/* game packets already marked by the app */
	STAT_EXITS,		/* exit events delivered */
	STAT_EVENTS_DROPPED,	/* ring buffer full */
	STAT_BULK_MARKED,	/* bulk packets demoted (egress and ingress) */
	NR_STATS,
};

/*
 * Per-process (tgid) counters, one copy per CPU. Packets and bytes are UDP
 * (what match detection looks at); TCP bytes are counted separately, for
 * spotting bulk transfers during a match.
 */
struct proc_stats {
	__u64 tx_pkts;
	__u64 rx_pkts;
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u32 ifindex;		/* egress device seen on a connected socket */
	__u32 _pad;
	__u64 tcp_tx_bytes;
	__u64 tcp_rx_bytes;
};

/* Local UDP port owned by a game process, learned in the send hook. */
struct game_port {
	__u32 tgid;
};

/*
 * Arrivals on one game port, measured at tc ingress: gaps between
 * consecutive packets, as a histogram plus the longest one.
 */
struct port_rx {
	__u64 pkts;
	__u64 last_ns;
	__u64 max_gap_ns;	/* longest gap counted */
	__u64 held_ns;		/* quiet stretch waiting for game-rate traffic */
	__u64 resume_ns;	/* fast gaps since then */
	__u32 resume_n;
	__u32 stalls;		/* quiet stretches of GAP_STALL_MS .. GAP_IDLE_MS */
	__u32 napi_id;		/* NAPI instance (receive queue) of the latest packet */
	__u32 hist[GAP_BUCKETS];
};

/* An interface the DSCP marker or the arrival meter is attached to. */
struct mark_iface {
	__u32 l2_len;		/* 14 for Ethernet/Wi-Fi, 0 for L3 tunnels */
	__u32 _pad;
	__u64 game_pkts;	/* game packets seen leaving here */
};

/*
 * A socket of a bulk process, as its packets show it: addresses in network
 * order (IPv4 in word 0), ports in host order, local first. An unconnected
 * UDP socket is keyed by protocol and local port alone (family 0, the rest
 * zero), since it talks to anyone.
 */
struct flow_key {
	__u8 family;
	__u8 proto;
	__u16 lport;
	__u16 rport;
	__u16 _pad;
	__u32 laddr[4];
	__u32 raddr[4];
};

struct bulk_flow {
	__u32 tgid;	/* owner, so its flows can be dropped when it stops being bulk */
};

enum event_kind {
	EVENT_EXIT = 1,
};

struct event {
	__u32 kind;
	__u32 tgid;
};

#endif /* __BPFRAG_INTF_H */
