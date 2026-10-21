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
	MAX_PROCS = 8192,	/* tracked UDP-using processes */
	MAX_WATCH = 64,		/* processes we want exit events for */
	MAX_PORTS = 1024,	/* game UDP ports being DSCP marked */
	MAX_IFACES = 64,
};

/* Global counters, one slot per CPU (summed by userspace). */
enum stat_idx {
	STAT_TC_SEEN,		/* packets that hit the DSCP marker */
	STAT_DSCP_MARKED,	/* packets whose DSCP we rewrote */
	STAT_DSCP_KEPT,		/* game packets already marked by the app */
	STAT_EXITS,		/* exit events delivered */
	STAT_EVENTS_DROPPED,	/* ring buffer full */
	NR_STATS,
};

/* Per-process (tgid) UDP counters, one copy per CPU. */
struct proc_stats {
	__u64 tx_pkts;
	__u64 rx_pkts;
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u32 ifindex;		/* egress device seen on a connected socket */
	__u32 _pad;
};

/* Local UDP port owned by a game process, learned in the send hook. */
struct port_mark {
	__u32 tgid;
};

/* An interface the DSCP marker is attached to. */
struct mark_iface {
	__u32 l2_len;		/* 14 for Ethernet/Wi-Fi, 0 for L3 tunnels */
	__u32 _pad;
	__u64 game_pkts;	/* game packets seen leaving here */
};

enum event_kind {
	EVENT_EXIT = 1,
};

struct event {
	__u32 kind;
	__u32 tgid;
};

#endif /* __BPFRAG_INTF_H */
