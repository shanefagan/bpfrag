// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Reading and writing the BPF maps declared in `main.bpf.c`.
//!
//! Per-CPU maps come back as one value per CPU and are summed here, so
//! callers only ever see totals.

use anyhow::Result;
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapMut};
use log::warn;

use super::from_bytes;
use crate::bpf_intf;
use crate::bpf_skel::BpfSkel;
use crate::detect::Sample;

/// Cumulative UDP and TCP counters for every process the BPF side has seen,
/// summed over CPUs. A process's entry disappears when it exits.
pub fn read_proc_stats(skel: &BpfSkel) -> Vec<Sample> {
    let map = &skel.maps.proc_stats;
    let mut out = Vec::new();
    for key in map.keys() {
        let Ok(Some(per_cpu)) = map.lookup_percpu(&key, MapFlags::ANY) else {
            continue; // exited between keys() and the lookup
        };
        let mut s = Sample {
            tgid: from_bytes::<u32>(&key),
            ..Default::default()
        };
        for v in per_cpu {
            let ps: bpf_intf::proc_stats = from_bytes(&v);
            s.tx_pkts += ps.tx_pkts;
            s.rx_pkts += ps.rx_pkts;
            s.tx_bytes += ps.tx_bytes;
            s.rx_bytes += ps.rx_bytes;
            s.tcp_tx_bytes += ps.tcp_tx_bytes;
            s.tcp_rx_bytes += ps.tcp_rx_bytes;
            if ps.ifindex != 0 {
                s.ifindex = ps.ifindex;
            }
        }
        out.push(s);
    }
    out
}

/// Global counters from the per-CPU `stats` array, indexed by `stat_idx`.
pub fn read_global_stats(skel: &BpfSkel) -> [u64; bpf_intf::NR_STATS as usize] {
    let mut out = [0u64; bpf_intf::NR_STATS as usize];
    for (idx, slot) in out.iter_mut().enumerate() {
        let key = (idx as u32).to_ne_bytes();
        if let Ok(Some(per_cpu)) = skel.maps.stats.lookup_percpu(&key, MapFlags::ANY) {
            *slot = per_cpu.iter().map(|v| from_bytes::<u64>(v)).sum();
        }
    }
    out
}

/// Add or remove `tgid` in a tgid -> u8 "set" map.
fn set_flag(map: &MapMut, tgid: u32, on: bool, what: &str) {
    let k = tgid.to_ne_bytes();
    let r = if on {
        map.update(&k, &[1u8], MapFlags::ANY)
    } else {
        map.delete(&k).or(Ok(())) // already gone is fine
    };
    if let Err(e) = r {
        warn!("{what} map update failed: {e}");
    }
}

/// Ask for an exit event when `tgid` exits.
pub fn watch(skel: &BpfSkel, tgid: u32, on: bool) {
    set_flag(&skel.maps.watch_tgids, tgid, on, "watch");
}

/// Start or stop tracking the current game's UDP ports. The send hook
/// learns the ports of processes in `game_tgids`; the marker and the
/// arrival meter act on those ports. Stopping also forgets the ports.
pub fn track_ports(skel: &BpfSkel, tgid: u32, on: bool) {
    set_flag(&skel.maps.game_tgids, tgid, on, "game");
    if on {
        return;
    }
    let ports = &skel.maps.game_ports;
    let stale: Vec<Vec<u8>> = ports
        .keys()
        .filter(|key| {
            ports
                .lookup(key, MapFlags::ANY)
                .ok()
                .flatten()
                .is_some_and(|v| from_bytes::<bpf_intf::game_port>(&v).tgid == tgid)
        })
        .collect();
    for key in stale {
        let _ = ports.delete(&key);
    }
}

/// Declare `tgid` bulk (or not). Its sockets are learned from then on. The
/// BPF side only demotes a flow while its owner is in `bulk_tgids`, so
/// letting a process go takes effect at once; its flows stay in the LRU map
/// (ready if it turns bulk again) until evicted or the match ends.
pub fn bulk_tgid(skel: &BpfSkel, tgid: u32, on: bool) {
    set_flag(&skel.maps.bulk_tgids, tgid, on, "bulk");
}

/// Turn the bulk flow lookups (learning and marking) on or off. A plain
/// write to the BPF side's .bss, which the kernel side reads directly.
pub fn bulk_active(skel: &mut BpfSkel, on: bool) {
    if let Some(bss) = skel.maps.bss_data.as_deref_mut() {
        bss.bulk_on = on;
    }
}

/// Count TCP per process (needed only while a match is on).
pub fn count_tcp(skel: &mut BpfSkel, on: bool) {
    if let Some(bss) = skel.maps.bss_data.as_deref_mut() {
        bss.count_tcp = on;
    }
}

/// Forget every bulk process and flow (between matches).
pub fn clear_bulk(skel: &mut BpfSkel) {
    bulk_active(skel, false);
    for map in [&skel.maps.bulk_tgids, &skel.maps.bulk_flows] {
        let keys: Vec<Vec<u8>> = map.keys().collect();
        for k in keys {
            let _ = map.delete(&k);
        }
    }
}

/// Local UDP ports the current game has used so far.
pub fn marked_ports(skel: &BpfSkel) -> usize {
    skel.maps.game_ports.keys().count()
}

/// (ifindex, game packets seen leaving there) for every interface the
/// marker is attached to. Counts start at zero when the marker attaches.
pub fn game_packets(skel: &BpfSkel) -> Vec<(u32, u64)> {
    let map = &skel.maps.mark_ifaces;
    map.keys()
        .filter_map(|key| {
            let v = map.lookup(&key, MapFlags::ANY).ok().flatten()?;
            let mi: bpf_intf::mark_iface = from_bytes(&v);
            Some((from_bytes::<u32>(&key), mi.game_pkts))
        })
        .collect()
}

/// The `mark_ifaces` value for an interface the marker attaches to, with
/// its packet count at zero.
pub fn mark_iface_bytes(l2_len: u32) -> Vec<u8> {
    let mi = bpf_intf::mark_iface {
        l2_len,
        ..Default::default()
    };
    let mut v = Vec::with_capacity(size_of_val(&mi));
    v.extend_from_slice(&mi.l2_len.to_ne_bytes());
    v.extend_from_slice(&mi._pad.to_ne_bytes());
    v.extend_from_slice(&mi.game_pkts.to_ne_bytes());
    v
}

/// Arrival statistics per game port, as the meter recorded them.
pub fn read_port_rx(skel: &BpfSkel) -> Vec<(u16, bpf_intf::port_rx)> {
    let map = &skel.maps.port_rx;
    map.keys()
        .filter_map(|key| {
            let v = map.lookup(&key, MapFlags::ANY).ok().flatten()?;
            Some((from_bytes::<u32>(&key) as u16, from_bytes(&v)))
        })
        .collect()
}

/// Forget all arrival statistics (between matches).
pub fn clear_port_rx(skel: &BpfSkel) {
    let map = &skel.maps.port_rx;
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for k in keys {
        let _ = map.delete(&k);
    }
}

/// A handle on the exit-event ring buffer, for `RingBufferBuilder`.
pub fn events_handle(skel: &BpfSkel) -> Result<MapHandle> {
    Ok(MapHandle::try_from(&skel.maps.events)?)
}

/// One record from the ring buffer, if it is long enough to be one.
pub fn decode_event(data: &[u8]) -> Option<bpf_intf::event> {
    (data.len() >= size_of::<bpf_intf::event>()).then(|| from_bytes(data))
}
