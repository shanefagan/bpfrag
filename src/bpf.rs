// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Helpers around the BPF skeleton: hook selection, map access and the tc
// DSCP marker attachments.

use std::collections::BTreeMap;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result, bail};
use libbpf_rs::{MapCore, MapFlags, MapHandle, TC_EGRESS, TcHookBuilder};
use log::{debug, warn};

use crate::bpf_intf;
use crate::bpf_skel::BpfSkel;
use crate::config::HookPref;
use crate::net::Iface;

/// Our legacy tc filter's handle/priority (unlikely to collide).
const TC_HANDLE: u32 = 0xbf7a;
const TC_PRIORITY: u32 = 0xbf7a;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookKind {
    /// raw_tp on sock_send_length / sock_recv_length (kernel >= 6.4)
    Tracepoint,
    /// fexit on udp{,v6}_{send,recv}msg (kernel >= 5.17 with BTF trampolines)
    Fexit,
}

impl HookKind {
    pub fn describe(self) -> &'static str {
        match self {
            HookKind::Tracepoint => "socket tracepoints",
            HookKind::Fexit => "UDP fexit probes",
        }
    }
}

fn btf_has(btf: &libbpf_rs::btf::Btf, name: &str) -> bool {
    btf.type_by_name::<libbpf_rs::btf::BtfType>(name).is_some()
}

/// Which counting hook can this kernel run?
pub fn pick_hook(pref: HookPref) -> Result<HookKind> {
    let btf = libbpf_rs::btf::Btf::from_vmlinux()
        .context("kernel BTF (/sys/kernel/btf/vmlinux) is required")?;
    let tp =
        btf_has(&btf, "btf_trace_sock_send_length") && btf_has(&btf, "btf_trace_sock_recv_length");
    let fx = btf_has(&btf, "udp_sendmsg") && btf_has(&btf, "udp_recvmsg");
    match pref {
        HookPref::Tracepoint if tp => Ok(HookKind::Tracepoint),
        HookPref::Tracepoint => {
            bail!("kernel lacks sock_send_length/sock_recv_length tracepoints (need >= 6.4)")
        }
        HookPref::Fexit if fx => Ok(HookKind::Fexit),
        HookPref::Fexit => bail!("udp_sendmsg/udp_recvmsg not found in kernel BTF"),
        HookPref::Auto if tp => Ok(HookKind::Tracepoint),
        HookPref::Auto if fx => Ok(HookKind::Fexit),
        HookPref::Auto => {
            bail!("no usable hook: need kernel >= 6.4, or >= 5.17 with fexit support")
        }
    }
}

pub fn has_udpv6_btf() -> bool {
    libbpf_rs::btf::Btf::from_vmlinux()
        .map(|b| btf_has(&b, "udpv6_sendmsg") && btf_has(&b, "udpv6_recvmsg"))
        .unwrap_or(false)
}

fn from_bytes<T: Copy + Default>(b: &[u8]) -> T {
    let mut v = T::default();
    if b.len() >= size_of::<T>() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                b.as_ptr(),
                (&mut v as *mut T).cast::<u8>(),
                size_of::<T>(),
            )
        };
    }
    v
}

/// Cumulative per-process counters, summed over CPUs.
pub fn read_proc_stats(skel: &BpfSkel) -> Vec<crate::detect::Sample> {
    let map = &skel.maps.proc_stats;
    let mut out = Vec::new();
    for key in map.keys() {
        let Ok(Some(per_cpu)) = map.lookup_percpu(&key, MapFlags::ANY) else {
            continue;
        };
        let mut s = crate::detect::Sample {
            tgid: from_bytes::<u32>(&key),
            ..Default::default()
        };
        for v in per_cpu {
            let ps: bpf_intf::proc_stats = from_bytes(&v);
            s.tx_pkts += ps.tx_pkts;
            s.rx_pkts += ps.rx_pkts;
            s.tx_bytes += ps.tx_bytes;
            s.rx_bytes += ps.rx_bytes;
            if ps.ifindex != 0 {
                s.ifindex = ps.ifindex;
            }
        }
        out.push(s);
    }
    out
}

/// Global counters from the per-CPU `stats` array, indexed by stat_idx.
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

fn set_flag(map: &libbpf_rs::MapMut, tgid: u32, on: bool, what: &str) {
    let k = tgid.to_ne_bytes();
    let r = if on {
        map.update(&k, &[1u8], MapFlags::ANY)
    } else {
        map.delete(&k).or(Ok(()))
    };
    if let Err(e) = r {
        warn!("{what} map update failed: {e}");
    }
}

/// Ask for an exit event when `tgid` exits.
pub fn watch(skel: &BpfSkel, tgid: u32, on: bool) {
    set_flag(&skel.maps.watch_tgids, tgid, on, "watch");
}

/// Start/stop DSCP marking for a process's UDP ports.
pub fn set_marking(skel: &BpfSkel, tgid: u32, on: bool) {
    set_flag(&skel.maps.mark_tgids, tgid, on, "mark");
    if on {
        return;
    }
    // forget every port this process owned
    let ports = &skel.maps.mark_ports;
    let stale: Vec<Vec<u8>> = ports
        .keys()
        .filter(|key| {
            ports
                .lookup(key, MapFlags::ANY)
                .ok()
                .flatten()
                .is_some_and(|v| from_bytes::<bpf_intf::port_mark>(&v).tgid == tgid)
        })
        .collect();
    for key in stale {
        let _ = ports.delete(&key);
    }
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Devices the tc marker saw this game's packets leave on within `max_age`
/// (bpf_ktime_get_ns() is CLOCK_MONOTONIC).
pub fn game_egress(skel: &BpfSkel, tgid: u32, max_age: std::time::Duration) -> Vec<u32> {
    let now = monotonic_ns();
    let max = max_age.as_nanos() as u64;
    let ports = &skel.maps.mark_ports;
    let mut out: Vec<u32> = Vec::new();
    for key in ports.keys() {
        let Ok(Some(v)) = ports.lookup(&key, MapFlags::ANY) else {
            continue;
        };
        let pm: bpf_intf::port_mark = from_bytes(&v);
        if pm.tgid == tgid
            && pm.ifindex != 0
            && now.saturating_sub(pm.last_ns) <= max
            && !out.contains(&pm.ifindex)
        {
            out.push(pm.ifindex);
        }
    }
    out.sort_unstable();
    out
}

pub fn marked_ports(skel: &BpfSkel) -> usize {
    skel.maps.mark_ports.keys().count()
}

pub fn events_handle(skel: &BpfSkel) -> Result<MapHandle> {
    Ok(MapHandle::try_from(&skel.maps.events)?)
}

pub fn decode_event(data: &[u8]) -> Option<bpf_intf::event> {
    (data.len() >= size_of::<bpf_intf::event>()).then(|| from_bytes(data))
}

enum Attach {
    /// tcx link fd: closing it detaches, including when we crash.
    Tcx(#[allow(dead_code)] OwnedFd),
    /// cls_bpf filter: outlives us, so it is journalled for cleanup.
    Legacy(libbpf_rs::TcHook),
}

/// DSCP marker attachments, one per egress interface.
#[derive(Default)]
pub struct TcMarker {
    attached: BTreeMap<u32, (Iface, Attach)>,
}

impl TcMarker {
    pub fn ifaces(&self) -> Vec<String> {
        self.attached
            .values()
            .map(|(i, _)| i.name.clone())
            .collect()
    }

    /// Attach on `ifaces` (and detach from any others). Returns ifindexes
    /// that needed a legacy tc filter, so the caller can journal them.
    pub fn attach(&mut self, skel: &BpfSkel, ifaces: &[Iface]) -> Vec<i32> {
        let mut legacy = Vec::new();
        let wanted: Vec<u32> = ifaces.iter().map(|i| i.ifindex).collect();
        let stale: Vec<u32> = self
            .attached
            .keys()
            .copied()
            .filter(|k| !wanted.contains(k))
            .collect();
        for k in stale {
            self.detach_one(skel, k);
        }
        for ifc in ifaces {
            if self.attached.contains_key(&ifc.ifindex) {
                continue;
            }
            if let Err(e) = skel.maps.if_l2.update(
                &ifc.ifindex.to_ne_bytes(),
                &ifc.l2_len.to_ne_bytes(),
                MapFlags::ANY,
            ) {
                warn!("{}: if_l2 map update failed: {e}", ifc.name);
                continue;
            }
            match attach_one(skel, ifc.ifindex) {
                Ok(a) => {
                    let kind = match &a {
                        Attach::Tcx(_) => "tcx",
                        Attach::Legacy(_) => {
                            legacy.push(ifc.ifindex as i32);
                            "legacy tc"
                        }
                    };
                    debug!("DSCP marker attached to {} ({kind})", ifc.name);
                    self.attached.insert(ifc.ifindex, (ifc.clone(), a));
                }
                Err(e) => warn!("{}: cannot attach DSCP marker: {e:#}", ifc.name),
            }
        }
        legacy
    }

    fn detach_one(&mut self, skel: &BpfSkel, ifindex: u32) {
        if let Some((ifc, a)) = self.attached.remove(&ifindex) {
            match a {
                Attach::Tcx(fd) => drop(fd),
                Attach::Legacy(mut hook) => {
                    if let Err(e) = hook.detach() {
                        warn!("{}: detaching tc filter: {e}", ifc.name);
                    }
                }
            }
            let _ = skel.maps.if_l2.delete(&ifindex.to_ne_bytes());
            debug!("DSCP marker detached from {}", ifc.name);
        }
    }

    /// Detach everything; returns ifindexes that had legacy filters.
    pub fn detach_all(&mut self, skel: &BpfSkel) -> Vec<i32> {
        let keys: Vec<u32> = self.attached.keys().copied().collect();
        let mut legacy = Vec::new();
        for k in keys {
            if matches!(self.attached.get(&k), Some((_, Attach::Legacy(_)))) {
                legacy.push(k as i32);
            }
            self.detach_one(skel, k);
        }
        legacy
    }
}

fn attach_one(skel: &BpfSkel, ifindex: u32) -> Result<Attach> {
    let prog = &skel.progs.bpfrag_dscp;
    // tcx (6.6+): a real BPF link. Created with link_create directly since
    // libbpf's attach_tcx() wants an expected_attach_type that SEC("tc")
    // leaves unset; one SEC("tc") program can then also do legacy cls_bpf.
    // BPFRAG_NO_TCX=1 forces the legacy path (debugging odd kernels).
    if std::env::var_os("BPFRAG_NO_TCX").is_none() {
        let fd = unsafe {
            libbpf_sys::bpf_link_create(
                prog.as_fd().as_raw_fd(),
                ifindex as i32,
                libbpf_sys::BPF_TCX_EGRESS,
                std::ptr::null(),
            )
        };
        if fd >= 0 {
            return Ok(Attach::Tcx(unsafe { OwnedFd::from_raw_fd(fd) }));
        }
        debug!(
            "tcx link failed ({}), falling back to legacy tc",
            std::io::Error::from_raw_os_error(-fd)
        );
    }
    let mut hook = TcHookBuilder::new(prog.as_fd())
        .ifindex(ifindex as i32)
        .replace(true)
        .handle(TC_HANDLE)
        .priority(TC_PRIORITY)
        .hook(TC_EGRESS);
    hook.create().context("creating clsact qdisc")?;
    hook.attach().context("attaching tc filter")?;
    Ok(Attach::Legacy(hook))
}

/// Remove our legacy tc filter from an interface (crash recovery path).
pub fn detach_legacy_tc(ifindex: i32) {
    let hook = libbpf_sys::bpf_tc_hook {
        sz: size_of::<libbpf_sys::bpf_tc_hook>() as _,
        ifindex,
        attach_point: libbpf_sys::BPF_TC_EGRESS,
        ..Default::default()
    };
    let opts = libbpf_sys::bpf_tc_opts {
        sz: size_of::<libbpf_sys::bpf_tc_opts>() as _,
        handle: TC_HANDLE,
        priority: TC_PRIORITY,
        ..Default::default()
    };
    let r = unsafe { libbpf_sys::bpf_tc_detach(&hook, &opts) };
    if r != 0 && r != -libc::ENOENT {
        debug!(
            "legacy tc detach on ifindex {ifindex}: {}",
            std::io::Error::from_raw_os_error(-r)
        );
    }
}

pub fn bump_memlock() {
    // Only matters on kernels < 5.11 (memcg accounting replaced it).
    let rl = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl) } != 0 {
        debug!(
            "could not raise RLIMIT_MEMLOCK: {}",
            std::io::Error::last_os_error()
        );
    }
}
