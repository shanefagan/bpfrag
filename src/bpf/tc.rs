// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Attaching the DSCP marker (`bpfrag_dscp`) to interfaces at tc egress.
//!
//! On kernel 6.6+ it is a tcx link: a file descriptor we hold, so the
//! kernel detaches it by itself if bpfrag dies. Older kernels get a
//! classic cls_bpf filter on a clsact qdisc, which outlives the process;
//! those are journalled (see `tune::journal`) so `--restore` can remove
//! them.

use std::collections::BTreeMap;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags, TC_EGRESS, TcHookBuilder};
use log::{debug, warn};

use super::maps::mark_iface_bytes;
use crate::bpf_skel::BpfSkel;
use crate::net::Iface;

/// Our legacy tc filter's handle and priority. Fixed, so a later run (or
/// `--restore`) can find and remove a filter left behind by a crash.
const TC_HANDLE: u32 = 0xbf7a;
const TC_PRIORITY: u32 = 0xbf7a;

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
    /// Names of the interfaces the marker is on.
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
            // The program skips packets on interfaces it has no entry for,
            // so the entry goes in before the program is attached.
            if let Err(e) = skel.maps.mark_ifaces.update(
                &ifc.ifindex.to_ne_bytes(),
                &mark_iface_bytes(ifc.l2_len),
                MapFlags::ANY,
            ) {
                warn!("{}: mark_ifaces map update failed: {e}", ifc.name);
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
        let Some((ifc, a)) = self.attached.remove(&ifindex) else {
            return;
        };
        match a {
            Attach::Tcx(fd) => drop(fd),
            Attach::Legacy(mut hook) => {
                if let Err(e) = hook.detach() {
                    warn!("{}: detaching tc filter: {e}", ifc.name);
                }
            }
        }
        let _ = skel.maps.mark_ifaces.delete(&ifindex.to_ne_bytes());
        debug!("DSCP marker detached from {}", ifc.name);
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
    // tcx (6.6+) is created with bpf_link_create() directly: libbpf's
    // attach_tcx() wants an expected_attach_type that SEC("tc") leaves
    // unset, and SEC("tc") is what lets the same program also run as a
    // legacy cls_bpf filter. BPFRAG_NO_TCX=1 forces the legacy path, for
    // debugging odd kernels.
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

/// Remove our legacy tc filter from an interface. Used by crash recovery,
/// where the `TcHook` that created it is long gone.
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
