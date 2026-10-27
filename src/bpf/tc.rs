// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Attaching our two tc programs to interfaces:
//!
//! - the DSCP marker (`bpfrag_dscp`) at egress, during a match;
//! - the arrival meter (`bpfrag_rx`) at ingress, which times the gaps
//!   between the game's incoming packets (see `crate::health`).
//!
//! On kernel 6.6+ each is a tcx link: a file descriptor we hold, so the
//! kernel detaches it by itself if bpfrag dies. On older kernels the marker
//! falls back to a classic cls_bpf filter on a clsact qdisc, which outlives
//! the process; those are journalled (see `tune::journal`) so `--restore`
//! can remove them. The meter has no fallback: it only observes, and is
//! not worth leaving anything behind for.

use std::collections::BTreeMap;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result, bail};
use libbpf_rs::{MapCore, MapFlags, MapMut, ProgramMut, TC_EGRESS, TcHookBuilder};
use log::{debug, warn};

use super::maps::mark_iface_bytes;
use crate::bpf_skel::BpfSkel;
use crate::net::Iface;

/// Our legacy tc filter's handle and priority. Fixed, so a later run (or
/// `--restore`) can find and remove a filter left behind by a crash.
const TC_HANDLE: u32 = 0xbf7a;
const TC_PRIORITY: u32 = 0xbf7a;

/// Which of our tc programs a [`TcSet`] manages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// `bpfrag_dscp` at egress: DSCP-marks the game's packets.
    Marker,
    /// `bpfrag_rx` at ingress: times arrivals on the game's ports.
    Meter,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::Marker => "DSCP marker",
            Role::Meter => "arrival meter",
        }
    }

    fn prog<'s>(self, skel: &'s BpfSkel) -> &'s ProgramMut<'s> {
        match self {
            Role::Marker => &skel.progs.bpfrag_dscp,
            Role::Meter => &skel.progs.bpfrag_rx,
        }
    }

    /// The program's ifindex -> interface map: it skips packets on
    /// interfaces without an entry.
    fn ifaces_map<'s>(self, skel: &'s BpfSkel) -> &'s MapMut<'s> {
        match self {
            Role::Marker => &skel.maps.mark_ifaces,
            Role::Meter => &skel.maps.rx_ifaces,
        }
    }

    fn tcx_attach_type(self) -> libbpf_sys::bpf_attach_type {
        match self {
            Role::Marker => libbpf_sys::BPF_TCX_EGRESS,
            Role::Meter => libbpf_sys::BPF_TCX_INGRESS,
        }
    }
}

enum Attach {
    /// tcx link fd: closing it detaches, including when we crash.
    Tcx(#[allow(dead_code)] OwnedFd),
    /// cls_bpf filter: outlives us, so it is journalled for cleanup.
    Legacy(libbpf_rs::TcHook),
}

/// One tc program's attachments, one per interface.
pub struct TcSet {
    role: Role,
    attached: BTreeMap<u32, (Iface, Attach)>,
    /// The meter couldn't attach (no tcx); said once, not every match.
    told_no_tcx: bool,
}

impl TcSet {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            attached: BTreeMap::new(),
            told_no_tcx: false,
        }
    }

    /// Names of the interfaces the program is on.
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
        let what = self.role.name();
        for ifc in ifaces {
            if self.attached.contains_key(&ifc.ifindex) {
                continue;
            }
            // The program skips packets on interfaces it has no entry for,
            // so the entry goes in before the program is attached.
            if let Err(e) = self.role.ifaces_map(skel).update(
                &ifc.ifindex.to_ne_bytes(),
                &mark_iface_bytes(ifc.l2_len),
                MapFlags::ANY,
            ) {
                warn!("{}: {what} map update failed: {e}", ifc.name);
                continue;
            }
            match attach_one(skel, self.role, ifc.ifindex) {
                Ok(a) => {
                    let kind = match &a {
                        Attach::Tcx(_) => "tcx",
                        Attach::Legacy(_) => {
                            legacy.push(ifc.ifindex as i32);
                            "legacy tc"
                        }
                    };
                    debug!("{what} attached to {} ({kind})", ifc.name);
                    self.attached.insert(ifc.ifindex, (ifc.clone(), a));
                }
                Err(e) if self.role == Role::Meter => {
                    let _ = self
                        .role
                        .ifaces_map(skel)
                        .delete(&ifc.ifindex.to_ne_bytes());
                    if !self.told_no_tcx {
                        self.told_no_tcx = true;
                        log::info!("packet-gap measurement unavailable: {e:#}");
                    }
                }
                Err(e) => warn!("{}: cannot attach {what}: {e:#}", ifc.name),
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
        let _ = self.role.ifaces_map(skel).delete(&ifindex.to_ne_bytes());
        debug!("{} detached from {}", self.role.name(), ifc.name);
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

fn attach_one(skel: &BpfSkel, role: Role, ifindex: u32) -> Result<Attach> {
    let prog = role.prog(skel);
    // tcx (6.6+) is created with bpf_link_create() directly: libbpf's
    // attach_tcx() wants an expected_attach_type that SEC("tc") leaves
    // unset, and SEC("tc") is what lets the marker also run as a legacy
    // cls_bpf filter. BPFRAG_NO_TCX=1 forces the legacy path, for
    // debugging odd kernels.
    let no_tcx = std::env::var_os("BPFRAG_NO_TCX").is_some();
    if !no_tcx {
        let fd = unsafe {
            libbpf_sys::bpf_link_create(
                prog.as_fd().as_raw_fd(),
                ifindex as i32,
                role.tcx_attach_type(),
                std::ptr::null(),
            )
        };
        if fd >= 0 {
            return Ok(Attach::Tcx(unsafe { OwnedFd::from_raw_fd(fd) }));
        }
        let err = std::io::Error::from_raw_os_error(-fd);
        if role == Role::Meter {
            bail!("needs a tcx link (kernel 6.6+): {err}");
        }
        debug!("tcx link failed ({err}), falling back to legacy tc");
    } else if role == Role::Meter {
        bail!("BPFRAG_NO_TCX is set, and it needs a tcx link");
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
