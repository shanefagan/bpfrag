// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Attaching our two tc programs to interfaces:
//!
//! - the DSCP marker (`bpfrag_dscp`) at egress, during a match;
//! - the arrival meter (`bpfrag_rx`) at ingress, which times the gaps
//!   between the game's incoming packets (see `crate::health`).
//!
//! Each is a tcx link (kernel 6.6+): a file descriptor we hold, so the
//! kernel detaches it by itself if bpfrag dies, and nothing is left behind
//! for `--restore` to clean up. tcx links also sit alongside other tc
//! users (qdiscs, classic filters, other tcx programs) without touching
//! them.

use std::collections::BTreeMap;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Result, bail};
use libbpf_rs::{MapCore, MapFlags, MapMut, ProgramMut};
use log::{debug, warn};

use super::maps::mark_iface_bytes;
use crate::bpf_skel::BpfSkel;
use crate::net::Iface;

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

/// One tc program's attachments, one per interface. Each holds the tcx
/// link's fd: closing it detaches the program, including when we crash.
pub struct TcSet {
    role: Role,
    attached: BTreeMap<u32, (Iface, OwnedFd)>,
    /// The meter couldn't attach; said once, not every match.
    told_meter_failed: bool,
}

impl TcSet {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            attached: BTreeMap::new(),
            told_meter_failed: false,
        }
    }

    /// Names of the interfaces the program is on.
    pub fn ifaces(&self) -> Vec<String> {
        self.attached
            .values()
            .map(|(i, _)| i.name.clone())
            .collect()
    }

    /// Attach on `ifaces`, and detach from any others.
    pub fn attach(&mut self, skel: &BpfSkel, ifaces: &[Iface]) {
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
                &mark_iface_bytes(ifc.l2_len, ifc.local),
                MapFlags::ANY,
            ) {
                warn!("{}: {what} map update failed: {e}", ifc.name);
                continue;
            }
            match attach_one(skel, self.role, ifc.ifindex) {
                Ok(fd) => {
                    debug!("{what} attached to {}", ifc.name);
                    self.attached.insert(ifc.ifindex, (ifc.clone(), fd));
                }
                Err(e) => {
                    let _ = self
                        .role
                        .ifaces_map(skel)
                        .delete(&ifc.ifindex.to_ne_bytes());
                    if self.role == Role::Meter {
                        // It only measures: say so once, not every match.
                        if !self.told_meter_failed {
                            self.told_meter_failed = true;
                            log::info!("packet-gap measurement unavailable: {e:#}");
                        }
                    } else {
                        warn!("{}: cannot attach {what}: {e:#}", ifc.name);
                    }
                }
            }
        }
    }

    fn detach_one(&mut self, skel: &BpfSkel, ifindex: u32) {
        let Some((ifc, fd)) = self.attached.remove(&ifindex) else {
            return;
        };
        drop(fd); // closing the link detaches the program
        let _ = self.role.ifaces_map(skel).delete(&ifindex.to_ne_bytes());
        debug!("{} detached from {}", self.role.name(), ifc.name);
    }

    pub fn detach_all(&mut self, skel: &BpfSkel) {
        let keys: Vec<u32> = self.attached.keys().copied().collect();
        for k in keys {
            self.detach_one(skel, k);
        }
    }
}

fn attach_one(skel: &BpfSkel, role: Role, ifindex: u32) -> Result<OwnedFd> {
    // Created with bpf_link_create() directly: libbpf's attach_tcx() wants
    // an expected_attach_type, which SEC("tc") leaves unset.
    let prog = role.prog(skel);
    let fd = unsafe {
        libbpf_sys::bpf_link_create(
            prog.as_fd().as_raw_fd(),
            ifindex as i32,
            role.tcx_attach_type(),
            std::ptr::null(),
        )
    };
    if fd < 0 {
        bail!("tcx link: {}", std::io::Error::from_raw_os_error(-fd));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
