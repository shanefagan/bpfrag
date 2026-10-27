// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! NIC interrupt coalescing: how long the NIC waits to batch packets
//! before raising an interrupt. Lower means less added receive latency.
//!
//! Only rx-usecs matters for latency; tx-usecs is set along with it when
//! the driver accepts that, and adaptive coalescing is switched off so the
//! driver doesn't move the value back. Wi-Fi drivers don't do coalescing
//! (power save is their knob, see `wifi`).

use std::collections::HashSet;

use anyhow::{Context, Result};
use log::debug;

use super::Knobs;
use super::journal::{Outcome, Saved};
use crate::net::{
    self, Iface,
    ethtool::{self, Coalesce},
};

impl Knobs {
    pub(super) fn apply_coalesce(
        &mut self,
        usecs: u32,
        ifaces: &[Iface],
        wanted: &mut HashSet<String>,
        changes: &mut Vec<String>,
    ) {
        // Wi-Fi drivers don't do coalescing; power save is their knob.
        for ifc in ifaces
            .iter()
            .filter(|i| i.physical && !net::is_wireless(&i.name))
        {
            let key = format!("coalesce:{}", ifc.name);
            let cur = match ethtool::get_coalesce(&ifc.name) {
                Ok(c) => c,
                Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                    debug!(
                        "{}: driver {} has no interrupt coalescing",
                        ifc.name,
                        net::driver(&ifc.name)
                    );
                    continue;
                }
                Err(e) => {
                    self.warn_once(&key, || {
                        format!("{}: cannot read interrupt coalescing ({e})", ifc.name)
                    });
                    continue;
                }
            };
            wanted.insert(key.clone());
            // rx is what matters for receive latency; tx is best effort.
            if cur.rx_usecs() == usecs && !cur.adaptive_rx() {
                continue;
            }
            if self.dry_run {
                changes.push(format!(
                    "would set {} coalescing to {usecs}us (now {})",
                    ifc.name,
                    cur.describe()
                ));
                self.current.insert(key, format!("{usecs}us"));
                continue;
            }
            let prev = self.saved_get(&key).cloned();
            match self.saved_get_mut(&key) {
                Some(Saved::Coalesce { applied, .. }) => *applied = Some(usecs),
                _ => self.save(
                    &key,
                    Saved::Coalesce {
                        ifname: ifc.name.clone(),
                        words: cur.0.to_vec(),
                        applied: Some(usecs),
                    },
                ),
            }
            if !self.persist() {
                self.put_back(&key, prev);
                continue;
            }
            // Build from the device's current state, not the baseline:
            // drivers validate the whole struct, and e.g. a tx value that
            // was fine before the last tier change may not be now.
            let res = ethtool::set_coalesce(&ifc.name, &cur.with_usecs(usecs, true))
                .or_else(|_| ethtool::set_coalesce(&ifc.name, &cur.with_usecs(usecs, false)));
            match res {
                Ok(()) => {
                    changes.push(format!("{} coalescing={usecs}us", ifc.name));
                    self.current.insert(key, format!("{usecs}us"));
                }
                Err(e) => {
                    self.put_back(&key, prev);
                    let (name, drv, now) =
                        (ifc.name.clone(), net::driver(&ifc.name), cur.rx_usecs());
                    self.warn_once(&format!("w:{key}:{usecs}"), || {
                        format!("{name} ({drv}): driver rejected rx-usecs {usecs} ({e}); leaving it at {now}")
                    });
                }
            }
        }
    }
}

/// Put coalescing back to the journalled `words`, unless rx-usecs no
/// longer holds what we set.
pub(super) fn restore(ifname: &str, words: &[u32], applied: Option<u32>) -> Result<Outcome> {
    let changed_by_others =
        applied.is_some_and(|a| ethtool::get_coalesce(ifname).is_ok_and(|cur| cur.rx_usecs() != a));
    if changed_by_others {
        return Ok(Outcome::Kept(format!(
            "{ifname} coalescing was changed by someone else during the match; leaving it"
        )));
    }
    let c = Coalesce::from_words(words);
    if let Err(full) = ethtool::set_coalesce(ifname, &c) {
        // Some drivers reject parts of the very struct they reported
        // (e.g. tx-usecs with paired queues). Put back just the
        // fields bpfrag changes, with and then without tx.
        let cur = ethtool::get_coalesce(ifname)
            .with_context(|| format!("reading coalescing on {ifname}"))?;
        ethtool::set_coalesce(ifname, &cur.restore_from(&c, true))
            .or_else(|_| ethtool::set_coalesce(ifname, &cur.restore_from(&c, false)))
            .with_context(|| {
                format!("restoring coalescing on {ifname} (full restore failed: {full})")
            })?;
    }
    Ok(Outcome::Restored(format!(
        "{ifname} coalescing {}",
        c.describe()
    )))
}
