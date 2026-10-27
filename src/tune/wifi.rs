// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Wi-Fi power save, turned off for the match so the radio never dozes
//! between packets. Power save lets the radio sleep between beacons; in a
//! lull (between rounds, a quiet second on a low-tick server) it dozes and
//! the next packets wait for it to wake.
//!
//! bpfrag only ever turns it off, and only turns it back on if it was on
//! before and nobody else changed it meanwhile.

use std::collections::HashSet;

use anyhow::{Context, Result};

use super::Knobs;
use super::journal::{Outcome, Saved};
use crate::net::{self, Iface, nl80211};

impl Knobs {
    pub(super) fn apply_wifi_ps(
        &mut self,
        ifaces: &[Iface],
        wanted: &mut HashSet<String>,
        changes: &mut Vec<String>,
    ) {
        for ifc in ifaces.iter().filter(|i| net::is_wireless(&i.name)) {
            let key = format!("wifi_ps:{}", ifc.name);
            let on = match nl80211::get_power_save(ifc.ifindex) {
                Ok(on) => on,
                Err(e) => {
                    self.warn_once(&key, || {
                        format!("{}: cannot read wifi power save ({e})", ifc.name)
                    });
                    continue;
                }
            };
            wanted.insert(key.clone());
            if !on {
                continue; // already off (by us earlier, or by the user)
            }
            if self.dry_run {
                changes.push(format!("would turn {} wifi power save off", ifc.name));
                self.current.insert(key, "off".into());
                continue;
            }
            let prev = self.saved_get(&key).cloned();
            if prev.is_none() {
                self.save(
                    &key,
                    Saved::WifiPs {
                        ifname: ifc.name.clone(),
                        enabled: true,
                    },
                );
                if !self.persist() {
                    self.unsave(&key);
                    continue;
                }
            }
            match nl80211::set_power_save(ifc.ifindex, false) {
                Ok(()) => {
                    changes.push(format!("{} wifi power_save=off", ifc.name));
                    self.current.insert(key, "off".into());
                }
                Err(e) => {
                    self.put_back(&key, prev);
                    self.warn_once(&format!("w:{key}"), || {
                        format!("{}: cannot turn power save off: {e}", ifc.name)
                    });
                }
            }
        }
    }
}

/// Turn power save back on if it was on before the match.
pub(super) fn restore(ifname: &str, enabled: bool) -> Result<Outcome> {
    let Some(ifc) = net::iface_by_name(ifname) else {
        return Ok(Outcome::Kept(format!(
            "{ifname} is gone; nothing to restore"
        )));
    };
    if !enabled {
        return Ok(Outcome::Kept(format!(
            "{ifname} power save was already off"
        )));
    }
    if nl80211::get_power_save(ifc.ifindex).unwrap_or(false) {
        return Ok(Outcome::Kept(format!(
            "{ifname} power save was turned back on by someone else; leaving it"
        )));
    }
    nl80211::set_power_save(ifc.ifindex, true)
        .with_context(|| format!("re-enabling power save on {ifname}"))?;
    Ok(Outcome::Restored(format!("{ifname} wifi power save on")))
}
