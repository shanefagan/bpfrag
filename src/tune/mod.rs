// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Reversible knobs: everything bpfrag changes during a match, and how it
//! puts each one back.
//!
//! Every change follows the same rule: read the current value, write it
//! (and what we are about to set) to the journal, *then* change it. If the
//! journal can't be written, the knob isn't changed. Restoring walks the
//! journal backwards.
//!
//! Two rules avoid conflicts with other tuning (bpftune, tuned, sysctl.d):
//!   * capacity knobs are raise-only and writeback is lower-only, so we
//!     never undo something someone sized more generously (or strictly);
//!   * on restore, if a value no longer holds what we wrote, someone else
//!     changed it during the match and we leave their value alone.
//!
//! One file per knob type, each with its apply and restore rules:
//! [`sysctl`], [`coalesce`], [`writeback`], [`wifi`]. The journal format
//! is in [`journal`]; [`coexist`] decides which sysctls belong to bpftune.

mod coalesce;
pub mod coexist;
pub mod journal;
mod sysctl;
pub use sysctl::target_for;
pub use writeback::would_tighten as writeback_would_tighten;
mod wifi;
mod writeback;

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use log::{info, warn};

use crate::config::Profile;
use crate::net::Iface;
use journal::{Outcome, Saved, restore_one};

/// One applied knob, for `--monitor`.
#[derive(Clone, Debug)]
pub struct AppliedView {
    pub knob: String,
    pub value: String,
    pub baseline: String,
}

/// The knobs bpfrag currently holds changed, and their journal.
///
/// Entries are keyed by `<type>:<name>`, e.g. `sysctl:net.core.busy_poll`,
/// `coalesce:eno1`, `writeback:dirty`, `wifi_ps:wlan0`, `tc:<ifindex>`.
pub struct Knobs {
    dry_run: bool,
    journal_path: PathBuf,
    /// key -> original value, in the order they were changed
    saved: Vec<(String, Saved)>,
    /// key -> value we set (for stats output)
    current: BTreeMap<String, String>,
    /// warnings already logged, so a broken knob isn't reported every tick
    warned: HashSet<String>,
}

impl Knobs {
    pub fn new(run_dir: &Path, dry_run: bool) -> Self {
        let journal_path = journal::journal_path(run_dir);
        // What a previous run couldn't restore is held on to, so it's
        // tried again and never written over. A dry run leaves it alone.
        let saved = if dry_run {
            Vec::new()
        } else {
            journal::load(&journal_path)
        };
        Self {
            dry_run,
            journal_path,
            saved,
            current: BTreeMap::new(),
            warned: HashSet::new(),
        }
    }

    /// Undo whatever a previous (crashed or killed) instance left behind.
    pub fn recover(run_dir: &Path) -> Result<usize> {
        journal::recover(run_dir)
    }

    fn warn_once(&mut self, key: &str, msg: impl FnOnce() -> String) {
        if self.warned.insert(key.to_string()) {
            warn!("{}", msg());
        }
    }

    /// A knob someone else changed after bpfrag did, mid-match: stop
    /// holding it (it no longer shows as ours), but keep its journal entry,
    /// so the end of the match leaves it alone too. Logged once.
    fn theirs(&mut self, key: &str, msg: impl FnOnce() -> String) {
        self.current.remove(key);
        if self.warned.insert(format!("theirs:{key}")) {
            info!("{}", msg());
        }
    }

    /// Write the journal. Returns false if it couldn't be written, in which
    /// case callers must not change the knob they journalled for.
    fn persist(&self) -> bool {
        if self.dry_run {
            return true;
        }
        if let Err(e) = journal::write(&self.journal_path, &self.saved) {
            warn!(
                "could not write restore journal {}: {e:#}; not changing anything it would cover",
                self.journal_path.display()
            );
            return false;
        }
        true
    }

    fn saved_get(&self, key: &str) -> Option<&Saved> {
        self.saved.iter().find(|(k, _)| k == key).map(|(_, s)| s)
    }

    fn saved_get_mut(&mut self, key: &str) -> Option<&mut Saved> {
        self.saved
            .iter_mut()
            .find(|(k, _)| k == key)
            .map(|(_, s)| s)
    }

    /// Record a baseline (or update an existing one). Callers persist()
    /// before touching the knob.
    fn save(&mut self, key: &str, s: Saved) {
        match self.saved_get_mut(key) {
            Some(slot) => *slot = s,
            None => self.saved.push((key.to_string(), s)),
        }
    }

    fn unsave(&mut self, key: &str) {
        self.saved.retain(|(k, _)| k != key);
        self.current.remove(key);
    }

    /// Undo a save() whose change didn't happen: back to `prev`, or gone.
    fn put_back(&mut self, key: &str, prev: Option<Saved>) {
        match prev {
            Some(p) => self.save(key, p),
            None => self.unsave(key),
        }
    }

    /// Make the system look like `profile`, reverting anything the previous
    /// tier changed that this one doesn't want. `ifaces` get the
    /// per-interface knobs; `skip` holds sysctls that belong to someone
    /// else right now (bpftune). Returns a change summary for the log.
    pub fn apply(
        &mut self,
        profile: &Profile,
        ifaces: &[Iface],
        skip: &HashSet<String>,
    ) -> Vec<String> {
        let mut changes = Vec::new();
        // Keys this profile wants held; anything else saved gets restored.
        let mut wanted: HashSet<String> = HashSet::new();

        self.apply_sysctls(profile, skip, &mut wanted, &mut changes);
        if let Some(usecs) = profile.coalesce_usecs {
            self.apply_coalesce(usecs, ifaces, &mut wanted, &mut changes);
        }
        if let Some(wb) = profile.writeback {
            self.apply_writeback(wb, &mut wanted, &mut changes);
        }
        if profile.wifi_powersave_off {
            self.apply_wifi_ps(ifaces, &mut wanted, &mut changes);
        }

        // Revert what this tier no longer wants, newest first. tc entries
        // belong to the marker (bpf::tc), which manages its own.
        let stale: Vec<(String, Saved)> = self
            .saved
            .iter()
            .rev()
            .filter(|(k, _)| !wanted.contains(k) && !k.starts_with("tc:"))
            .cloned()
            .collect();
        for (key, saved) in stale {
            match restore_one(&saved) {
                Ok(Outcome::Restored(what)) => changes.push(format!("restored {what}")),
                Ok(Outcome::Kept(why)) => info!("{why}"),
                Err(e) => {
                    // keep the original to try again at the end of the match
                    self.current.remove(&key);
                    warn!("could not restore {key}: {e:#}; will try again");
                    continue;
                }
            }
            self.unsave(&key);
        }
        self.persist();
        changes
    }

    /// Put everything back. Returns (restored, kept-because-changed) notes.
    pub fn restore_all(&mut self) -> (Vec<String>, Vec<String>) {
        let mut done = Vec::new();
        let mut kept = Vec::new();
        let all: Vec<(String, Saved)> = self.saved.iter().rev().cloned().collect();
        for (key, saved) in all {
            if key.starts_with("tc:") {
                continue; // owned by the tc layer
            }
            match restore_one(&saved) {
                Ok(Outcome::Restored(what)) => done.push(what),
                Ok(Outcome::Kept(why)) => kept.push(why),
                Err(e) => {
                    // The original stays in the journal: the next match's
                    // end, --restore or the next start tries again.
                    warn!("could not restore {key}: {e:#}; kept in the journal to try again");
                    continue;
                }
            }
            self.saved.retain(|(k, _)| *k != key);
        }
        self.current.clear();
        self.warned.retain(|w| !w.starts_with("theirs:"));
        self.persist();
        (done, kept)
    }

    /// What is applied right now, with the value it replaced.
    pub fn view(&self) -> Vec<AppliedView> {
        self.current
            .iter()
            .map(|(k, val)| {
                let baseline = self.saved_get(k).map(Saved::baseline).unwrap_or_default();
                let knob = match k.split_once(':') {
                    Some(("coalesce", ifname)) => format!("{ifname} coalescing"),
                    Some(("wifi_ps", ifname)) => format!("{ifname} wifi power save"),
                    Some(("writeback", which)) => format!("vm.{which}_bytes"),
                    Some((_, rest)) => rest.to_string(),
                    None => k.clone(),
                };
                AppliedView {
                    knob,
                    value: val.clone(),
                    baseline,
                }
            })
            .collect()
    }
}
