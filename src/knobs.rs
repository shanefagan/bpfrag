// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Reversible knobs. Every change follows the same rule: read the current
// value, write it (and what we are about to set) to the on-disk journal,
// *then* change it. Restoring walks the journal backwards.
//
// Two rules avoid conflicts with other tuning (bpftune, tuned, sysctl.d):
//   * capacity knobs are raise-only and writeback is lower-only, so we never
//     undo something someone sized more generously (or more strictly);
//   * on restore, if a value no longer holds what we wrote, someone else
//     changed it during the match and we leave their value alone.
//
// If the daemon dies mid-match, the journal in /run/bpfrag lets
// `bpfrag --restore` (ExecStopPost in the systemd unit) or the next start
// put everything back. tcx links detach by themselves when we die.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::config::{Tier, Writeback};
use crate::net::{self, Coalesce, Iface};
use crate::util::{norm_ws, read_trim, sysctl_path, write_str};
use crate::wifi;

const MIB: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Saved {
    /// sysctl file: original contents, and what we wrote
    File {
        path: String,
        value: String,
        #[serde(default)]
        applied: String,
    },
    /// ethtool coalescing words
    Coalesce { ifname: String, words: Vec<u32> },
    /// vm.dirty[_background]_{bytes,ratio}: bytes and ratio are mutually
    /// exclusive, and *_bytes can't be written back to 0, so restoring a
    /// ratio-based setup means writing the ratio.
    Dirty {
        which: String,
        bytes: u64,
        ratio: u64,
        #[serde(default)]
        applied: u64,
    },
    /// legacy (non-tcx) tc filter that must be removed by hand
    TcLegacy { ifindex: i32 },
    /// Wi-Fi power save state before the match (we only ever turn it off)
    WifiPs { ifname: String, enabled: bool },
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Journal {
    pid: u32,
    entries: Vec<(String, Saved)>,
}

#[derive(Clone, Debug)]
pub struct AppliedView {
    pub knob: String,
    pub value: String,
    pub baseline: String,
}

enum Want {
    Exact(String),
    AtLeast(Vec<u64>),
}

pub enum Outcome {
    Restored(String),
    /// someone else changed it during the match; left alone
    Kept(String),
}

pub fn journal_path(run_dir: &Path) -> PathBuf {
    run_dir.join("journal.json")
}

pub fn short_path(path: &str) -> String {
    match path.strip_prefix("/proc/sys/") {
        Some(k) => k.replace('/', "."),
        None => path.to_string(),
    }
}

fn dirty_paths(which: &str) -> (PathBuf, PathBuf) {
    (
        PathBuf::from(format!("/proc/sys/vm/{which}_bytes")),
        PathBuf::from(format!("/proc/sys/vm/{which}_ratio")),
    )
}

fn read_u64(p: &Path) -> Option<u64> {
    read_trim(p).ok()?.parse().ok()
}

fn mem_available() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            m.lines()
                .find_map(|l| l.strip_prefix("MemAvailable:"))
                .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        })
        .map(|kib| kib * 1024)
        .unwrap_or(0)
}

/// Restore one saved item.
pub fn restore_one(saved: &Saved) -> Result<Outcome> {
    match saved {
        Saved::File {
            path,
            value,
            applied,
        } => {
            let label = short_path(path);
            let cur = norm_ws(&read_trim(path).unwrap_or_default());
            if !applied.is_empty() && cur != *applied {
                return Ok(Outcome::Kept(format!(
                    "{label} was changed by someone else during the match (now {cur}); leaving it"
                )));
            }
            write_str(path, value).with_context(|| format!("writing {path}"))?;
            Ok(Outcome::Restored(format!("{label} = {value}")))
        }
        Saved::Coalesce { ifname, words } => {
            let mut w = [0u32; net::COALESCE_WORDS];
            for (d, s) in w.iter_mut().zip(words) {
                *d = *s;
            }
            let c = Coalesce(w);
            if let Err(full) = net::set_coalesce(ifname, &c) {
                // Some drivers reject parts of the very struct they reported
                // (e.g. tx-usecs with paired queues). Put back just the
                // fields bpfrag changes, with and then without tx.
                let cur = net::get_coalesce(ifname)
                    .with_context(|| format!("reading coalescing on {ifname}"))?;
                net::set_coalesce(ifname, &cur.restore_from(&c, true))
                    .or_else(|_| net::set_coalesce(ifname, &cur.restore_from(&c, false)))
                    .with_context(|| {
                        format!("restoring coalescing on {ifname} (full restore failed: {full})")
                    })?;
            }
            Ok(Outcome::Restored(format!(
                "{ifname} coalescing {}",
                c.describe()
            )))
        }
        Saved::Dirty {
            which,
            bytes,
            ratio,
            applied,
        } => {
            let (bp, rp) = dirty_paths(which);
            let cur = read_u64(&bp).unwrap_or(0);
            if *applied != 0 && cur != *applied {
                return Ok(Outcome::Kept(format!(
                    "vm.{which}_bytes was changed by someone else during the match; leaving it"
                )));
            }
            if *bytes != 0 {
                write_str(&bp, &bytes.to_string())?;
                Ok(Outcome::Restored(format!("vm.{which}_bytes = {bytes}")))
            } else {
                write_str(&rp, &ratio.to_string())?;
                Ok(Outcome::Restored(format!("vm.{which}_ratio = {ratio}")))
            }
        }
        Saved::WifiPs { ifname, enabled } => {
            let Some(ifc) = net::iface_by_name(ifname) else {
                return Ok(Outcome::Kept(format!(
                    "{ifname} is gone; nothing to restore"
                )));
            };
            if !*enabled {
                return Ok(Outcome::Kept(format!(
                    "{ifname} power save was already off"
                )));
            }
            if wifi::get_power_save(ifc.ifindex).unwrap_or(false) {
                return Ok(Outcome::Kept(format!(
                    "{ifname} power save was turned back on by someone else; leaving it"
                )));
            }
            wifi::set_power_save(ifc.ifindex, true)
                .with_context(|| format!("re-enabling power save on {ifname}"))?;
            Ok(Outcome::Restored(format!("{ifname} wifi power save on")))
        }
        Saved::TcLegacy { ifindex } => {
            crate::bpf::detach_legacy_tc(*ifindex);
            Ok(Outcome::Restored(format!("tc filter on ifindex {ifindex}")))
        }
    }
}

pub struct Knobs {
    dry_run: bool,
    journal_path: PathBuf,
    saved: Vec<(String, Saved)>,
    /// key -> value we set (for stats output)
    current: BTreeMap<String, String>,
    warned: HashSet<String>,
}

impl Knobs {
    pub fn new(run_dir: &Path, dry_run: bool) -> Self {
        Self {
            dry_run,
            journal_path: journal_path(run_dir),
            saved: Vec::new(),
            current: BTreeMap::new(),
            warned: HashSet::new(),
        }
    }

    /// Undo whatever a previous (crashed or killed) instance left behind.
    pub fn recover(run_dir: &Path) -> Result<usize> {
        let path = journal_path(run_dir);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e).context("reading journal"),
        };
        let j: Journal = serde_json::from_str(&text).context("parsing journal")?;
        let mut n = 0;
        for (key, saved) in j.entries.iter().rev() {
            match restore_one(saved) {
                Ok(Outcome::Restored(what)) => {
                    info!("restored {what}");
                    n += 1;
                }
                Ok(Outcome::Kept(why)) => info!("{why}"),
                Err(e) => warn!("could not restore {key}: {e:#}"),
            }
        }
        fs::remove_file(&path).context("removing journal")?;
        Ok(n)
    }

    fn warn_once(&mut self, key: &str, msg: impl FnOnce() -> String) {
        if self.warned.insert(key.to_string()) {
            warn!("{}", msg());
        }
    }

    fn persist(&self) {
        if self.dry_run {
            return;
        }
        let j = Journal {
            pid: std::process::id(),
            entries: self.saved.clone(),
        };
        let res = (|| -> Result<()> {
            if j.entries.is_empty() {
                match fs::remove_file(&self.journal_path) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                    _ => return Ok(()),
                }
            }
            if let Some(d) = self.journal_path.parent() {
                fs::create_dir_all(d)?;
            }
            let tmp = self.journal_path.with_extension("json.tmp");
            let mut f = File::create(&tmp)?;
            f.write_all(serde_json::to_string_pretty(&j)?.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &self.journal_path)?;
            Ok(())
        })();
        if let Err(e) = res {
            warn!(
                "could not write restore journal {}: {e:#}",
                self.journal_path.display()
            );
        }
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

    pub fn track_tc_legacy(&mut self, ifindex: i32) {
        self.save(&format!("tc:{ifindex}"), Saved::TcLegacy { ifindex });
        self.persist();
    }

    pub fn untrack_tc_legacy(&mut self, ifindex: i32) {
        let key = format!("tc:{ifindex}");
        if self.saved_get(&key).is_some() {
            self.unsave(&key);
            self.persist();
        }
    }

    /// Make the system look like `tier`, reverting anything the previous
    /// tier changed that this one doesn't want. `skip` holds sysctls that
    /// belong to someone else right now (bpftune). Returns a change summary.
    pub fn apply(&mut self, tier: &Tier, ifaces: &[Iface], skip: &HashSet<String>) -> Vec<String> {
        let mut changes = Vec::new();
        let mut wanted: HashSet<String> = HashSet::new();

        self.apply_sysctls(tier, skip, &mut wanted, &mut changes);
        if let Some(usecs) = tier.coalesce_usecs {
            self.apply_coalesce(usecs, ifaces, &mut wanted, &mut changes);
        }
        if let Some(wb) = tier.writeback {
            self.apply_writeback(wb, &mut wanted, &mut changes);
        }
        if tier.wifi_powersave_off {
            self.apply_wifi_ps(ifaces, &mut wanted, &mut changes);
        }

        // revert what this tier no longer wants (newest first)
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
                Err(e) => warn!("could not restore {key}: {e:#}"),
            }
            self.unsave(&key);
        }
        self.persist();
        changes
    }

    fn apply_sysctls(
        &mut self,
        tier: &Tier,
        skip: &HashSet<String>,
        wanted: &mut HashSet<String>,
        changes: &mut Vec<String>,
    ) {
        struct Pending {
            key: String,
            path: PathBuf,
            label: String,
            target: String,
            prev: Option<Saved>,
        }
        let mut pending: Vec<Pending> = Vec::new();

        for (k, v) in &tier.sysctl {
            if skip.contains(k) {
                // Someone else owns it now. If we already changed it (they
                // showed up mid-match) hold it until the match ends rather
                // than churning it.
                let key = format!("sysctl:{k}");
                if self.saved_get(&key).is_some() {
                    wanted.insert(key);
                }
                continue;
            }
            let Some(path) = sysctl_path(k) else { continue };
            if !path.exists() {
                debug!("sysctl {k} not present on this kernel, skipping");
                continue;
            }
            let want = match v.trim().strip_prefix(">=") {
                Some(nums) => match nums
                    .split_whitespace()
                    .map(str::parse::<u64>)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(n) if !n.is_empty() => Want::AtLeast(n),
                    _ => {
                        self.warn_once(&format!("bad:{k}"), || {
                            format!("sysctl {k}: bad value {v:?}")
                        });
                        continue;
                    }
                },
                None => Want::Exact(norm_ws(v)),
            };
            let key = format!("sysctl:{k}");
            wanted.insert(key.clone());

            let cur = match read_trim(&path) {
                Ok(c) => norm_ws(&c),
                Err(e) => {
                    self.warn_once(&key, || format!("cannot read {k}: {e}"));
                    continue;
                }
            };
            let prev = self.saved_get(&key).cloned();
            let baseline = match &prev {
                Some(Saved::File { value, .. }) => value.clone(),
                _ => cur.clone(),
            };
            let target = match &want {
                Want::Exact(s) => s.clone(),
                Want::AtLeast(n) => {
                    let base: Vec<u64> = baseline
                        .split_whitespace()
                        .filter_map(|x| x.parse().ok())
                        .collect();
                    if base.len() == n.len() {
                        base.iter()
                            .zip(n)
                            .map(|(b, t)| (*b).max(*t).to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                    } else {
                        n.iter().map(u64::to_string).collect::<Vec<_>>().join(" ")
                    }
                }
            };
            if target == cur {
                if prev.is_some() && target == baseline {
                    self.unsave(&key); // back at baseline, nothing to restore
                }
                continue;
            }
            if self.dry_run {
                changes.push(format!("would set {k} = {target} (now {cur})"));
                self.current.insert(key, target);
                continue;
            }
            self.save(
                &key,
                Saved::File {
                    path: path.to_string_lossy().into_owned(),
                    value: baseline,
                    applied: target.clone(),
                },
            );
            pending.push(Pending {
                key,
                path,
                label: k.clone(),
                target,
                prev,
            });
        }

        // journal first, then touch the knobs
        self.persist();
        for p in pending {
            match write_str(&p.path, &p.target) {
                Ok(()) => {
                    changes.push(format!("{}={}", p.label, p.target));
                    self.current.insert(p.key, p.target);
                }
                Err(e) => {
                    match p.prev {
                        Some(prev) => self.save(&p.key, prev),
                        None => self.unsave(&p.key),
                    }
                    let (label, target) = (p.label.clone(), p.target.clone());
                    self.warn_once(&format!("w:{}", p.key), || {
                        format!("cannot set {label}={target}: {e}")
                    });
                }
            }
        }
    }

    fn apply_coalesce(
        &mut self,
        usecs: u32,
        ifaces: &[Iface],
        wanted: &mut HashSet<String>,
        changes: &mut Vec<String>,
    ) {
        // Wi-Fi drivers don't do coalescing; power save is their knob.
        for ifc in ifaces
            .iter()
            .filter(|i| i.physical && !wifi::is_wireless(&i.name))
        {
            let key = format!("coalesce:{}", ifc.name);
            let cur = match net::get_coalesce(&ifc.name) {
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
            let fresh = self.saved_get(&key).is_none();
            if fresh {
                self.save(
                    &key,
                    Saved::Coalesce {
                        ifname: ifc.name.clone(),
                        words: cur.0.to_vec(),
                    },
                );
                self.persist();
            }
            // Build from the device's current state, not the baseline:
            // drivers validate the whole struct, and e.g. a tx value that
            // was fine before the last tier change may not be now.
            let res = net::set_coalesce(&ifc.name, &cur.with_usecs(usecs, true))
                .or_else(|_| net::set_coalesce(&ifc.name, &cur.with_usecs(usecs, false)));
            match res {
                Ok(()) => {
                    changes.push(format!("{} coalescing={usecs}us", ifc.name));
                    self.current.insert(key, format!("{usecs}us"));
                }
                Err(e) => {
                    if fresh {
                        self.unsave(&key);
                    }
                    let (name, drv, now) =
                        (ifc.name.clone(), net::driver(&ifc.name), cur.rx_usecs());
                    self.warn_once(&format!("w:{key}:{usecs}"), || {
                        format!("{name} ({drv}): driver rejected rx-usecs {usecs} ({e}); leaving it at {now}")
                    });
                }
            }
        }
    }

    fn apply_writeback(
        &mut self,
        wb: Writeback,
        wanted: &mut HashSet<String>,
        changes: &mut Vec<String>,
    ) {
        let avail = mem_available();
        // dirty first, then background (restore runs in reverse)
        for (which, mb) in [
            ("dirty", wb.dirty_mb),
            ("dirty_background", wb.background_mb),
        ] {
            let key = format!("writeback:{which}");
            let (bp, rp) = dirty_paths(which);
            let (Some(bytes), Some(ratio)) = (read_u64(&bp), read_u64(&rp)) else {
                continue;
            };
            wanted.insert(key.clone());
            let target = mb * MIB;
            if bytes == target {
                continue;
            }
            if self.saved_get(&key).is_none() {
                // Only ever tighten: compare against the effective limit.
                let effective = if bytes > 0 {
                    bytes
                } else {
                    ratio * avail / 100
                };
                if effective <= target {
                    debug!("vm.{which} already at or below {mb} MiB, leaving it");
                    continue;
                }
            }
            if self.dry_run {
                changes.push(format!("would set vm.{which}_bytes = {target}"));
                self.current.insert(key, format!("{mb} MiB"));
                continue;
            }
            let fresh = self.saved_get(&key).is_none();
            if fresh {
                self.save(
                    &key,
                    Saved::Dirty {
                        which: which.into(),
                        bytes,
                        ratio,
                        applied: target,
                    },
                );
            } else if let Some(Saved::Dirty { applied, .. }) = self.saved_get_mut(&key) {
                *applied = target;
            }
            self.persist();
            match write_str(&bp, &target.to_string()) {
                Ok(()) => {
                    changes.push(format!("vm.{which}_bytes={target}"));
                    self.current.insert(key, format!("{mb} MiB"));
                }
                Err(e) => {
                    if fresh {
                        self.unsave(&key);
                    }
                    self.warn_once(&format!("w:{key}"), || {
                        format!("cannot set vm.{which}_bytes: {e}")
                    });
                }
            }
        }
    }

    fn apply_wifi_ps(
        &mut self,
        ifaces: &[Iface],
        wanted: &mut HashSet<String>,
        changes: &mut Vec<String>,
    ) {
        for ifc in ifaces.iter().filter(|i| wifi::is_wireless(&i.name)) {
            let key = format!("wifi_ps:{}", ifc.name);
            let on = match wifi::get_power_save(ifc.ifindex) {
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
            let fresh = self.saved_get(&key).is_none();
            if fresh {
                self.save(
                    &key,
                    Saved::WifiPs {
                        ifname: ifc.name.clone(),
                        enabled: true,
                    },
                );
                self.persist();
            }
            match wifi::set_power_save(ifc.ifindex, false) {
                Ok(()) => {
                    changes.push(format!("{} wifi power_save=off", ifc.name));
                    self.current.insert(key, "off".into());
                }
                Err(e) => {
                    if fresh {
                        self.unsave(&key);
                    }
                    self.warn_once(&format!("w:{key}"), || {
                        format!("{}: cannot turn power save off: {e}", ifc.name)
                    });
                }
            }
        }
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
                Err(e) => warn!("could not restore {key}: {e:#}"),
            }
            self.saved.retain(|(k, _)| *k != key);
        }
        self.current.clear();
        self.persist();
        (done, kept)
    }

    pub fn view(&self) -> Vec<AppliedView> {
        self.current
            .iter()
            .map(|(k, val)| {
                let baseline = match self.saved_get(k) {
                    Some(Saved::File { value, .. }) => value.clone(),
                    Some(Saved::Coalesce { words, .. }) => {
                        format!("{}us", words.get(1).copied().unwrap_or(0))
                    }
                    Some(Saved::WifiPs { enabled, .. }) => {
                        (if *enabled { "on" } else { "off" }).into()
                    }
                    Some(Saved::Dirty { bytes, ratio, .. }) => {
                        if *bytes > 0 {
                            format!("{} MiB", bytes / MIB)
                        } else {
                            format!("{ratio}% of RAM")
                        }
                    }
                    _ => String::new(),
                };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bpfrag-knobs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn file_entry(path: &Path, value: &str, applied: &str) -> (String, Saved) {
        (
            format!("sysctl:{}", path.display()),
            Saved::File {
                path: path.to_string_lossy().into(),
                value: value.into(),
                applied: applied.into(),
            },
        )
    }

    #[test]
    fn recover_restores_ours_and_keeps_theirs() {
        let d = tmpdir("journal");
        let ours = d.join("ours");
        let theirs = d.join("theirs");
        fs::write(&ours, "50").unwrap(); // still what we wrote
        fs::write(&theirs, "9000").unwrap(); // someone changed it after us
        let j = Journal {
            pid: 1,
            entries: vec![
                file_entry(&ours, "0", "50"),
                file_entry(&theirs, "1000", "5000"),
            ],
        };
        fs::write(journal_path(&d), serde_json::to_string(&j).unwrap()).unwrap();
        assert_eq!(Knobs::recover(&d).unwrap(), 1);
        assert_eq!(fs::read_to_string(&ours).unwrap(), "0");
        assert_eq!(fs::read_to_string(&theirs).unwrap(), "9000");
        assert!(!journal_path(&d).exists());
        assert_eq!(Knobs::recover(&d).unwrap(), 0);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn old_journal_without_applied_still_restores() {
        let s: Saved = serde_json::from_str(r#"{"kind":"file","path":"/x","value":"1"}"#).unwrap();
        assert!(matches!(s, Saved::File { ref applied, .. } if applied.is_empty()));
    }

    #[test]
    fn short_paths() {
        assert_eq!(
            short_path("/proc/sys/net/core/busy_poll"),
            "net.core.busy_poll"
        );
    }
}
