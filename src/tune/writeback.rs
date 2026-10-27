// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Dirty-page writeback limits (`vm.dirty_bytes`,
//! `vm.dirty_background_bytes`), held lower during a match so background
//! downloads and shader caches flush in small steps rather than in bursts.
//!
//! Only ever tightened: if the current limit is already lower, nothing
//! changes. The kernel keeps either a `_bytes` or a `_ratio` limit (setting
//! one zeroes the other), and `_bytes` can't be written back to 0, so a
//! ratio-based setup is restored by writing the ratio.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use log::debug;

use super::Knobs;
use super::journal::{Outcome, Saved};
use crate::config::Writeback;
use crate::util::{read_trim, write_str};

pub(super) const MIB: u64 = 1024 * 1024;

/// (`vm.<which>_bytes`, `vm.<which>_ratio`) for "dirty" or "dirty_background".
fn dirty_paths(which: &str) -> (PathBuf, PathBuf) {
    (
        PathBuf::from(format!("/proc/sys/vm/{which}_bytes")),
        PathBuf::from(format!("/proc/sys/vm/{which}_ratio")),
    )
}

fn read_u64(p: &Path) -> Option<u64> {
    read_trim(p).ok()?.parse().ok()
}

/// MemAvailable in bytes: what a ratio limit is a percentage of (roughly;
/// the kernel uses "dirtyable" memory, which is close to it).
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

impl Knobs {
    pub(super) fn apply_writeback(
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
            let prev = self.saved_get(&key).cloned();
            match self.saved_get_mut(&key) {
                Some(Saved::Dirty { applied, .. }) => *applied = target,
                _ => self.save(
                    &key,
                    Saved::Dirty {
                        which: which.into(),
                        bytes,
                        ratio,
                        applied: target,
                    },
                ),
            }
            if !self.persist() {
                self.put_back(&key, prev);
                continue;
            }
            match write_str(&bp, &target.to_string()) {
                Ok(()) => {
                    changes.push(format!("vm.{which}_bytes={target}"));
                    self.current.insert(key, format!("{mb} MiB"));
                }
                Err(e) => {
                    self.put_back(&key, prev);
                    self.warn_once(&format!("w:{key}"), || {
                        format!("cannot set vm.{which}_bytes: {e}")
                    });
                }
            }
        }
    }
}

/// Put a writeback limit back, unless it no longer holds what we set.
pub(super) fn restore(which: &str, bytes: u64, ratio: u64, applied: u64) -> Result<Outcome> {
    let (bp, rp) = dirty_paths(which);
    let cur = read_u64(&bp).unwrap_or(0);
    if applied != 0 && cur != applied {
        return Ok(Outcome::Kept(format!(
            "vm.{which}_bytes was changed by someone else during the match; leaving it"
        )));
    }
    if bytes != 0 {
        write_str(&bp, &bytes.to_string())?;
        Ok(Outcome::Restored(format!("vm.{which}_bytes = {bytes}")))
    } else {
        write_str(&rp, &ratio.to_string())?;
        Ok(Outcome::Restored(format!("vm.{which}_ratio = {ratio}")))
    }
}
