// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! sysctl knobs (`/proc/sys/...`).
//!
//! A profile value is either exact (`"50"`) or raise-only (`">=8388608"`).
//! Raise-only never lowers a value someone already sized larger, and for
//! multi-value sysctls it applies per field.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use log::debug;

use super::Knobs;
use super::journal::{Outcome, Saved};
use crate::config::Profile;
use crate::util::{norm_ws, read_trim, sysctl_path, write_str};

/// What a profile asks for one sysctl.
enum Want {
    Exact(String),
    /// Raise-only, per field.
    AtLeast(Vec<u64>),
}

/// "/proc/sys/net/core/busy_poll" -> "net.core.busy_poll", for messages.
pub fn short_path(path: &str) -> String {
    match path.strip_prefix("/proc/sys/") {
        Some(k) => k.replace('/', "."),
        None => path.to_string(),
    }
}

impl Knobs {
    pub(super) fn apply_sysctls(
        &mut self,
        profile: &Profile,
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

        for (k, v) in &profile.sysctl {
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
        if !self.persist() {
            for p in pending {
                self.put_back(&p.key, p.prev);
            }
            return;
        }
        for p in pending {
            match write_str(&p.path, &p.target) {
                Ok(()) => {
                    changes.push(format!("{}={}", p.label, p.target));
                    self.current.insert(p.key, p.target);
                }
                Err(e) => {
                    self.put_back(&p.key, p.prev);
                    let (label, target) = (p.label.clone(), p.target.clone());
                    self.warn_once(&format!("w:{}", p.key), || {
                        format!("cannot set {label}={target}: {e}")
                    });
                }
            }
        }
    }
}

/// Put a sysctl back to `value`, unless it no longer holds what we wrote.
pub(super) fn restore(path: &str, value: &str, applied: &str) -> Result<Outcome> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_paths() {
        assert_eq!(
            short_path("/proc/sys/net/core/busy_poll"),
            "net.core.busy_poll"
        );
    }
}
