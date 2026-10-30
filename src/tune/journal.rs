// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! The restore journal: `/run/bpfrag/journal.json`.
//!
//! Before any knob changes, its original value (and what we are about to
//! write) is saved here. Restoring walks the entries newest first. If the
//! daemon dies mid-match, `bpfrag --restore` (the unit's ExecStopPost) or
//! the next start replays it. `/run` is tmpfs, so a reboot clears the
//! journal together with the settings it describes.
//!
//! Entries written by older versions must keep loading, so new fields get
//! `#[serde(default)]`.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};

use super::{coalesce, sysctl, wifi, writeback};
use crate::net::ethtool::Coalesce;

/// One knob's state before bpfrag changed it.
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
    /// ethtool coalescing words, and the rx-usecs we set
    Coalesce {
        ifname: String,
        words: Vec<u32>,
        #[serde(default)]
        applied: Option<u32>,
    },
    /// `vm.dirty[_background]_{bytes,ratio}` before, and the bytes we set
    Dirty {
        which: String,
        bytes: u64,
        ratio: u64,
        #[serde(default)]
        applied: u64,
    },
    /// A classic tc filter that bpfrag 0.1 used on kernels before 6.6.
    /// Never written any more; kept so such a journal still loads and its
    /// other entries get restored.
    TcLegacy { ifindex: i32 },
    /// Wi-Fi power save state before the match (we only ever turn it off)
    WifiPs { ifname: String, enabled: bool },
}

impl Saved {
    /// The original value, as shown in `--monitor` ("was ...").
    pub fn baseline(&self) -> String {
        match self {
            Saved::File { value, .. } => value.clone(),
            Saved::Coalesce { words, .. } => {
                format!("{}us", Coalesce::from_words(words).rx_usecs())
            }
            Saved::WifiPs { enabled, .. } => (if *enabled { "on" } else { "off" }).into(),
            Saved::Dirty { bytes, ratio, .. } => {
                if *bytes > 0 {
                    format!("{} MiB", bytes / writeback::MIB)
                } else {
                    format!("{ratio}% of RAM")
                }
            }
            Saved::TcLegacy { .. } => String::new(),
        }
    }
}

/// The file format: who wrote it, and (key, original) pairs in the order
/// they were changed.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Journal {
    pub pid: u32,
    pub entries: Vec<(String, Saved)>,
}

pub enum Outcome {
    Restored(String),
    /// someone else changed it during the match; left alone
    Kept(String),
}

pub fn journal_path(run_dir: &Path) -> PathBuf {
    run_dir.join("journal.json")
}

/// Write the journal atomically (temp file, fsync, rename), or remove it
/// when there is nothing left to restore.
pub(super) fn write(path: &Path, entries: &[(String, Saved)]) -> Result<()> {
    if entries.is_empty() {
        return match fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        };
    }
    if let Some(d) = path.parent() {
        fs::create_dir_all(d)?;
    }
    let j = Journal {
        pid: std::process::id(),
        entries: entries.to_vec(),
    };
    let tmp = path.with_extension("json.tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(serde_json::to_string_pretty(&j)?.as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Restore one saved item. Each knob type restores itself, applying the
/// "leave it if someone else changed it" rule where that can be checked.
pub fn restore_one(saved: &Saved) -> Result<Outcome> {
    match saved {
        Saved::File {
            path,
            value,
            applied,
        } => sysctl::restore(path, value, applied),
        Saved::Coalesce {
            ifname,
            words,
            applied,
        } => coalesce::restore(ifname, words, *applied),
        Saved::Dirty {
            which,
            bytes,
            ratio,
            applied,
        } => writeback::restore(which, *bytes, *ratio, *applied),
        Saved::WifiPs { ifname, enabled } => wifi::restore(ifname, *enabled),
        Saved::TcLegacy { ifindex } => Ok(Outcome::Kept(format!(
            "tc filter on interface #{ifindex}, left by an older bpfrag \
             (tc filter del dev <interface> egress, or a reboot, removes it)"
        ))),
    }
}

/// The entries a journal holds; none if there is no journal or it can't be
/// read.
pub(super) fn load(path: &Path) -> Vec<(String, Saved)> {
    fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Journal>(&t).ok())
        .map(|j| j.entries)
        .unwrap_or_default()
}

/// Undo whatever a previous (crashed or killed) instance left behind.
/// Entries that couldn't be restored (an interface that's gone, say) stay
/// in the journal for the next try; the rest are removed. Returns how many
/// settings were restored.
pub fn recover(run_dir: &Path) -> Result<usize> {
    let path = journal_path(run_dir);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).context("reading journal"),
    };
    let j: Journal = serde_json::from_str(&text).context("parsing journal")?;
    let mut n = 0;
    let mut failed = Vec::new();
    for (key, saved) in j.entries.iter().rev() {
        match restore_one(saved) {
            Ok(Outcome::Restored(what)) => {
                info!("restored {what}");
                n += 1;
            }
            Ok(Outcome::Kept(why)) => info!("{why}"),
            Err(e) => {
                warn!("could not restore {key}: {e:#}; kept in the journal to try again");
                failed.push((key.clone(), saved.clone()));
            }
        }
    }
    failed.reverse();
    write(&path, &failed).context("updating journal")?;
    Ok(n)
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
        assert_eq!(recover(&d).unwrap(), 1);
        assert_eq!(fs::read_to_string(&ours).unwrap(), "0");
        assert_eq!(fs::read_to_string(&theirs).unwrap(), "9000");
        assert!(!journal_path(&d).exists());
        assert_eq!(recover(&d).unwrap(), 0);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn what_cant_be_restored_stays_in_the_journal() {
        let d = tmpdir("failed");
        let ours = d.join("ours");
        fs::write(&ours, "50").unwrap();
        // a sysctl whose file is gone: writing it fails
        let gone = d.join("gone/x");
        let j = Journal {
            pid: 1,
            entries: vec![file_entry(&ours, "0", "50"), file_entry(&gone, "1", "")],
        };
        fs::write(journal_path(&d), serde_json::to_string(&j).unwrap()).unwrap();
        assert_eq!(recover(&d).unwrap(), 1);
        assert_eq!(fs::read_to_string(&ours).unwrap(), "0");
        let left = load(&journal_path(&d));
        assert_eq!(left, vec![file_entry(&gone, "1", "")]);
        // once it can be restored, it is, and the journal goes
        fs::create_dir_all(gone.parent().unwrap()).unwrap();
        fs::write(&gone, "7").unwrap();
        assert_eq!(recover(&d).unwrap(), 1);
        assert_eq!(fs::read_to_string(&gone).unwrap(), "1");
        assert!(!journal_path(&d).exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn old_journal_without_applied_still_restores() {
        let s: Saved = serde_json::from_str(r#"{"kind":"file","path":"/x","value":"1"}"#).unwrap();
        assert!(matches!(s, Saved::File { ref applied, .. } if applied.is_empty()));
    }

    #[test]
    fn write_then_empty_removes_the_file() {
        let d = tmpdir("write");
        let p = journal_path(&d);
        write(&p, &[file_entry(&d.join("x"), "1", "2")]).unwrap();
        assert!(p.exists());
        write(&p, &[]).unwrap();
        assert!(!p.exists());
        let _ = fs::remove_dir_all(&d);
    }
}
