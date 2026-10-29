// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Processes tagged `BPFRAG_OBSERVE=1` in their environment, for example
//! with `BPFRAG_OBSERVE=1 %command%` in a game's Steam launch options. Their
//! UDP and TCP traffic is logged ([`super::observe`]) whatever it looks
//! like, so a game whose traffic isn't known yet can be studied before
//! deciding how to detect or tune it. The tag changes nothing else: whether
//! the process is a game, and whether its traffic starts a match, are up to
//! the classifier and the detector as usual.
//!
//! The environment can't be seen from the BPF side, so new processes are
//! found by listing /proc every few seconds and reading the environment of
//! the ones not seen before. Children inherit the tag, so a launcher's
//! whole process tree is covered.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::classify::truthy;

/// The environment variable.
pub const VAR: &str = "BPFRAG_OBSERVE";

#[derive(Debug)]
pub struct Tagged {
    root: PathBuf,
    /// Every process seen so far, and whether it's tagged.
    known: HashMap<u32, bool>,
}

/// What a scan found: processes newly tagged, and tagged ones now gone.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: Vec<u32>,
    pub gone: Vec<u32>,
}

impl Default for Tagged {
    fn default() -> Self {
        Self::with_root("/proc")
    }
}

impl Tagged {
    pub fn with_root(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            known: HashMap::new(),
        }
    }

    /// List the processes, read the environment of new ones, and forget
    /// those that exited.
    pub fn scan(&mut self) -> Changes {
        let mut ch = Changes::default();
        let Ok(dir) = fs::read_dir(&self.root) else {
            return ch;
        };
        let mut present = Vec::with_capacity(self.known.len() + 64);
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            present.push(pid);
            if self.known.contains_key(&pid) {
                continue;
            }
            let tagged = fs::read(e.path().join("environ")).is_ok_and(|env| has_tag(&env));
            if tagged {
                ch.added.push(pid);
            }
            self.known.insert(pid, tagged);
        }
        present.sort_unstable();
        self.known.retain(|pid, tagged| {
            let alive = present.binary_search(pid).is_ok();
            if !alive && *tagged {
                ch.gone.push(*pid);
            }
            alive
        });
        ch.added.sort_unstable();
        ch.gone.sort_unstable();
        ch
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.known.get(&pid).copied().unwrap_or(false)
    }

    pub fn is_empty(&self) -> bool {
        !self.known.values().any(|t| *t)
    }
}

/// Does a `/proc/<pid>/environ` block carry a true `BPFRAG_OBSERVE`?
fn has_tag(environ: &[u8]) -> bool {
    environ.split(|b| *b == 0).any(|kv| {
        kv.strip_prefix(VAR.as_bytes())
            .and_then(|rest| rest.strip_prefix(b"="))
            .is_some_and(|v| truthy(&String::from_utf8_lossy(v)) == Some(true))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bpfrag-tagged-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn add(root: &Path, pid: u32, env: &[&str]) {
        let d = root.join(pid.to_string());
        fs::create_dir_all(&d).unwrap();
        let mut b = Vec::new();
        for e in env {
            b.extend_from_slice(e.as_bytes());
            b.push(0);
        }
        fs::write(d.join("environ"), b).unwrap();
    }

    #[test]
    fn the_tag_is_read_from_the_environment() {
        assert!(has_tag(b"HOME=/home/u\0BPFRAG_OBSERVE=1\0"));
        assert!(has_tag(b"BPFRAG_OBSERVE=yes"));
        assert!(!has_tag(b"BPFRAG_OBSERVE=0\0"));
        assert!(!has_tag(b"BPFRAG_OBSERVE=\0"));
        assert!(!has_tag(b"BPFRAG_OBSERVED=1\0XBPFRAG_OBSERVE=1\0"));
        assert!(!has_tag(b""));
    }

    #[test]
    fn scans_report_new_and_gone_tagged_processes() {
        let root = proc_dir("scan");
        add(&root, 10, &["PATH=/usr/bin"]);
        add(&root, 11, &["SteamAppId=2694490", "BPFRAG_OBSERVE=1"]);
        fs::create_dir_all(root.join("self")).unwrap(); // not a pid
        let mut t = Tagged::with_root(&root);
        assert!(t.is_empty());
        assert_eq!(
            t.scan(),
            Changes {
                added: vec![11],
                gone: vec![]
            }
        );
        assert!(t.contains(11) && !t.contains(10) && !t.is_empty());

        // a child of the game starts; nothing else changes
        add(&root, 12, &["BPFRAG_OBSERVE=1"]);
        assert_eq!(t.scan().added, vec![12]);
        assert_eq!(
            t.scan(),
            Changes::default(),
            "known processes aren't re-read"
        );

        // the game exits, and so does an untagged process
        fs::remove_dir_all(root.join("11")).unwrap();
        fs::remove_dir_all(root.join("10")).unwrap();
        assert_eq!(
            t.scan(),
            Changes {
                added: vec![],
                gone: vec![11]
            }
        );
        assert!(!t.contains(11) && t.contains(12));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unreadable_environment_is_not_tagged() {
        let root = proc_dir("unreadable");
        fs::create_dir_all(root.join("20")).unwrap(); // no environ file
        let mut t = Tagged::with_root(&root);
        assert_eq!(t.scan(), Changes::default());
        assert!(!t.contains(20));
        let _ = fs::remove_dir_all(&root);
    }
}
