// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// ASCII case-insensitive glob with `*` (any run) and `?` (any byte).
/// Works on bytes and allocates nothing; process names are short and the
/// patterns are plain ASCII.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// First pattern in `patterns` matching any of `names`.
pub fn first_match<'a>(patterns: &'a [String], names: &[&str]) -> Option<&'a str> {
    patterns.iter().find_map(|p| {
        names
            .iter()
            .any(|n| !n.is_empty() && glob_match(p, n))
            .then_some(p.as_str())
    })
}

pub fn read_trim(path: impl AsRef<Path>) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}

pub fn write_str(path: impl AsRef<Path>, value: &str) -> io::Result<()> {
    fs::write(path, value.as_bytes())
}

/// Collapse whitespace so "4096\t131072  6291456" == "4096 131072 6291456".
pub fn norm_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn sysctl_path(key: &str) -> Option<PathBuf> {
    let ok = !key.is_empty()
        && !key.contains("..")
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    ok.then(|| PathBuf::from("/proc/sys").join(key.replace('.', "/")))
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(glob_match("steam", "Steam"));
        assert!(!glob_match("steam", "steamwebhelper"));
        assert!(glob_match("steam*", "steamwebhelper"));
        assert!(glob_match("*.exe", "eldenring.exe"));
        assert!(glob_match("pressure-vessel*", "pressure-vessel-wrap"));
        assert!(glob_match("chrom?um", "chromium"));
        assert!(!glob_match("discord", "discordo"));
        assert!(glob_match("*", ""));
        assert!(glob_match("ISOLATED WEB CO", "Isolated Web Co"));
        assert!(!glob_match("a*b", "acd"));
        assert!(glob_match("*.EXE", "Overwatch.exe"));
    }

    #[test]
    fn sysctl_paths() {
        assert_eq!(
            sysctl_path("net.core.rmem_max").unwrap(),
            PathBuf::from("/proc/sys/net/core/rmem_max")
        );
        assert!(sysctl_path("../../etc/shadow").is_none());
        assert!(sysctl_path("net core").is_none());
    }

    #[test]
    fn whitespace() {
        assert_eq!(norm_ws("4096\t131072  6291456\n"), "4096 131072 6291456");
    }
}
