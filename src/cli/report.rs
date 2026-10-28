// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! `bpfrag --report`: everything useful for a bug report, as Markdown to
//! paste into a GitHub issue: the bpfrag sections below, the service, the
//! qdiscs (CAKE's tin counters), the restore journal and the log.
//!
//! The bpfrag sections (`--check`, `--selftest`, `--monitor`,
//! `--dump-config`) run this same binary as a child process, so a crash in
//! one of them (an illegal instruction, say) shows up in the report instead
//! of ending it. The hostname, user names in home paths, and IP and MAC
//! addresses are replaced before anything is printed.

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use crate::util::{is_root, read_trim};

/// Journal lines to include from the current boot.
const LOG_LINES: &str = "300";

/// Run `prog args`, returning its stdout and stderr together, plus a note
/// if it failed or couldn't be started.
fn run(prog: &Path, args: &[&str]) -> String {
    match Command::new(prog).args(args).output() {
        Ok(out) => {
            let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.trim().is_empty() {
                if !s.is_empty() && !s.ends_with('\n') {
                    s.push('\n');
                }
                s += &err;
            }
            if !out.status.success() {
                let _ = write!(s, "\n(exited with {})", out.status);
            }
            s
        }
        Err(e) => format!("(could not run {}: {e})", prog.display()),
    }
}

fn section(out: &mut String, title: &str, body: &str) {
    let body = body.trim_end();
    let body = if body.is_empty() { "(nothing)" } else { body };
    let _ = write!(out, "### {title}\n\n```\n{body}\n```\n\n");
}

/// `PRETTY_NAME` from os-release.
fn os_name() -> String {
    ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into())
}

fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("model name")
                    .map(|v| v.trim_start_matches([' ', '\t', ':']).to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into())
}

pub fn run_report(config: Option<&Path>, run_dir: &Path) -> String {
    let me = std::env::current_exe().unwrap_or_else(|_| "bpfrag".into());
    let cfg_args: Vec<&str> = match config.and_then(Path::to_str) {
        Some(c) => vec!["--config", c],
        None => vec![],
    };
    let with_cfg = |flag: &str| -> String {
        let mut a = cfg_args.clone();
        a.push(flag);
        run(&me, &a)
    };

    let mut out = String::new();
    let _ = write!(
        out,
        "## bpfrag report\n\n\
         The hostname, user names, and IP and MAC addresses are replaced. \
         Read it through before posting.\n\n\
         - bpfrag: {}\n- OS: {}\n- kernel: {}\n- CPU: {}\n- run as root: {}\n\n",
        env!("CARGO_PKG_VERSION"),
        os_name(),
        read_trim("/proc/sys/kernel/osrelease").unwrap_or_default(),
        cpu_model(),
        if is_root() {
            "yes"
        } else {
            "no (some sections are incomplete)"
        },
    );

    section(&mut out, "bpfrag --check", &with_cfg("--check"));
    let selftest = if is_root() {
        with_cfg("--selftest")
    } else {
        "(skipped: needs root)".into()
    };
    section(&mut out, "bpfrag --selftest", &selftest);
    section(
        &mut out,
        "bpfrag --monitor 0",
        &run(&me, &["--monitor", "0"]),
    );
    section(
        &mut out,
        "Effective configuration",
        &with_cfg("--dump-config"),
    );

    let service = run(
        Path::new("systemctl"),
        &[
            "show",
            "bpfrag.service",
            "--property=UnitFileState,ActiveState,SubState,Result,ExecMainStatus,NRestarts",
        ],
    );
    section(&mut out, "Service", &service);

    // qdiscs, with CAKE's per-tin counters if CAKE is in use (does LE
    // traffic land in the Bulk tin?)
    section(
        &mut out,
        "tc -s qdisc",
        &run(Path::new("tc"), &["-s", "qdisc", "show"]),
    );

    let journal = run_dir.join("journal.json");
    let journal = match std::fs::read_to_string(&journal) {
        Ok(t) => t,
        Err(_) => "(none: no settings are currently changed)".into(),
    };
    section(&mut out, "Restore journal", &journal);

    let logs = run(
        Path::new("journalctl"),
        &[
            "-u",
            "bpfrag.service",
            "-b",
            "--no-pager",
            "-o",
            "short-iso",
            "-n",
            LOG_LINES,
        ],
    );
    section(&mut out, "Log (this boot)", &logs);

    let host = read_trim("/proc/sys/kernel/hostname").unwrap_or_default();
    redact(&out, &host)
}

/// Replace what identifies the machine or its network: the hostname, the
/// user part of `/home/<user>` paths, and IPv4, IPv6 and MAC addresses.
pub fn redact(text: &str, hostname: &str) -> String {
    let s = replace_word(text, hostname, "<host>");
    let s = redact_home(&s);
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '%' | '/') {
            token.push(c);
        } else {
            out += &redact_token(&token);
            token.clear();
            out.push(c);
        }
    }
    out += &redact_token(&token);
    out
}

/// Replace `word` where it isn't part of a longer name (so a host called
/// "arch" doesn't turn `x86_64-arch` into `x86_64-<host>`).
fn replace_word(s: &str, word: &str, with: &str) -> String {
    if word.is_empty() {
        return s.to_string();
    }
    let is_name = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/');
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(word) {
        let before = if i > 0 {
            rest[..i].chars().last()
        } else {
            out.chars().last()
        };
        let after = rest[i + word.len()..].chars().next();
        out += &rest[..i];
        if before.is_some_and(is_name) || after.is_some_and(is_name) {
            out += word;
        } else {
            out += with;
        }
        rest = &rest[i + word.len()..];
    }
    out + rest
}

fn redact_home(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("/home/") {
        out += &rest[..i + "/home/".len()];
        rest = &rest[i + "/home/".len()..];
        let end = rest
            .find(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(rest.len());
        if end > 0 {
            out += "<user>";
        }
        rest = &rest[end..];
    }
    out + rest
}

/// A token is an address if it is (an address followed by) a `/prefix`:
/// four dotted decimal octets, or hex groups joined by colons.
fn redact_token(t: &str) -> String {
    // Leading/trailing dots and colons are punctuation, not address.
    let core = t.trim_end_matches(['.', ':']);
    let tail = &t[core.len()..];
    let addr = core.split(['/', '%']).next().unwrap_or("");
    // 192.0.2.7:27015
    if let Some((ip, port)) = addr.rsplit_once(':') {
        if is_ipv4(ip) && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            return format!("<ip>:{port}{tail}");
        }
    }
    if is_ipv4(addr) {
        if addr == "127.0.0.1" || addr == "0.0.0.0" {
            return t.to_string();
        }
        return format!("<ip>{tail}");
    }
    if is_ipv6_or_mac(addr) {
        if addr == "::1" || addr == "::" {
            return t.to_string();
        }
        return format!("<addr>{tail}");
    }
    t.to_string()
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// IPv6 (`fe80::1`, `2001:db8:0:1::5`) or MAC (`aa:bb:cc:dd:ee:ff`). Clock
/// times like `19:02:43` have digits only and fewer groups, so they stay.
fn is_ipv6_or_mac(s: &str) -> bool {
    let colons = s.matches(':').count();
    if colons < 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    {
        return false;
    }
    let groups_ok = s.split(':').all(|g| g.len() <= 4 || is_ipv4(g));
    let has_letter = s.bytes().any(|b| b.is_ascii_alphabetic());
    groups_ok && (s.contains("::") || colons >= 5 || (has_letter && colons >= 3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_names_are_replaced() {
        let t = "gamer-pc bpfrag[812]: peer 192.168.1.20:27015, server 2a01:4f8:c0c:1::5/64 \
                 via fe80::1%eno1 mac aa:bb:cc:dd:ee:ff, file /home/shane/.config/x";
        let r = redact(t, "gamer-pc");
        assert_eq!(
            r,
            "<host> bpfrag[812]: peer <ip>:27015, server <addr> \
             via <addr> mac <addr>, file /home/<user>/.config/x"
        );
    }

    #[test]
    fn hostname_only_as_a_whole_name() {
        assert_eq!(
            redact("arch: x86_64-arch archive arch", "arch"),
            "<host>: x86_64-arch archive <host>"
        );
        assert_eq!(redact("vm vm.dirty_ratio", "vm"), "<host> vm.dirty_ratio");
    }

    #[test]
    fn times_versions_and_loopback_stay() {
        let t = "2026-10-27T19:02:43+0000 at 19:02:43, libbpf 1.7.0, 127.0.0.1 and ::1, \
                 kernel 6.18.44-fc-v165, ratio 10:1";
        assert_eq!(redact(t, ""), t);
    }
}
