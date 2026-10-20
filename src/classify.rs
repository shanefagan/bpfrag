// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// "Is this process a game?"  Traffic alone can't answer that: a Discord call
// is a steady 50 pkt/s UDP stream too. The original bpftune patches learned
// this the hard way (QUIC bursts, torrents, voice chat), and grew launcher
// lineage checks. Here every candidate is a specific process (the BPF side
// counts per tgid), so we can look at who it really is.
//
// Signals, strongest first:
//   BPFRAG_GAME=1/0 in the environment     explicit tag (Steam launch options)
//   allow / deny globs on comm + exe name   user + built-in lists
//   SteamAppId / SteamGameId                 anything Steam launched
//   LD_PRELOAD with gamemode / MangoHud      people only use these on games
//   exe/cmdline inside a game library        steamapps/common, ~/Games, ...
//   Wine / Proton (*.exe on the cmdline)
//   an ancestor that is a launcher           reaper, gamescope, lutris, umu...

use std::fs;
use std::path::Path;

use crate::config::Classify;
use crate::util::first_match;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Game(String),
    NotGame(String),
}

#[cfg(test)]
impl Verdict {
    pub fn is_game(&self) -> bool {
        matches!(self, Verdict::Game(_))
    }
    pub fn reason(&self) -> &str {
        match self {
            Verdict::Game(r) | Verdict::NotGame(r) => r,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcInfo {
    pub ppid: u32,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
    pub environ: Vec<(String, String)>,
    pub start_time: u64,
}

impl ProcInfo {
    pub fn exe_name(&self) -> &str {
        self.exe.rsplit('/').next().unwrap_or("")
    }
    pub fn env(&self, key: &str) -> Option<&str> {
        self.environ
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    /// The best human-readable name: comm, or the exe name for Wine
    /// preloaders whose comm has not been renamed yet.
    pub fn display_name(&self) -> String {
        if !self.comm.is_empty() {
            self.comm.clone()
        } else {
            self.exe_name().to_string()
        }
    }
}

/// /proc/<pid>/stat field 22 (starttime), used to spot PID reuse.
pub fn start_time(root: &Path, pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(root.join(pid.to_string()).join("stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    // after ") " the fields start at #3 (state); starttime is #22
    after.split_whitespace().nth(19)?.parse().ok()
}

pub fn read_proc(root: &Path, pid: u32) -> Option<ProcInfo> {
    let dir = root.join(pid.to_string());
    let status = fs::read_to_string(dir.join("status")).ok()?;
    let mut info = ProcInfo::default();
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            info.comm = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("PPid:") {
            info.ppid = v.trim().parse().unwrap_or(0);
        }
    }
    info.exe = fs::read_link(dir.join("exe"))
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
        .unwrap_or_default();
    info.cmdline = fs::read(dir.join("cmdline"))
        .map(|b| {
            String::from_utf8_lossy(&b)
                .split('\0')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    info.environ = fs::read(dir.join("environ"))
        .map(|b| {
            b.split(|c| *c == 0)
                .filter_map(|kv| {
                    let kv = String::from_utf8_lossy(kv);
                    let (k, v) = kv.split_once('=')?;
                    Some((k.to_string(), v.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    info.start_time = start_time(root, pid).unwrap_or(0);
    Some(info)
}

pub struct Classifier {
    root: std::path::PathBuf,
    allow: Vec<String>,
    deny: Vec<String>,
    launchers: Vec<String>,
    game_paths: Vec<String>,
}

const MAX_LINEAGE: usize = 12;

fn truthy(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

impl Classifier {
    pub fn new(cfg: &Classify) -> Self {
        Self::with_root(cfg, "/proc")
    }

    pub fn with_root(cfg: &Classify, root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            allow: cfg.allow.clone(),
            deny: cfg.deny_list(),
            launchers: cfg.launcher_list(),
            game_paths: cfg
                .game_path_list()
                .iter()
                .map(|s| s.to_lowercase())
                .collect(),
        }
    }

    pub fn read(&self, pid: u32) -> Option<ProcInfo> {
        read_proc(&self.root, pid)
    }

    pub fn classify(&self, pid: u32) -> (Verdict, Option<ProcInfo>) {
        let Some(info) = self.read(pid) else {
            return (Verdict::NotGame("process gone".into()), None);
        };
        (self.classify_info(&info), Some(info))
    }

    pub fn classify_info(&self, p: &ProcInfo) -> Verdict {
        if p.exe.is_empty() && p.cmdline.is_empty() {
            return Verdict::NotGame("kernel thread".into());
        }
        if let Some(v) = p.env("BPFRAG_GAME").and_then(truthy) {
            return if v {
                Verdict::Game("tagged BPFRAG_GAME=1".into())
            } else {
                Verdict::NotGame("tagged BPFRAG_GAME=0".into())
            };
        }

        let names = [p.comm.as_str(), p.exe_name()];
        if let Some(pat) = first_match(&self.allow, &names) {
            return Verdict::Game(format!("allow list '{pat}'"));
        }
        if let Some(pat) = first_match(&self.deny, &names) {
            return Verdict::NotGame(format!("deny list '{pat}'"));
        }

        for key in ["SteamGameId", "SteamAppId"] {
            if let Some(id) = p.env(key)
                && !id.is_empty()
                && id != "0"
            {
                return Verdict::Game(format!("Steam app {id}"));
            }
        }

        if let Some(preload) = p.env("LD_PRELOAD") {
            let pl = preload.to_lowercase();
            if pl.contains("gamemode") {
                return Verdict::Game("running under gamemode".into());
            }
            if pl.contains("mangohud") {
                return Verdict::Game("running with MangoHud".into());
            }
        }
        if p.env("MANGOHUD").and_then(truthy) == Some(true) {
            return Verdict::Game("running with MangoHud".into());
        }

        let exe_l = p.exe.to_lowercase();
        let cmd_l = p.cmdline.to_lowercase();
        if let Some(gp) = self
            .game_paths
            .iter()
            .find(|gp| exe_l.contains(gp.as_str()) || cmd_l.contains(gp.as_str()))
        {
            return Verdict::Game(format!("lives in a game library ({gp})"));
        }

        if p.exe_name().starts_with("wine") || cmd_l.contains(".exe") {
            return Verdict::Game("Wine/Proton process".into());
        }

        // Walk up the family tree looking for a launcher.
        let mut ppid = p.ppid;
        for _ in 0..MAX_LINEAGE {
            if ppid <= 1 {
                break;
            }
            let Some(anc) = self.read(ppid) else { break };
            let anc_names = [anc.comm.as_str(), anc.exe_name()];
            if let Some(pat) = first_match(&self.launchers, &anc_names) {
                return Verdict::Game(format!("launched by {} ('{pat}')", anc.display_name()));
            }
            if anc.cmdline.contains("SteamLaunch") {
                return Verdict::Game("launched by Steam (SteamLaunch)".into());
            }
            ppid = anc.ppid;
        }

        Verdict::NotGame("no game signals".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct FakeProc {
        dir: std::path::PathBuf,
    }

    impl FakeProc {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("bpfrag-test-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn add(&self, pid: u32, ppid: u32, comm: &str, exe: &str, cmdline: &[&str], env: &[&str]) {
            let d = self.dir.join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("status"), format!("Name:\t{comm}\nPPid:\t{ppid}\n")).unwrap();
            fs::write(
                d.join("stat"),
                format!("{pid} ({comm}) S {ppid} 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 0 0"),
            )
            .unwrap();
            let mut f = fs::File::create(d.join("cmdline")).unwrap();
            for a in cmdline {
                f.write_all(a.as_bytes()).unwrap();
                f.write_all(&[0]).unwrap();
            }
            let mut f = fs::File::create(d.join("environ")).unwrap();
            for e in env {
                f.write_all(e.as_bytes()).unwrap();
                f.write_all(&[0]).unwrap();
            }
            if !exe.is_empty() {
                std::os::unix::fs::symlink(exe, d.join("exe")).unwrap();
            }
        }
    }

    impl Drop for FakeProc {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn classifier(fp: &FakeProc) -> Classifier {
        Classifier::with_root(&Classify::default(), &fp.dir)
    }

    #[test]
    fn steam_proton_game() {
        let fp = FakeProc::new("steam");
        fp.add(100, 1, "steam", "/usr/lib/steam/steam", &["steam"], &[]);
        fp.add(
            200,
            100,
            "reaper",
            "/usr/lib/steam/reaper",
            &["reaper", "SteamLaunch", "AppId=730"],
            &["SteamAppId=730"],
        );
        fp.add(
            300,
            200,
            "cs2",
            "/home/u/.steam/steamapps/common/cs2/cs2",
            &["cs2"],
            &["SteamAppId=730"],
        );
        let c = classifier(&fp);
        assert_eq!(c.classify(300).0, Verdict::Game("Steam app 730".into()));
        // the Steam client itself is not a game
        assert!(!c.classify(100).0.is_game());
    }

    #[test]
    fn discord_is_not_a_game_even_from_a_launcher() {
        let fp = FakeProc::new("discord");
        fp.add(
            10,
            1,
            "gamescope",
            "/usr/bin/gamescope",
            &["gamescope"],
            &[],
        );
        fp.add(11, 10, "Discord", "/opt/discord/Discord", &["Discord"], &[]);
        let c = classifier(&fp);
        let v = c.classify(11).0;
        assert!(!v.is_game(), "{v:?}");
        assert!(v.reason().contains("deny"));
    }

    #[test]
    fn wine_and_lineage_and_tags() {
        let fp = FakeProc::new("misc");
        fp.add(
            20,
            1,
            "Overwatch.exe",
            "/usr/bin/wine64-preloader",
            &["Z:\\games\\Overwatch.exe"],
            &[],
        );
        fp.add(30, 1, "lutris", "/usr/bin/python3", &["lutris"], &[]);
        fp.add(31, 30, "bash", "/usr/bin/bash", &["bash"], &[]);
        fp.add(
            32,
            31,
            "nativegame",
            "/opt/nativegame/bin",
            &["/opt/nativegame/bin"],
            &[],
        );
        fp.add(
            40,
            1,
            "quake",
            "/usr/bin/quake",
            &["quake"],
            &["BPFRAG_GAME=1"],
        );
        fp.add(
            41,
            1,
            "firefox",
            "/usr/lib/firefox/firefox",
            &["firefox"],
            &["BPFRAG_GAME=1"],
        );
        fp.add(50, 1, "randomd", "/usr/bin/randomd", &["randomd"], &[]);
        fp.add(
            60,
            1,
            "game",
            "/usr/bin/game",
            &["game"],
            &["LD_PRELOAD=/usr/lib/libgamemodeauto.so.0"],
        );
        let c = classifier(&fp);
        assert_eq!(
            c.classify(20).0,
            Verdict::Game("Wine/Proton process".into())
        );
        assert!(c.classify(32).0.reason().contains("launched by lutris"));
        assert!(c.classify(40).0.is_game());
        // explicit tag beats the deny list
        assert!(c.classify(41).0.is_game());
        assert_eq!(c.classify(50).0, Verdict::NotGame("no game signals".into()));
        assert!(c.classify(60).0.reason().contains("gamemode"));
        assert!(!c.classify(999).0.is_game());
        assert_eq!(start_time(&fp.dir, 20), Some(4242));
    }
}
