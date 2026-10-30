// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! "Is this process a game?"  Traffic alone can't answer that: a Discord call
//! is a steady 50 pkt/s UDP stream too. The original bpftune patches learned
//! this the hard way (QUIC bursts, torrents, voice chat), and grew launcher
//! lineage checks. Here every candidate is a specific process (the BPF side
//! counts per tgid), so we can look at who it really is.
//!
//! Signals, strongest first:
//!
//! ```text
//! BPFRAG_GAME=1/0 in the environment     explicit tag (Steam launch options)
//! allow / deny globs on comm + exe name   user + built-in lists
//! SteamAppId / SteamGameId                anything Steam launched
//! LD_PRELOAD with gamemode / MangoHud     people only use these on games
//! exe/cmdline inside a game library       steamapps/common, ~/Games, ...
//! Wine / Proton                           wine* binary, or argv[0] is an .exe
//! an ancestor that is a launcher          reaper, gamescope, lutris, umu...
//! ```
//!
//! [`ProcfsLookup`] wraps the classifier with a cache for the daemon.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use super::ProcessLookup;
use crate::config::Classify;
use crate::util::first_match;

/// The classifier's answer, with the signal that decided it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Game(String),
    /// Ruled out on purpose: a deny list entry or BPFRAG_GAME=0.
    Excluded(String),
    /// No game signals found.
    NotGame(String),
}

impl Verdict {
    pub fn reason(&self) -> &str {
        match self {
            Verdict::Game(r) | Verdict::Excluded(r) | Verdict::NotGame(r) => r,
        }
    }

    /// `game: <why>` / `not a game: <why>`, for status output.
    pub fn describe(&self) -> String {
        match self {
            Verdict::Game(r) => format!("game: {r}"),
            Verdict::Excluded(r) | Verdict::NotGame(r) => format!("not a game: {r}"),
        }
    }

    #[cfg(test)]
    pub fn is_game(&self) -> bool {
        matches!(self, Verdict::Game(_))
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcInfo {
    pub ppid: u32,
    pub comm: String,
    pub exe: String,
    pub cwd: String,
    pub cmdline: String,
    pub args: Vec<String>,
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
    /// The best human-readable name. A game's main thread is often called
    /// something like "MainThrd", so prefer, in order: the Steam title from
    /// the library's appmanifest, the Windows .exe a Wine process runs, the
    /// process name.
    pub fn display_name(&self) -> String {
        if let Some(t) = self.steam_title() {
            return t;
        }
        if let Some(e) = self.wine_exe() {
            return e;
        }
        if !self.comm.is_empty() {
            self.comm.clone()
        } else {
            self.exe_name().to_string()
        }
    }

    /// Paths that may sit inside a Steam library: cwd, exe, and every
    /// argument (Windows paths under Proton are Z:\home\...).
    fn path_candidates(&self) -> impl Iterator<Item = String> + '_ {
        [self.cwd.clone(), self.exe.clone()]
            .into_iter()
            .chain(self.args.iter().map(|a| {
                let a = a.replace('\\', "/");
                match a.get(..2) {
                    Some(d) if d.eq_ignore_ascii_case("z:") => a[2..].to_string(),
                    _ => a,
                }
            }))
            .filter(|p| p.starts_with('/'))
    }

    /// See [`ProcfsLookup::app_id`].
    pub fn app_id(&self) -> u32 {
        ["SteamAppId", "SteamGameId"]
            .iter()
            .filter_map(|k| self.env(k))
            .find_map(|v| v.parse::<u32>().ok().filter(|n| *n != 0))
            .unwrap_or(0)
    }

    fn steam_title(&self) -> Option<String> {
        let id = ["SteamAppId", "SteamGameId"]
            .iter()
            .filter_map(|k| self.env(k))
            .find(|v| !v.is_empty() && *v != "0" && v.bytes().all(|b| b.is_ascii_digit()))?;
        for p in self.path_candidates() {
            // ASCII-only lowercasing keeps byte offsets valid for slicing `p`
            let lower = p.to_ascii_lowercase();
            let Some(i) = lower
                .find("/steamapps/")
                .or_else(|| lower.ends_with("/steamapps").then(|| lower.len() - 10))
            else {
                continue;
            };
            let manifest =
                Path::new(&p[..i + "/steamapps".len()]).join(format!("appmanifest_{id}.acf"));
            if let Some(name) = manifest_name(&manifest) {
                return Some(name);
            }
        }
        None
    }

    /// Tagged `BPFRAG_OBSERVE=1`: its traffic is logged.
    pub fn observe_tagged(&self) -> bool {
        self.env(super::tagged::VAR).and_then(truthy) == Some(true)
    }

    /// The program itself: the Windows .exe a Wine process runs, or the
    /// process name. Tells a game apart from its launcher or helpers when
    /// they share a display name.
    pub fn program(&self) -> String {
        self.wine_exe().unwrap_or_else(|| {
            if self.comm.is_empty() {
                self.exe_name().to_string()
            } else {
                self.comm.clone()
            }
        })
    }

    fn wine_exe(&self) -> Option<String> {
        let a = self.args.iter().find(|a| is_exe(a))?;
        let base = a.rsplit(['/', '\\']).next()?;
        let stem = &base[..base.len() - 4];
        (!stem.is_empty()).then(|| stem.to_string())
    }
}

fn is_exe(arg: &str) -> bool {
    arg.len() > 4 && arg.as_bytes()[arg.len() - 4..].eq_ignore_ascii_case(b".exe")
}

/// `"name"  "Deadlock"` from a Steam `appmanifest_<id>.acf`.
/// A Steam appmanifest is a few KiB; anything bigger isn't one.
const MANIFEST_MAX: u64 = 256 * 1024;

/// The game's title from a Steam appmanifest. The path comes from the
/// process's own arguments and working directory, so any user can point
/// it anywhere: only a small regular file is read, and opening doesn't
/// wait (a FIFO there would otherwise block the daemon, and /dev/zero
/// never ends).
fn manifest_name(path: &Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > MANIFEST_MAX {
        return None;
    }
    let mut text = String::new();
    f.take(MANIFEST_MAX).read_to_string(&mut text).ok()?;
    text.lines().find_map(|l| {
        let parts: Vec<&str> = l.trim().split('"').collect();
        // ["", "name", "\t\t", "Deadlock", ""]
        (parts.len() >= 4 && parts[1] == "name" && !parts[3].is_empty())
            .then(|| parts[3].to_string())
    })
}

/// `/proc/<pid>/stat` field 22 (starttime), used to spot PID reuse.
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
    info.cwd = fs::read_link(dir.join("cwd"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    info.args = fs::read(dir.join("cmdline"))
        .map(|b| {
            String::from_utf8_lossy(&b)
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    info.cmdline = info.args.join(" ");
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

pub(super) fn truthy(v: &str) -> Option<bool> {
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
                Verdict::Excluded("tagged BPFRAG_GAME=0".into())
            };
        }

        let names = [p.comm.as_str(), p.exe_name()];
        if let Some(pat) = first_match(&self.allow, &names) {
            return Verdict::Game(format!("allow list '{pat}'"));
        }
        if let Some(pat) = first_match(&self.deny, &names) {
            return Verdict::Excluded(format!("deny list '{pat}'"));
        }

        for key in ["SteamGameId", "SteamAppId"] {
            if let Some(id) = p.env(key).filter(|id| !id.is_empty() && *id != "0") {
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

        // Wine shows the Windows program as argv[0].
        if p.exe_name().starts_with("wine") || p.args.first().is_some_and(|a| is_exe(a)) {
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

/// How long a verdict is reused before /proc is read again.
const VERDICT_TTL: Duration = Duration::from_secs(30);

/// One cached verdict. `start` (the process start time) tells a reused pid
/// apart from the process the verdict was for.
struct Cached {
    start: u64,
    verdict: Verdict,
    name: String,
    at: Instant,
}

/// The classifier over the real /proc, with a short-lived cache: the
/// daemon asks about the same handful of processes every second.
pub struct ProcfsLookup {
    classifier: Classifier,
    cache: HashMap<u32, Cached>,
}

impl ProcfsLookup {
    pub fn new(cfg: &Classify) -> Self {
        Self {
            classifier: Classifier::new(cfg),
            cache: HashMap::new(),
        }
    }

    /// Verdict and display name for `tgid`.
    pub fn lookup(&mut self, tgid: u32) -> (Verdict, String) {
        let start = start_time(Path::new("/proc"), tgid).unwrap_or(0);
        if let Some(c) = self
            .cache
            .get(&tgid)
            .filter(|c| c.start == start && c.at.elapsed() < VERDICT_TTL)
        {
            return (c.verdict.clone(), c.name.clone());
        }
        let (verdict, info) = self.classifier.classify(tgid);
        let name = info
            .map(|i| i.display_name())
            .unwrap_or_else(|| format!("pid {tgid}"));
        let cached = Cached {
            start,
            verdict: verdict.clone(),
            name: name.clone(),
            at: Instant::now(),
        };
        self.cache.insert(tgid, cached);
        if self.cache.len() > 512 {
            self.cache.retain(|_, c| c.at.elapsed() < VERDICT_TTL);
        }
        (verdict, name)
    }
}

impl ProcfsLookup {
    /// "Some Game (SomeGame-Win64, pid 4242)", or "randomd (pid
    /// 77)" when the program is what the process is called anyway.
    pub fn label(&self, tgid: u32) -> String {
        let Some(info) = self.classifier.read(tgid) else {
            return format!("pid {tgid}");
        };
        let (name, prog) = (info.display_name(), info.program());
        if prog.is_empty() || prog == name {
            format!("{name} (pid {tgid})")
        } else {
            format!("{name} ({prog}, pid {tgid})")
        }
    }

    /// The Steam app id from its environment (SteamAppId, else
    /// SteamGameId); 0 for anything Steam didn't launch, or a non-Steam
    /// game added to Steam (whose SteamGameId is a large shortcut id).
    pub fn app_id(&self, tgid: u32) -> u32 {
        self.classifier.read(tgid).map_or(0, |i| i.app_id())
    }

    /// Display name, and the names lists are matched against (comm, exe
    /// name). None if the process is gone.
    pub fn names(&self, tgid: u32) -> Option<(String, Vec<String>)> {
        let info = self.classifier.read(tgid)?;
        let all = vec![info.comm.clone(), info.exe_name().to_string()];
        Some((info.display_name(), all))
    }
}

impl ProcessLookup for ProcfsLookup {
    fn verdict(&mut self, tgid: u32) -> (Verdict, String) {
        self.lookup(tgid)
    }

    fn alive(&mut self, tgid: u32) -> bool {
        Path::new(&format!("/proc/{tgid}")).exists()
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

        fn cwd(&self, pid: u32, cwd: &Path) {
            std::os::unix::fs::symlink(cwd, self.dir.join(pid.to_string()).join("cwd")).unwrap();
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
    fn manifests_must_be_small_regular_files() {
        let fp = FakeProc::new("manifest");
        let lib = fp.dir.join("lib/steamapps");
        fs::create_dir_all(&lib).unwrap();
        let good = lib.join("appmanifest_1.acf");
        fs::write(&good, "\"AppState\"\n{\n\t\"name\"\t\t\"Deadlock\"\n}\n").unwrap();
        assert_eq!(manifest_name(&good).as_deref(), Some("Deadlock"));
        // a FIFO: opening it must not wait for a writer
        let fifo = lib.join("appmanifest_2.acf");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(manifest_name(&fifo), None);
        // a device that never ends
        let zero = lib.join("appmanifest_3.acf");
        std::os::unix::fs::symlink("/dev/zero", &zero).unwrap();
        assert_eq!(manifest_name(&zero), None);
        // too big to be a manifest
        let big = lib.join("appmanifest_4.acf");
        fs::write(&big, vec![b'x'; MANIFEST_MAX as usize + 1]).unwrap();
        assert_eq!(manifest_name(&big), None);
    }

    #[test]
    fn steam_app_ids() {
        let info = |env: &[(&str, &str)]| ProcInfo {
            environ: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        };
        assert_eq!(info(&[("SteamAppId", "1422450")]).app_id(), 1422450);
        assert_eq!(info(&[("SteamGameId", "730")]).app_id(), 730);
        assert_eq!(
            info(&[("SteamAppId", "0"), ("SteamGameId", "2357570")]).app_id(),
            2357570
        );
        // a non-Steam game added to Steam: a shortcut id, not an app
        assert_eq!(info(&[("SteamGameId", "12345678901234567890")]).app_id(), 0);
        assert_eq!(info(&[]).app_id(), 0);
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
    fn names_come_from_steam_manifest_or_wine_exe() {
        let fp = FakeProc::new("names");
        // a Steam library with Deadlock's manifest
        let lib = fp.dir.join("lib/steamapps");
        let game = lib.join("common/Deadlock/game/bin/win64");
        fs::create_dir_all(&game).unwrap();
        fs::write(
            lib.join("appmanifest_1422450.acf"),
            "\"AppState\"\n{\n\t\"appid\"\t\t\"1422450\"\n\t\"name\"\t\t\"Deadlock\"\n}\n",
        )
        .unwrap();
        let winpath = format!("Z:{}\\project8.exe", game.display()).replace('/', "\\");
        // found via cwd
        fp.add(
            10,
            1,
            "MainThrd",
            "/usr/bin/wine64-preloader",
            &[&winpath],
            &["SteamAppId=1422450"],
        );
        fp.cwd(10, &game);
        // found via the Z:\ argument only
        fp.add(
            11,
            1,
            "MainThrd",
            "/usr/bin/wine64-preloader",
            &[&winpath],
            &["SteamAppId=1422450"],
        );
        // no manifest: fall back to the .exe stem, then comm
        fp.add(
            12,
            1,
            "MainThrd",
            "/usr/bin/wine64-preloader",
            &["C:\\Games\\Overwatch.exe"],
            &[],
        );
        fp.add(
            13,
            1,
            "cs2",
            "/opt/cs2/cs2",
            &["/opt/cs2/cs2", "-steam"],
            &["SteamAppId=730"],
        );
        let c = classifier(&fp);
        assert_eq!(c.read(10).unwrap().display_name(), "Deadlock");
        assert_eq!(c.read(11).unwrap().display_name(), "Deadlock");
        assert_eq!(c.read(12).unwrap().display_name(), "Overwatch");
        assert_eq!(c.read(13).unwrap().display_name(), "cs2");
    }

    #[test]
    fn deny_list_is_precise() {
        let fp = FakeProc::new("deny");
        fp.add(
            20,
            1,
            "SignalRgb",
            "/usr/bin/wine64-preloader",
            &["C:\\SignalRgb.exe"],
            &[],
        );
        fp.add(
            21,
            1,
            "signal-desktop",
            "/opt/Signal/signal-desktop",
            &["signal-desktop"],
            &[],
        );
        fp.add(22, 1, "Discord", "/opt/discord/Discord", &["Discord"], &[]);
        fp.add(23, 1, "brave", "/opt/brave/brave", &["brave"], &[]);
        // real games whose names start like denied apps
        fp.add(
            30,
            1,
            "SIGNALIS",
            "/usr/bin/wine64-preloader",
            &["Z:\\g\\SIGNALIS.exe"],
            &["SteamAppId=1262350"],
        );
        fp.add(
            31,
            1,
            "BravelyDefault",
            "/usr/bin/wine64-preloader",
            &["Z:\\g\\BravelyDefault2.exe"],
            &["SteamAppId=1219450"],
        );
        fp.add(
            32,
            1,
            "Zoombinis",
            "/opt/z/Zoombinis",
            &["Zoombinis"],
            &["SteamAppId=339910"],
        );
        let c = classifier(&fp);
        for pid in [20, 21, 22, 23] {
            let v = c.classify(pid).0;
            assert!(
                matches!(&v, Verdict::Excluded(r) if r.contains("deny")),
                "{pid}: {v:?}"
            );
        }
        for pid in [30, 31, 32] {
            assert!(c.classify(pid).0.is_game(), "{pid}");
        }
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
        fp.add(
            42,
            1,
            "cs2",
            "/opt/cs2/cs2",
            &["cs2"],
            &["SteamAppId=730", "BPFRAG_GAME=0"],
        );
        fp.add(50, 1, "randomd", "/usr/bin/randomd", &["randomd"], &[]);
        fp.add(
            52,
            1,
            "MainThrd",
            "/usr/bin/wine64-preloader",
            &["Z:\\g\\SomeGame-Win64.exe"],
            &["BPFRAG_OBSERVE=1"],
        );
        // a native tool that merely mentions an .exe is not Wine
        fp.add(51, 1, "7z", "/usr/bin/7z", &["7z", "x", "setup.exe"], &[]);
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
        // explicit tags beat the deny list and Steam
        assert!(c.classify(41).0.is_game());
        assert!(matches!(c.classify(42).0, Verdict::Excluded(_)));
        assert_eq!(c.classify(50).0, Verdict::NotGame("no game signals".into()));
        assert_eq!(c.classify(51).0, Verdict::NotGame("no game signals".into()));
        assert!(c.classify(60).0.reason().contains("gamemode"));
        assert!(!c.read(40).unwrap().observe_tagged());
        let tagged = c.read(52).unwrap();
        assert!(tagged.observe_tagged());
        assert_eq!(tagged.program(), "SomeGame-Win64");
        // the tag only asks for logging: the process is classified as usual
        assert_eq!(
            c.classify(52).0,
            Verdict::Game("Wine/Proton process".into())
        );
        assert_eq!(c.read(50).unwrap().program(), "randomd");
        assert!(!c.classify(999).0.is_game());
        assert_eq!(start_time(&fp.dir, 20), Some(4242));
    }
}
