// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! A read-only D-Bus interface on the system bus, so other programs (a
//! status bar, an experiment runner) can follow matches without root and
//! without polling stats.json.
//!
//! `com.performativenonsense.Bpfrag1` at `/com/performativenonsense/Bpfrag1`, one
//! interface of the same name. Properties describe the match in progress;
//! signals mark its start, its tier changes and its end. There are no
//! methods, and `Set` is refused, so nothing on the bus can change what
//! bpfrag does. Everything published is also in /run/bpfrag/stats.json,
//! which any user can read; the list of other processes' UDP rates and
//! bulk transfers is left out, so the bus only describes the game and
//! bpfrag itself. docs/dbus.md has the reference.
//!
//! The daemon is single-threaded, so the bus is pumped from its loop (at
//! least every 250 ms) rather than from a thread of its own. A missing
//! bus, or one that goes away, never stops the daemon: it carries on and
//! tries to reconnect every 30 s.

use std::ffi::CString;
use std::time::{Duration, Instant};

use dbus::Message;
use dbus::arg::{PropMap, RefArg, Variant};
use dbus::blocking::Connection;
use dbus::blocking::stdintf::org_freedesktop_dbus::{
    PropertiesPropertiesChanged, RequestNameReply,
};
use dbus::message::{MessageType, SignalArgs};
use dbus::strings::ErrorName;
use log::{debug, info};

use crate::health::Health;

pub const NAME: &str = "com.performativenonsense.Bpfrag1";
pub const PATH: &str = "/com/performativenonsense/Bpfrag1";
pub const IFACE: &str = NAME;

const PROPS: &str = "org.freedesktop.DBus.Properties";
const INTROSPECTABLE: &str = "org.freedesktop.DBus.Introspectable";
const PEER: &str = "org.freedesktop.DBus.Peer";

/// How long to wait before trying the bus again after it went away.
const RETRY: Duration = Duration::from_secs(30);

/// What the properties say. The daemon builds one every tick; whatever
/// changed goes out as a single PropertiesChanged signal.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct State {
    /// The game's process id; 0 between matches.
    pub game_pid: u32,
    pub game: String,
    /// Why the classifier counts it as a game.
    pub reason: String,
    /// "casual", "competitive" or "intense"; "" between matches.
    pub tier: String,
    /// When the match started, in Unix seconds; 0 between matches.
    pub since: u64,
    /// The `[experiment]` arm, e.g. "busy_polling off"; "" if none.
    pub experiment: String,
    /// (setting, value now, value before the match)
    pub applied: Vec<(String, String, String)>,
}

/// Property names, in the order GetAll and the introspection list them.
const NAMES: &[&str] = &[
    "Version",
    "DryRun",
    "InMatch",
    "GamePid",
    "Game",
    "Reason",
    "Tier",
    "MatchSince",
    "Experiment",
    "Applied",
];

/// Everything the properties are read from.
struct Published {
    dry_run: bool,
    state: State,
}

impl Published {
    fn get(&self, name: &str) -> Option<Box<dyn RefArg>> {
        let s = &self.state;
        Some(match name {
            "Version" => Box::new(env!("CARGO_PKG_VERSION").to_string()),
            "DryRun" => Box::new(self.dry_run),
            "InMatch" => Box::new(s.game_pid != 0),
            "GamePid" => Box::new(s.game_pid),
            "Game" => Box::new(s.game.clone()),
            "Reason" => Box::new(s.reason.clone()),
            "Tier" => Box::new(s.tier.clone()),
            "MatchSince" => Box::new(s.since),
            "Experiment" => Box::new(s.experiment.clone()),
            "Applied" => Box::new(s.applied.clone()),
            _ => return None,
        })
    }

    fn all(&self) -> PropMap {
        self.only(NAMES)
    }

    fn only(&self, names: &[&str]) -> PropMap {
        names
            .iter()
            .filter_map(|n| Some((n.to_string(), Variant(self.get(n)?))))
            .collect()
    }
}

/// The properties that differ between two states.
fn changed(old: &State, new: &State) -> Vec<&'static str> {
    let mut v = Vec::new();
    if (old.game_pid != 0) != (new.game_pid != 0) {
        v.push("InMatch");
    }
    if old.game_pid != new.game_pid {
        v.push("GamePid");
    }
    if old.game != new.game {
        v.push("Game");
    }
    if old.reason != new.reason {
        v.push("Reason");
    }
    if old.tier != new.tier {
        v.push("Tier");
    }
    if old.since != new.since {
        v.push("MatchSince");
    }
    if old.experiment != new.experiment {
        v.push("Experiment");
    }
    if old.applied != new.applied {
        v.push("Applied");
    }
    v
}

/// A finished match's connection health, for the MatchEnded signal.
/// Keys are left out when there is nothing to report (no meter, say).
pub fn health_dict(h: Option<&Health>) -> PropMap {
    fn put(m: &mut PropMap, k: &str, v: Box<dyn RefArg>) {
        m.insert(k.into(), Variant(v));
    }
    let mut m = PropMap::new();
    let Some(h) = h else {
        return m;
    };
    if let Some(g) = &h.gaps {
        put(&mut m, "packets", Box::new(g.pkts));
        put(&mut m, "gap_p50_ms", Box::new(g.p50_ms));
        put(&mut m, "gap_p99_ms", Box::new(g.p99_ms));
        put(&mut m, "gap_max_ms", Box::new(g.max_ms));
        put(&mut m, "stalls", Box::new(g.stalls));
    }
    put(&mut m, "socket_drops", Box::new(h.socket_drops));
    if let Some(d) = h.game_socket_drops {
        put(&mut m, "game_socket_drops", Box::new(d));
    }
    put(&mut m, "backlog_drops", Box::new(h.backlog_drops));
    put(&mut m, "nic_drops", Box::new(h.nic_drops));
    put(&mut m, "squeezed", Box::new(h.squeezed));
    put(&mut m, "game_tcp_bytes", Box::new(h.game_tcp_bytes));
    if let Some(n) = h.busy_polled {
        put(&mut m, "busy_polled", Box::new(n));
    }
    m
}

/// The connection, if there is one, and what it publishes.
pub struct Bus {
    conn: Option<Connection>,
    retry_at: Instant,
    /// The "no system bus" note has been logged at info once already.
    told: bool,
    /// We own NAME. Without it, property reads can't reach us but signals
    /// still go out; it is asked for again every 30 s, since the bus only
    /// allows it once it has loaded the policy file.
    owned: bool,
    /// Why owning NAME failed last time, so the log says it once.
    name_note: Option<String>,
    name_retry_at: Instant,
    published: Published,
}

impl Bus {
    pub fn new(dry_run: bool) -> Self {
        let mut b = Self {
            conn: None,
            retry_at: Instant::now(),
            told: false,
            owned: false,
            name_note: None,
            name_retry_at: Instant::now(),
            published: Published {
                dry_run,
                state: State::default(),
            },
        };
        b.connect();
        b
    }

    fn connect(&mut self) {
        let conn = match Connection::new_system() {
            Ok(c) => c,
            Err(e) => {
                let msg = format!(
                    "D-Bus: system bus not available ({}); not publishing",
                    e.message().unwrap_or("no reason given")
                );
                if self.told {
                    debug!("{msg}");
                } else {
                    info!("{msg}");
                    self.told = true;
                }
                self.retry_at = Instant::now() + RETRY;
                return;
            }
        };
        self.told = false;
        self.owned = false;
        self.name_note = None;
        self.conn = Some(conn);
        self.own_name();
    }

    /// Ask for NAME, logging only when the outcome changes.
    fn own_name(&mut self) {
        let Some(conn) = &self.conn else {
            return;
        };
        let note = match conn.request_name(NAME, false, false, true) {
            Ok(RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner) => {
                self.owned = true;
                self.name_note = None;
                info!("D-Bus: publishing {NAME} on the system bus (read-only)");
                return;
            }
            Ok(_) => format!("D-Bus: {NAME} is owned by another process; sending signals only"),
            Err(e) => format!(
                "D-Bus: can't own {NAME} ({}); sending signals only until the bus allows \
                 it. Is /usr/share/dbus-1/system.d/{NAME}.conf installed, and the bus \
                 reloaded?",
                e.message().unwrap_or("no reason given")
            ),
        };
        if self.name_note.as_ref() == Some(&note) {
            debug!("{note}");
        } else {
            info!("{note}");
        }
        self.name_note = Some(note);
        self.name_retry_at = Instant::now() + RETRY;
    }

    /// Answer whatever arrived and send what's queued. Never blocks.
    pub fn pump(&mut self) {
        let Some(conn) = &self.conn else {
            if Instant::now() >= self.retry_at {
                self.connect();
            }
            return;
        };
        let ch = conn.channel();
        if ch.read_write(Some(Duration::ZERO)).is_err() || !ch.is_connected() {
            info!(
                "D-Bus: lost the system bus; retrying every {}s",
                RETRY.as_secs()
            );
            self.conn = None;
            self.told = true;
            self.retry_at = Instant::now() + RETRY;
            return;
        }
        if !self.owned && Instant::now() >= self.name_retry_at {
            self.own_name();
        }
        let Some(conn) = &self.conn else {
            return;
        };
        let ch = conn.channel();
        let mut answered = false;
        while let Some(m) = ch.pop_message() {
            if let Some(reply) = respond(&self.published, &m) {
                let _ = ch.send(reply);
                answered = true;
            }
        }
        if answered {
            let _ = ch.read_write(Some(Duration::ZERO));
        }
    }

    fn send(&self, m: Message) {
        if let Some(c) = &self.conn {
            let ch = c.channel();
            let _ = ch.send(m);
            let _ = ch.read_write(Some(Duration::ZERO));
        }
    }

    /// Wait (briefly) until everything queued is out, before exiting.
    pub fn flush(&self) {
        if let Some(c) = &self.conn {
            c.channel().flush();
        }
    }

    /// Publish a new state; changed properties go out in one signal.
    pub fn set(&mut self, state: State) {
        let names = changed(&self.published.state, &state);
        self.published.state = state;
        if names.is_empty() {
            return;
        }
        let sig = PropertiesPropertiesChanged {
            interface_name: IFACE.into(),
            changed_properties: self.published.only(&names),
            invalidated_properties: Vec::new(),
        };
        self.send(sig.to_emit_message(&PATH.into()));
    }

    pub fn match_started(&self, pid: u32, game: &str, tier: &str, reason: &str, experiment: &str) {
        let m = signal("MatchStarted")
            .append3(pid, game, tier)
            .append2(reason, experiment);
        self.send(m);
    }

    pub fn tier_changed(&self, pid: u32, game: &str, from: &str, to: &str) {
        let m = signal("TierChanged").append2(pid, game).append2(from, to);
        self.send(m);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn match_ended(
        &self,
        pid: u32,
        game: &str,
        reason: &str,
        secs: u64,
        peak_tier: &str,
        experiment: &str,
        health: Option<&Health>,
    ) {
        let m = signal("MatchEnded")
            .append3(pid, game, reason)
            .append3(secs, peak_tier, experiment)
            .append1(health_dict(health));
        self.send(m);
    }
}

/// For `--check`: is the policy installed, and is the name published now?
/// Some(true) when it is; otherwise None, as bpfrag runs fine without it.
pub fn check() -> (Option<bool>, String) {
    let policy = ["/usr/share/dbus-1/system.d", "/etc/dbus-1/system.d"]
        .iter()
        .map(|d| std::path::Path::new(d).join(format!("{NAME}.conf")))
        .find(|p| p.exists());
    let Some(policy) = policy else {
        return (
            None,
            format!("policy {NAME}.conf not installed: signals only, no property reads"),
        );
    };
    let conn = match Connection::new_system() {
        Ok(c) => c,
        Err(e) => {
            return (
                None,
                format!(
                    "no system bus here ({})",
                    e.message().unwrap_or("no reason given")
                ),
            );
        }
    };
    let proxy = conn.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        Duration::from_secs(2),
    );
    let owned: Result<(bool,), _> =
        proxy.method_call("org.freedesktop.DBus", "NameHasOwner", (NAME,));
    let (ok, state) = match owned {
        Ok((true,)) => (Some(true), "published now"),
        Ok((false,)) => (None, "not published now (bpfrag not running?)"),
        Err(_) => (None, "couldn't ask the bus"),
    };
    (ok, format!("{NAME}: {state}; policy {}", policy.display()))
}

fn signal(name: &str) -> Message {
    Message::new_signal(PATH, IFACE, name).expect("valid signal name")
}

/// An error reply, unless the caller asked for none.
fn error(m: &Message, name: &str, text: &str) -> Message {
    let text = CString::new(text).unwrap_or_default();
    m.error(&ErrorName::from(name), &text)
}

/// The reply to one incoming message, if it needs one.
fn respond(p: &Published, m: &Message) -> Option<Message> {
    if m.msg_type() != MessageType::MethodCall || m.get_no_reply() {
        return None;
    }
    let path = m.path().map(|p| p.to_string()).unwrap_or_default();
    let iface = m.interface().map(|i| i.to_string()).unwrap_or_default();
    let member = m.member().map(|n| n.to_string()).unwrap_or_default();

    // Peer works on any path.
    if iface == PEER || (iface.is_empty() && member == "Ping") {
        return Some(match member.as_str() {
            "Ping" => m.method_return(),
            "GetMachineId" => match std::fs::read_to_string("/etc/machine-id") {
                Ok(id) => m.method_return().append1(id.trim()),
                Err(_) => error(m, "org.freedesktop.DBus.Error.Failed", "no machine id"),
            },
            _ => unknown_method(m, &iface, &member),
        });
    }
    if iface == INTROSPECTABLE || (iface.is_empty() && member == "Introspect") {
        if member != "Introspect" {
            return Some(unknown_method(m, &iface, &member));
        }
        return Some(match introspect(&path) {
            Some(xml) => m.method_return().append1(xml),
            None => unknown_object(m, &path),
        });
    }
    if path != PATH {
        return Some(unknown_object(m, &path));
    }
    if iface == PROPS {
        return Some(properties(p, m, &member));
    }
    Some(unknown_method(m, &iface, &member))
}

/// The D-Bus spec lets a caller leave the interface name empty; ours is the
/// only interface here with properties, so that means ours.
fn ours(iface: &str) -> bool {
    iface.is_empty() || iface == IFACE
}

fn properties(p: &Published, m: &Message, member: &str) -> Message {
    match member {
        "Get" => match m.read2::<&str, &str>() {
            Ok((i, name)) if ours(i) => match p.get(name) {
                Some(v) => m.method_return().append1(Variant(v)),
                None => error(
                    m,
                    "org.freedesktop.DBus.Error.UnknownProperty",
                    &format!("no property {name}"),
                ),
            },
            Ok((i, _)) => unknown_interface(m, i),
            Err(_) => invalid_args(m),
        },
        "GetAll" => match m.read1::<&str>() {
            Ok(i) if ours(i) => m.method_return().append1(p.all()),
            // The standard interfaces have no properties.
            Ok(PROPS | INTROSPECTABLE | PEER) => m.method_return().append1(PropMap::new()),
            Ok(i) => unknown_interface(m, i),
            Err(_) => invalid_args(m),
        },
        "Set" => error(
            m,
            "org.freedesktop.DBus.Error.PropertyReadOnly",
            "bpfrag's properties are read-only",
        ),
        _ => unknown_method(m, PROPS, member),
    }
}

fn unknown_method(m: &Message, iface: &str, member: &str) -> Message {
    error(
        m,
        "org.freedesktop.DBus.Error.UnknownMethod",
        &format!("no method {iface}.{member}"),
    )
}

fn unknown_object(m: &Message, path: &str) -> Message {
    error(
        m,
        "org.freedesktop.DBus.Error.UnknownObject",
        &format!("no object at {path}"),
    )
}

fn unknown_interface(m: &Message, iface: &str) -> Message {
    error(
        m,
        "org.freedesktop.DBus.Error.UnknownInterface",
        &format!("no interface {iface}"),
    )
}

fn invalid_args(m: &Message) -> Message {
    error(
        m,
        "org.freedesktop.DBus.Error.InvalidArgs",
        "wrong arguments",
    )
}

const DOCTYPE: &str = r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
"#;

/// Introspection data for `path`: the object itself, or one of the nodes
/// above it, so tools that walk the tree from "/" find it.
fn introspect(path: &str) -> Option<String> {
    if path == PATH {
        return Some(format!("{DOCTYPE}{OBJECT_XML}"));
    }
    let prefix = if path == "/" {
        "/".to_string()
    } else {
        format!("{path}/")
    };
    let rest = PATH.strip_prefix(&prefix)?;
    let child = rest.split('/').next()?;
    Some(format!(
        "{DOCTYPE}<node>\n  <node name=\"{child}\"/>\n</node>\n"
    ))
}

const OBJECT_XML: &str = r#"<node>
  <interface name="com.performativenonsense.Bpfrag1">
    <property name="Version" type="s" access="read">
      <annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>
    </property>
    <property name="DryRun" type="b" access="read">
      <annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>
    </property>
    <property name="InMatch" type="b" access="read"/>
    <property name="GamePid" type="u" access="read"/>
    <property name="Game" type="s" access="read"/>
    <property name="Reason" type="s" access="read"/>
    <property name="Tier" type="s" access="read"/>
    <property name="MatchSince" type="t" access="read"/>
    <property name="Experiment" type="s" access="read"/>
    <property name="Applied" type="a(sss)" access="read"/>
    <signal name="MatchStarted">
      <arg name="pid" type="u"/>
      <arg name="game" type="s"/>
      <arg name="tier" type="s"/>
      <arg name="reason" type="s"/>
      <arg name="experiment" type="s"/>
    </signal>
    <signal name="TierChanged">
      <arg name="pid" type="u"/>
      <arg name="game" type="s"/>
      <arg name="from" type="s"/>
      <arg name="to" type="s"/>
    </signal>
    <signal name="MatchEnded">
      <arg name="pid" type="u"/>
      <arg name="game" type="s"/>
      <arg name="reason" type="s"/>
      <arg name="duration_secs" type="t"/>
      <arg name="peak_tier" type="s"/>
      <arg name="experiment" type="s"/>
      <arg name="health" type="a{sv}"/>
    </signal>
  </interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get">
      <arg name="interface_name" type="s" direction="in"/>
      <arg name="property_name" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="GetAll">
      <arg name="interface_name" type="s" direction="in"/>
      <arg name="properties" type="a{sv}" direction="out"/>
    </method>
    <method name="Set">
      <arg name="interface_name" type="s" direction="in"/>
      <arg name="property_name" type="s" direction="in"/>
      <arg name="value" type="v" direction="in"/>
    </method>
    <signal name="PropertiesChanged">
      <arg name="interface_name" type="s"/>
      <arg name="changed_properties" type="a{sv}"/>
      <arg name="invalidated_properties" type="as"/>
    </signal>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg name="xml_data" type="s" direction="out"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Peer">
    <method name="Ping"/>
    <method name="GetMachineId">
      <arg name="machine_uuid" type="s" direction="out"/>
    </method>
  </interface>
</node>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::GapSummary;

    fn published() -> Published {
        Published {
            dry_run: false,
            state: State {
                game_pid: 6230,
                game: "cs2".into(),
                reason: "Steam app 730".into(),
                tier: "competitive".into(),
                since: 1_700_000_000,
                experiment: "busy_polling off".into(),
                applied: vec![("net.core.busy_poll".into(), "50".into(), "0".into())],
            },
        }
    }

    fn call(path: &str, iface: &str, member: &str) -> Message {
        let mut m = Message::new_method_call(NAME, path, iface, member).unwrap();
        m.set_serial(7);
        m
    }

    fn error_name(m: &Message) -> Option<String> {
        (m.msg_type() == MessageType::Error).then(|| {
            let mut m = m.duplicate().unwrap();
            m.as_result()
                .unwrap_err()
                .name()
                .unwrap_or_default()
                .to_string()
        })
    }

    #[test]
    fn get_and_get_all() {
        let p = published();
        let r = respond(&p, &call(PATH, PROPS, "Get").append2(IFACE, "Tier")).unwrap();
        assert_eq!(error_name(&r), None);
        let v: Variant<Box<dyn RefArg>> = r.read1().unwrap();
        assert_eq!(v.0.as_str(), Some("competitive"));

        let r = respond(&p, &call(PATH, PROPS, "Get").append2(IFACE, "InMatch")).unwrap();
        let v: Variant<bool> = r.read1().unwrap();
        assert!(v.0);

        let r = respond(&p, &call(PATH, PROPS, "GetAll").append1(IFACE)).unwrap();
        let all: PropMap = r.read1().unwrap();
        let mut keys: Vec<&str> = all.keys().map(String::as_str).collect();
        keys.sort();
        let mut want = NAMES.to_vec();
        want.sort();
        assert_eq!(keys, want);
        assert_eq!(all["GamePid"].0.as_u64(), Some(6230));
        assert_eq!(all["Experiment"].0.as_str(), Some("busy_polling off"));
    }

    #[test]
    fn an_empty_interface_name_means_ours() {
        let p = published();
        let r = respond(&p, &call(PATH, PROPS, "Get").append2("", "Tier")).unwrap();
        let v: Variant<Box<dyn RefArg>> = r.read1().unwrap();
        assert_eq!(v.0.as_str(), Some("competitive"));
        let r = respond(&p, &call(PATH, PROPS, "GetAll").append1("")).unwrap();
        let all: PropMap = r.read1().unwrap();
        assert_eq!(all.len(), NAMES.len());
    }

    #[test]
    fn nothing_can_be_changed() {
        let p = published();
        let set = call(PATH, PROPS, "Set").append3(IFACE, "Tier", Variant("intense"));
        assert_eq!(
            error_name(&respond(&p, &set).unwrap()).as_deref(),
            Some("org.freedesktop.DBus.Error.PropertyReadOnly")
        );
        let other = call(PATH, IFACE, "Restore");
        assert_eq!(
            error_name(&respond(&p, &other).unwrap()).as_deref(),
            Some("org.freedesktop.DBus.Error.UnknownMethod")
        );
    }

    #[test]
    fn bad_requests_get_errors() {
        let p = published();
        let r = respond(&p, &call(PATH, PROPS, "Get").append2(IFACE, "Nope")).unwrap();
        assert_eq!(
            error_name(&r).as_deref(),
            Some("org.freedesktop.DBus.Error.UnknownProperty")
        );
        let r = respond(&p, &call(PATH, PROPS, "Get").append2("x.y", "Tier")).unwrap();
        assert_eq!(
            error_name(&r).as_deref(),
            Some("org.freedesktop.DBus.Error.UnknownInterface")
        );
        let r = respond(&p, &call(PATH, PROPS, "Get").append1(IFACE)).unwrap();
        assert_eq!(
            error_name(&r).as_deref(),
            Some("org.freedesktop.DBus.Error.InvalidArgs")
        );
        let r = respond(&p, &call("/elsewhere", PROPS, "GetAll").append1(IFACE)).unwrap();
        assert_eq!(
            error_name(&r).as_deref(),
            Some("org.freedesktop.DBus.Error.UnknownObject")
        );
    }

    #[test]
    fn no_reply_when_none_is_wanted() {
        let p = published();
        let mut m = call(PATH, PROPS, "GetAll").append1(IFACE);
        m.set_no_reply(true);
        assert!(respond(&p, &m).is_none());
        let sig = Message::new_signal(PATH, IFACE, "MatchStarted").unwrap();
        assert!(respond(&p, &sig).is_none());
    }

    #[test]
    fn introspection_walks_down_from_the_root() {
        let p = published();
        let mut path = "/".to_string();
        for want in ["com", "performativenonsense", "Bpfrag1"] {
            let r = respond(&p, &call(&path, INTROSPECTABLE, "Introspect")).unwrap();
            let xml: &str = r.read1().unwrap();
            assert!(
                xml.contains(&format!("<node name=\"{want}\"/>")),
                "{path}: {xml}"
            );
            path = if path == "/" {
                format!("/{want}")
            } else {
                format!("{path}/{want}")
            };
        }
        let r = respond(&p, &call(PATH, INTROSPECTABLE, "Introspect")).unwrap();
        let xml: &str = r.read1().unwrap();
        for n in NAMES {
            assert!(
                xml.contains(&format!("<property name=\"{n}\"")),
                "{n} missing"
            );
        }
        let r = respond(&p, &call("/org", INTROSPECTABLE, "Introspect")).unwrap();
        assert!(error_name(&r).is_some());
    }

    #[test]
    fn ping() {
        let r = respond(&published(), &call("/", PEER, "Ping")).unwrap();
        assert_eq!(r.msg_type(), MessageType::MethodReturn);
    }

    #[test]
    fn only_what_changed_is_sent() {
        let a = published().state;
        assert!(changed(&a, &a).is_empty());
        let mut b = a.clone();
        b.tier = "intense".into();
        assert_eq!(changed(&a, &b), ["Tier"]);
        let idle = State::default();
        let c = changed(&a, &idle);
        assert!(c.contains(&"InMatch") && c.contains(&"GamePid") && c.contains(&"Applied"));
    }

    #[test]
    fn health_has_the_numbers() {
        assert!(health_dict(None).is_empty());
        let h = Health {
            gaps: Some(GapSummary {
                port: 27015,
                pkts: 120_000,
                p50_ms: 16,
                p99_ms: 31,
                max_ms: 84.5,
                stalls: 2,
            }),
            game_socket_drops: Some(0),
            nic_drops: 3,
            busy_polled: Some(0),
            ..Default::default()
        };
        let d = health_dict(Some(&h));
        assert_eq!(d["busy_polled"].0.as_u64(), Some(0));
        assert!(!health_dict(Some(&Health::default())).contains_key("busy_polled"));
        assert_eq!(d["gap_p99_ms"].0.as_u64(), Some(31));
        assert_eq!(d["gap_max_ms"].0.as_f64(), Some(84.5));
        assert_eq!(d["stalls"].0.as_u64(), Some(2));
        assert_eq!(d["nic_drops"].0.as_u64(), Some(3));
        assert!(d.contains_key("game_socket_drops"));
        // Not about the game's connection, so not on the bus.
        assert!(!d.contains_key("port") && !d.contains_key("bulk"));
    }
}
