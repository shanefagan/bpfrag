// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Tiny logger: syslog-style "<N>" prefixes when running under journald (so
// `journalctl -p` filtering works), timestamps otherwise.

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Write;

struct Logger {
    journald: bool,
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut err = std::io::stderr().lock();
        if self.journald {
            let prio = match record.level() {
                Level::Error => 3,
                Level::Warn => 4,
                Level::Info => 6,
                Level::Debug | Level::Trace => 7,
            };
            let _ = writeln!(err, "<{prio}>{}", record.args());
        } else {
            let lvl = match record.level() {
                Level::Error => "ERROR",
                Level::Warn => "WARN ",
                Level::Info => "INFO ",
                Level::Debug => "DEBUG",
                Level::Trace => "TRACE",
            };
            let _ = writeln!(err, "{} {lvl} {}", clock(), record.args());
        }
    }

    fn flush(&self) {}
}

fn clock() -> String {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        libc::localtime_r(&ts.tv_sec, &mut tm);
    }
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        ts.tv_nsec / 1_000_000
    )
}

pub fn init(verbosity: u8) {
    let journald = std::env::var_os("JOURNAL_STREAM").is_some();
    let level = match verbosity {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    let _ = log::set_boxed_logger(Box::new(Logger { journald }));
    log::set_max_level(level);

    // Route libbpf's own chatter through us.
    let lvl = if verbosity >= 2 {
        libbpf_rs::PrintLevel::Debug
    } else {
        libbpf_rs::PrintLevel::Warn
    };
    libbpf_rs::set_print(Some((lvl, |level, msg| {
        let msg = msg.trim_end();
        match level {
            libbpf_rs::PrintLevel::Warn => log::warn!("libbpf: {msg}"),
            libbpf_rs::PrintLevel::Info => log::debug!("libbpf: {msg}"),
            libbpf_rs::PrintLevel::Debug => log::trace!("libbpf: {msg}"),
        }
    })));
}
