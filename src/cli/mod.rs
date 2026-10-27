// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! One-shot commands that don't run the daemon. (`--monitor` and
//! `--waybar` live in `stats`, next to the metrics they read.)

pub mod check;
pub mod report;
pub mod selftest;
