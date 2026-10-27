// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Same split as the sched_ext Rust schedulers: src/bpf/main.bpf.c becomes a
// libbpf-rs skeleton (bpf_skel.rs, BpfSkel), and src/bpf/intf.h becomes
// bindgen'd Rust (bpf_intf.rs) so both sides share one definition.

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/main.bpf.c";
const INTF: &str = "src/bpf/intf.h";

/// libbpf-cargo pipes the skeleton through rustfmt when it can start it,
/// and only skips that if rustfmt is missing altogether. rustup's rustfmt
/// proxy without the rustfmt component starts and then fails, which fails
/// the build. Formatting is cosmetic, so use rustfmt only if it runs.
fn rustfmt() -> PathBuf {
    let r = env::var_os("RUSTFMT").map_or_else(|| PathBuf::from("rustfmt"), PathBuf::from);
    let works = Command::new(&r)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if works {
        r
    } else {
        // a path that can't exist: libbpf-cargo then skips formatting
        PathBuf::from("/nonexistent/rustfmt")
    }
}

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    // The BPF object's debug info (its BTF line info) records the source
    // path, and the object is embedded in the binary. Record it relative to
    // the crate, so the binary doesn't carry the build directory.
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    let prefix_map = format!("-ffile-prefix-map={manifest}=.");

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .obj(out.join("bpf.bpf.o"))
        .clang_args([
            "-Wall",
            "-Wno-unused-function",
            "-O2",
            "-g",
            prefix_map.as_str(),
        ])
        .rustfmt(rustfmt())
        .build_and_generate(out.join("bpf_skel.rs"))
        .expect("failed to build the BPF skeleton (is clang installed?)");

    let intf = std::fs::canonicalize(INTF).expect("intf.h");
    bindgen::Builder::default()
        .header_contents(
            "wrapper.h",
            &format!(
                "typedef unsigned char __u8; typedef unsigned short __u16;\n\
                 typedef unsigned int __u32; typedef unsigned long long __u64;\n\
                 #include \"{}\"\n",
                intf.display()
            ),
        )
        .allowlist_file(".*intf\\.h")
        .default_enum_style(bindgen::EnumVariation::Consts)
        .prepend_enum_name(false)
        .derive_default(true)
        .layout_tests(false)
        .generate()
        .expect("bindgen failed on intf.h (is libclang installed?)")
        .write_to_file(out.join("bpf_intf.rs"))
        .expect("writing bpf_intf.rs");

    println!("cargo:rerun-if-env-changed=RUSTFMT");
    for f in [BPF_SRC, INTF, "src/bpf/vmlinux_lite.h"] {
        println!("cargo:rerun-if-changed={f}");
    }
}
