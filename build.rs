// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Same split as the sched_ext Rust schedulers: src/bpf/main.bpf.c becomes a
// libbpf-rs skeleton (bpf_skel.rs, BpfSkel), and src/bpf/intf.h becomes
// bindgen'd Rust (bpf_intf.rs) so both sides share one definition.

use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/main.bpf.c";
const INTF: &str = "src/bpf/intf.h";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .obj(out.join("bpf.bpf.o"))
        .clang_args(["-Wall", "-Wno-unused-function", "-O2", "-g"])
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

    for f in [BPF_SRC, INTF, "src/bpf/vmlinux_lite.h"] {
        println!("cargo:rerun-if-changed={f}");
    }
}
