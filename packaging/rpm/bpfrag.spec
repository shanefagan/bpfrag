# SPDX-License-Identifier: MIT
#
# Builds offline from two tarballs: the source (git archive of HEAD) and
# the crates it needs (cargo vendor). packaging/rpm/build.sh makes both
# and runs rpmbuild. For COPR or mock, upload the .src.rpm it produces.

# libbpf (C, vendored by libbpf-sys) is built into a static library;
# keep its objects plain so they link into the Rust binary.
%global _lto_cflags %{nil}

Name:           bpfrag
Version:        0.1.0
Release:        1%{?dist}
Summary:        eBPF network tuning for competitive gaming that undoes itself

# bpfrag is MIT and its BPF program is GPL-2.0-only OR MIT. Crates linked
# into the binary: MIT OR Apache-2.0, MIT, Unlicense OR MIT, BSD-2-Clause
# (libbpf-sys) and LGPL-2.1-only OR BSD-2-Clause (libbpf-rs, libbpf).
License:        MIT AND (GPL-2.0-only OR MIT) AND (MIT OR Apache-2.0) AND (Unlicense OR MIT) AND BSD-2-Clause AND (LGPL-2.1-only OR BSD-2-Clause)
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  cargo >= 1.85
BuildRequires:  rust >= 1.85
BuildRequires:  clang
BuildRequires:  clang-devel
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  /usr/bin/pkg-config
BuildRequires:  pkgconfig(libelf)
BuildRequires:  pkgconfig(zlib)
BuildRequires:  systemd-rpm-macros

Recommends:     ethtool
Recommends:     iw

%description
bpfrag counts UDP traffic per process with eBPF. When a game's network
traffic appears (a steady, two-way stream of small packets from a process
that is a game), it applies a networking profile chosen from the tick
rate: socket busy-polling, NIC interrupt coalescing, buffer headroom, DSCP
marking of the game's packets, Wi-Fi power save and, optionally, tighter
dirty-page writeback. Every change is journalled first and put back when
the match ends or the game exits.

It never changes CPU scheduling, so it runs next to sched_ext schedulers,
and it leaves bpftune's sysctls alone while bpftune is running.

%prep
%autosetup -a1
mkdir -p .cargo
cat > .cargo/config.toml <<'CARGO'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
CARGO

%build
# The distribution's Rust flags, where its macros define them (Fedora).
export RUSTFLAGS="%{?build_rustflags}"
# The release profile strips debug info; keep it for the -debuginfo package.
export CARGO_PROFILE_RELEASE_STRIP=none
export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
cargo build --release --frozen

%install
install -Dpm0755 target/release/bpfrag %{buildroot}%{_bindir}/bpfrag
install -Dpm0644 dist/bpfrag.service %{buildroot}%{_unitdir}/bpfrag.service
install -Dpm0644 dist/bpfrag.8 %{buildroot}%{_mandir}/man8/bpfrag.8
install -Dpm0644 dist/bpfrag.default %{buildroot}%{_sysconfdir}/default/bpfrag
install -Dpm0644 dist/bpfrag.toml %{buildroot}%{_sysconfdir}/bpfrag/bpfrag.toml

%check
export RUSTFLAGS="%{?build_rustflags}"
export CARGO_PROFILE_RELEASE_STRIP=none
export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
cargo test --release --frozen

# Installed but not enabled: run `bpfrag --check` first, then enable it.
# On removal the unit is stopped while /usr/bin/bpfrag still exists, so
# ExecStopPost can restore any settings changed during a match.
%post
%systemd_post bpfrag.service

%preun
%systemd_preun bpfrag.service

%postun
%systemd_postun_with_restart bpfrag.service

%files
%license LICENSE LICENSE-GPL-2.0
%doc README.md
%{_bindir}/bpfrag
%{_unitdir}/bpfrag.service
%{_mandir}/man8/bpfrag.8*
%dir %{_sysconfdir}/bpfrag
%config(noreplace) %{_sysconfdir}/bpfrag/bpfrag.toml
%config(noreplace) %{_sysconfdir}/default/bpfrag

%changelog
* Wed Oct 21 2026 Shane Fagan <mail@shanefagan.com> - 0.1.0-1
- Initial package
