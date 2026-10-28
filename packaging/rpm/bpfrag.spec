# SPDX-License-Identifier: MIT
#
# Builds offline from two tarballs: the source and the crates it needs
# (cargo vendor). Each GitHub release carries both, so `spectool -g` or
# COPR can fetch them; packaging/rpm/build.sh makes the same two files
# from a checkout and runs rpmbuild.

# libbpf (C, vendored by libbpf-sys) is built into a static library;
# keep its objects plain so they link into the Rust binary.
%global _lto_cflags %{nil}

Name:           bpfrag
Version:        0.4.1
Release:        1%{?dist}
Summary:        eBPF network tuning for competitive gaming that undoes itself

# bpfrag is MIT and its BPF program is GPL-2.0-only OR MIT. Crates linked
# into the binary: MIT OR Apache-2.0, MIT, Unlicense OR MIT, BSD-2-Clause
# (libbpf-sys) and LGPL-2.1-only OR BSD-2-Clause (libbpf-rs, libbpf).
License:        MIT AND (GPL-2.0-only OR MIT) AND (MIT OR Apache-2.0) AND (Unlicense OR MIT) AND BSD-2-Clause AND (LGPL-2.1-only OR BSD-2-Clause)
URL:            https://github.com/shanefagan/bpfrag
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Source1:        %{url}/releases/download/v%{version}/%{name}-%{version}-vendor.tar.xz

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
install -Dpm0644 dist/bpfrag.preset %{buildroot}%{_presetdir}/80-bpfrag.preset

%check
export RUSTFLAGS="%{?build_rustflags}"
export CARGO_PROFILE_RELEASE_STRIP=none
export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
cargo test --release --frozen

# The preset enables the service on first install, and it is started
# then too; it does nothing until a match is detected. On removal the unit
# is stopped while /usr/bin/bpfrag still exists, so ExecStopPost can
# restore any settings changed during a match.
%post
%systemd_post bpfrag.service
if [ $1 -eq 1 ]; then
    systemctl start bpfrag.service >/dev/null 2>&1 || :
fi

%preun
%systemd_preun bpfrag.service

%postun
%systemd_postun_with_restart bpfrag.service

%files
%license LICENSE LICENSE-GPL-2.0
%doc README.md
%{_bindir}/bpfrag
%{_unitdir}/bpfrag.service
%{_presetdir}/80-bpfrag.preset
%{_mandir}/man8/bpfrag.8*
%dir %{_sysconfdir}/bpfrag
%config(noreplace) %{_sysconfdir}/bpfrag/bpfrag.toml
%config(noreplace) %{_sysconfdir}/default/bpfrag

%changelog
* Wed Oct 28 2026 Shane Fagan <mail@shanefagan.com> - 0.4.1-1
- Consecutive matches no longer merge into one

* Wed Oct 28 2026 Shane Fagan <mail@shanefagan.com> - 0.4.0-1
- A/B experiments; --check shows every setting against its tier; distribution defaults

* Wed Oct 28 2026 Shane Fagan <mail@shanefagan.com> - 0.3.1-1
- Stalls ignore lobbies; path holds through quiet spells; the game's own socket drops

* Wed Oct 28 2026 Shane Fagan <mail@shanefagan.com> - 0.3.0-1
- Bulk demotion during matches; docs on every setting

* Tue Oct 27 2026 Shane Fagan <mail@shanefagan.com> - 0.2.1-1
- tc programs no longer stop CAKE's IFB redirect (download shaping) during matches

* Tue Oct 27 2026 Shane Fagan <mail@shanefagan.com> - 0.2.0-1
- Requires kernel 6.6+; --report for bug reports; packages enable the service on install

* Tue Oct 27 2026 Shane Fagan <mail@shanefagan.com> - 0.1.1-1
- Build path no longer embedded in the binary

* Wed Oct 21 2026 Shane Fagan <mail@shanefagan.com> - 0.1.0-1
- Initial package
