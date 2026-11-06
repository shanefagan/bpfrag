## Which file?

| File | For |
|---|---|
| `bpfrag_<version>-1_amd64.deb` | Debian 12+, Ubuntu 22.04+ and their derivatives (Pop!_OS, Mint): `sudo apt install ./bpfrag_*.deb` |
| `bpfrag-<version>-1.fc<NN>.x86_64.rpm` | Fedora and Nobara: `sudo dnf install ./bpfrag-<version>-1.fc*.x86_64.rpm`. On Bazzite and other image-based Fedoras: `rpm-ostree install` it |
| `bpfrag-<version>-x86_64-linux.tar.gz` | Any other x86-64 distro with glibc 2.35+ (Arch, CachyOS, openSUSE...): the binary, systemd unit, man page, example config and D-Bus policy, to copy into place. On Arch-based distros, building with `packaging/arch/PKGBUILD` gives a proper package instead |
| `SHA256SUMS` | Checksums of every file here: `sha256sum -c --ignore-missing SHA256SUMS` |
| `bpfrag-debuginfo-*.rpm`, `bpfrag-debugsource-*.rpm` | Debug symbols for the RPM, only to read a crash backtrace. Not needed to run it |
| `bpfrag-<version>-1.fc<NN>.src.rpm` | The RPM's source package, for rebuilding it (COPR, mock, `rpmbuild --rebuild`) |
| `bpfrag-<version>-vendor.tar.xz` | The Rust crates bpfrag builds with, for building offline (the RPM spec's second source) |
| Source code (zip, tar.gz) | The tagged source, added by GitHub |

All of them need kernel 6.6 or newer with BTF.
