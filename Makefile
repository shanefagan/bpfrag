# SPDX-License-Identifier: MIT
# Thin wrapper around cargo for installing the daemon and its unit.

PREFIX  ?= /usr
DESTDIR ?=
CARGO   ?= cargo

BIN := target/release/bpfrag

.PHONY: all build test install uninstall deb rpm srpm clean

all: build

build:
	$(CARGO) build --release

test:
	$(CARGO) test

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/bpfrag
	install -Dm644 dist/bpfrag.service $(DESTDIR)/usr/lib/systemd/system/bpfrag.service
	install -Dm644 dist/bpfrag.8 $(DESTDIR)$(PREFIX)/share/man/man8/bpfrag.8
	install -Dm644 dist/com.performativenonsense.Bpfrag1.conf $(DESTDIR)/usr/share/dbus-1/system.d/com.performativenonsense.Bpfrag1.conf
	test -e $(DESTDIR)/etc/default/bpfrag || install -Dm644 dist/bpfrag.default $(DESTDIR)/etc/default/bpfrag
	test -e $(DESTDIR)/etc/bpfrag/bpfrag.toml || install -Dm644 dist/bpfrag.toml $(DESTDIR)/etc/bpfrag/bpfrag.toml
	@echo
	@echo "Installed. Next: sudo systemctl daemon-reload && sudo systemctl enable --now bpfrag"

uninstall:
	-systemctl disable --now bpfrag 2>/dev/null
	rm -f $(DESTDIR)$(PREFIX)/bin/bpfrag $(DESTDIR)/usr/lib/systemd/system/bpfrag.service \
		$(DESTDIR)$(PREFIX)/share/man/man8/bpfrag.8 \
		$(DESTDIR)/usr/share/dbus-1/system.d/com.performativenonsense.Bpfrag1.conf
	@echo "Left /etc/default/bpfrag and /etc/bpfrag/ in place."

# Debian/Ubuntu package in target/debian/ (needs: cargo install cargo-deb).
deb:
	$(CARGO) deb

# Fedora packages in target/rpm/, built offline from vendored
# crates. srpm makes only the source package, for COPR or mock.
rpm:
	packaging/rpm/build.sh

srpm:
	packaging/rpm/build.sh --srpm

$(BIN):
	$(CARGO) build --release

clean:
	$(CARGO) clean
