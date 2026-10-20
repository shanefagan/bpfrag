# SPDX-License-Identifier: MIT
# Thin wrapper around cargo for installing the daemon and its unit.

PREFIX  ?= /usr
DESTDIR ?=
CARGO   ?= cargo

BIN := target/release/bpfrag

.PHONY: all build test install uninstall clean

all: build

build:
	$(CARGO) build --release

test:
	$(CARGO) test

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/bpfrag
	install -Dm644 dist/bpfrag.service $(DESTDIR)/usr/lib/systemd/system/bpfrag.service
	test -e $(DESTDIR)/etc/default/bpfrag || install -Dm644 dist/bpfrag.default $(DESTDIR)/etc/default/bpfrag
	test -e $(DESTDIR)/etc/bpfrag/bpfrag.toml || install -Dm644 dist/bpfrag.toml $(DESTDIR)/etc/bpfrag/bpfrag.toml
	@echo
	@echo "Installed. Next: sudo systemctl daemon-reload && sudo systemctl enable --now bpfrag"

uninstall:
	-systemctl disable --now bpfrag 2>/dev/null
	rm -f $(DESTDIR)$(PREFIX)/bin/bpfrag $(DESTDIR)/usr/lib/systemd/system/bpfrag.service
	@echo "Left /etc/default/bpfrag and /etc/bpfrag/ in place."

$(BIN):
	$(CARGO) build --release

clean:
	$(CARGO) clean
