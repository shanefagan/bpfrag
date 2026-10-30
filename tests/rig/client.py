# SPDX-License-Identifier: MIT
# Fake netcode: send `rate` packets/s of `size` bytes to the echo server and
# read the echoes. The rate can be changed live by writing a number to the
# control file. DEST overrides the server address (an IPv6 one selects v6);
# with DEST2 and SWITCH_AFTER, the same socket moves to DEST2 after that
# many seconds, the way a game goes straight into its next match.
# PHASES="local:12,remote:20,..." alternates between the server and a
# server of its own on 127.0.0.1 (a thread echoing back), the way Deadlock
# talks to itself in its menus; the last phase lasts.
import os, socket, sys, threading, time
rate, size = float(sys.argv[1]), int(sys.argv[2])
ctl = sys.argv[3] if len(sys.argv) > 3 else None
dest = os.environ.get("DEST", "10.99.0.2")
dest2 = os.environ.get("DEST2")
switch_after = float(os.environ.get("SWITCH_AFTER", "0"))
t0 = time.monotonic()
fam = socket.AF_INET6 if ":" in dest else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.setblocking(False)
phases = []
for p in filter(None, os.environ.get("PHASES", "").split(",")):
    kind, secs = p.split(":")
    phases.append((kind, float(secs)))
local_addr = None
if any(k == "local" for k, _ in phases):
    own = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    own.bind(("127.0.0.1", 0))
    local_addr = own.getsockname()

    def own_server():
        while True:
            data, peer = own.recvfrom(4096)
            own.sendto(data, peer)

    threading.Thread(target=own_server, daemon=True).start()


def phase(t):
    for kind, secs in phases:
        if t < secs:
            return kind
        t -= secs
    return phases[-1][0] if phases else "remote"
payload = b"x" * size
nxt = time.monotonic()
last_ctl = 0
while True:
    now = time.monotonic()
    if ctl and now - last_ctl > 1:
        last_ctl = now
        try:
            rate = float(open(ctl).read())
        except Exception:
            pass
    if rate > 0:
        moved = dest2 and switch_after and now - t0 >= switch_after
        if phase(now - t0) == "local":
            s.sendto(payload, local_addr)
        else:
            s.sendto(payload, (dest2 if moved else dest, 27015))
        nxt += 1.0 / rate
    else:
        nxt = now + 0.1
    while True:
        try:
            s.recv(4096)
        except BlockingIOError:
            break
    d = nxt - time.monotonic()
    if d > 0:
        time.sleep(d)
    else:
        nxt = time.monotonic()
