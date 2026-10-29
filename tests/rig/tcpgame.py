# SPDX-License-Identifier: MIT
# Fake game that talks TCP (an MMO client) for the e2e rig: RATE small
# messages a second to the server's port 27016, echoed back.
#   tcpgame.py RATE
import os, socket, sys, time
rate = float(sys.argv[1])
dest = os.environ.get("DEST", "10.99.0.2")
s = socket.create_connection((dest, 27016))
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.sendall(b"e")
time.sleep(0.1)
nxt = time.monotonic()
while True:
    s.sendall(b"m" * 90)
    s.recv(4096)
    nxt += 1.0 / rate
    d = nxt - time.monotonic()
    if d > 0:
        time.sleep(d)
