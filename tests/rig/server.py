# SPDX-License-Identifier: MIT
# Server for the e2e rig, on IPv4 10.99.0.2 and IPv6 fd00:99::2:
# - UDP 27015 echoes every datagram (the fake game's server);
# - TCP 27016 is a bulk peer: a client sends "u" and then uploads (we read
#   and drop it), or "d MBPS" and we send it MBPS megabits per second, or
#   "e" and we echo everything back (a game that talks TCP).
import select, socket, threading, time

def bulk_peer(conn):
    with conn:
        cmd = conn.recv(64).decode(errors="replace").split()
        if not cmd:
            return
        if cmd[0] == "u":
            while conn.recv(65536):
                pass
            return
        if cmd[0] == "e":
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                while True:
                    d = conn.recv(4096)
                    if not d:
                        return
                    conn.sendall(d)
            except OSError:
                return
        per_sec = float(cmd[1]) * 1e6 / 8
        chunk = b"y" * 16384
        nxt = time.monotonic()
        try:
            while True:
                conn.sendall(chunk)
                nxt += len(chunk) / per_sec
                d = nxt - time.monotonic()
                if d > 0:
                    time.sleep(d)
        except OSError:
            pass

def tcp_listener(lst):
    while True:
        conn, _ = lst.accept()
        threading.Thread(target=bulk_peer, args=(conn,), daemon=True).start()

socks = []
for fam, addr in ((socket.AF_INET, "10.99.0.2"), (socket.AF_INET6, "fd00:99::2")):
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.bind((addr, 27015))
        t = socket.socket(fam, socket.SOCK_STREAM)
        t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        t.bind((addr, 27016))
        t.listen(8)
    except OSError:
        continue  # e.g. IPv6 disabled on this host
    socks.append(s)
    threading.Thread(target=tcp_listener, args=(t,), daemon=True).start()
while True:
    for s in select.select(socks, [], [])[0]:
        data, peer = s.recvfrom(4096)
        s.sendto(data, peer)
