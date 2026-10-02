"""Handshake benchmark: full authenticated handshake over localhost TCP, plus the cost of ML-DSA."""
import statistics, time
import pqsecure as secure
from pqsecure import Identity
from pqsecure.core import Client

ident = Identity.generate()
srv = secure.Server(port=0, identity=ident).start()
host, port = srv.address
N = 100
times = []
for _ in range(N):
    c = Client(host, port, server_key=ident.public_key)   # pinned: signature verified every time
    times.append(c.handshake_seconds * 1000)
    c.close()
times.sort()
print(f"Authenticated handshake (ML-KEM-768 + ML-DSA-65) over localhost, {N} runs (pure-Python kyber-py, dilithium-py)")
print(f"  median {statistics.median(times):.1f} ms | p95 {times[int(N*.95)]:.1f} ms | min {times[0]:.1f} ms | max {times[-1]:.1f} ms")

M = 30
msg = b"x" * 4000
t = time.perf_counter(); sigs = [ident.sign(msg) for _ in range(M)]; sign_ms = (time.perf_counter() - t) * 1000 / M
from pqsecure.identity import verify
t = time.perf_counter(); [verify(ident.public_key, msg, s) for s in sigs]; verify_ms = (time.perf_counter() - t) * 1000 / M
print(f"  of which ML-DSA-65: sign {sign_ms:.1f} ms (server), verify {verify_ms:.1f} ms (client)")
print(f"  handshake bytes: server hello 3,168 + client message 1,124 + signature 3,309 = 7,601 (v0.1 unauthenticated: 2,272)")

t = time.perf_counter()
with Client(host, port, server_key=ident.public_key) as c:
    for _ in range(1000):
        c.send("x" * 100)
dt = time.perf_counter() - t
print(f"  1000 encrypted 100-byte round trips: {dt*1000/1000:.2f} ms each")
srv.stop()
