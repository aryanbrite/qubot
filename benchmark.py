"""Handshake benchmark: full client+server handshake over localhost TCP."""
import statistics, time
import pqsecure as secure
from pqsecure.core import Client

srv = secure.Server(port=0).start()
host, port = srv.address
N = 200
times = []
for _ in range(N):
    c = Client(host, port)
    times.append(c.handshake_seconds * 1000)
    c.close()
times.sort()
print(f"ML-KEM-768 handshake over localhost, {N} runs (pure-Python kyber-py)")
print(f"  median {statistics.median(times):.1f} ms | p95 {times[int(N*.95)]:.1f} ms | min {times[0]:.1f} ms | max {times[-1]:.1f} ms")
t = time.perf_counter()
with Client(host, port) as c:
    for _ in range(1000):
        c.send("x" * 100)
dt = time.perf_counter() - t
print(f"  1000 encrypted 100-byte round trips: {dt*1000/1000:.2f} ms each")
srv.stop()
