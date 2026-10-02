"""Detailed benchmark for the README charts. Writes bench_data.json. Run: python3 bench_full.py"""
import json, os, platform, statistics as st, time, sys
sys.path.insert(0, ".")
import pqsecure as secure
from pqsecure import Identity
from pqsecure.core import Client, EK_LEN, CT_LEN, NONCE_LEN, MAGIC
from pqsecure.identity import PUBLIC_KEY_LEN, SIGNATURE_LEN, verify
from kyber_py.ml_kem import ML_KEM_768
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def timeit(fn, n):
    out = []
    for _ in range(n):
        t = time.perf_counter(); fn(); out.append((time.perf_counter() - t) * 1000)
    return out
def summ(x):
    s = sorted(x); return dict(median=st.median(s), mean=st.mean(s), p95=s[int(len(s)*.95)-1], min=s[0], max=s[-1], n=len(s))

D = {"machine": {"python": platform.python_version(), "platform": platform.platform(), "cpus": os.cpu_count(),
                 "cpu_model": next((l.split(":")[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "unknown")}}
# primitives
ek, dk = ML_KEM_768.keygen()
K, ct = ML_KEM_768.encaps(ek)
D["mlkem_keygen"] = summ(timeit(ML_KEM_768.keygen, 50))
D["mlkem_encaps"] = summ(timeit(lambda: ML_KEM_768.encaps(ek), 50))
D["mlkem_decaps"] = summ(timeit(lambda: ML_KEM_768.decaps(dk, ct), 50))
ident = Identity.generate()
D["mldsa_keygen"] = summ(timeit(Identity.generate, 30))
msg = os.urandom(4400)
sig = ident.sign(msg)
D["mldsa_sign"] = summ(timeit(lambda: ident.sign(msg), 60))
D["mldsa_verify"] = summ(timeit(lambda: verify(ident.public_key, msg, sig), 60))
# full handshake
srv = secure.Server(port=0, identity=ident).start(); host, port = srv.address
hs = []
for _ in range(100):
    c = Client(host, port, server_key=ident.public_key); hs.append(c.handshake_seconds * 1000); c.close()
D["handshake"] = summ(hs); D["handshake_raw"] = hs
with Client(host, port, server_key=ident.public_key) as c:
    rt = timeit(lambda: c.send("x" * 100), 1000)
D["roundtrip_100B"] = summ(rt)
srv.stop()
# AES-GCM record layer throughput (library-level, 16 KiB records)
a = AESGCM(os.urandom(32)); blk = os.urandom(16384); n = os.urandom(12)
t = time.perf_counter()
for _ in range(2000): a.encrypt(n, blk, None)
D["aesgcm_MBps"] = 2000 * 16384 / (time.perf_counter() - t) / 1e6
# sizes (bytes, from the protocol constants and the wire format)
D["bytes"] = {"server_hello": PUBLIC_KEY_LEN + EK_LEN + NONCE_LEN, "client_msg": len(MAGIC) + NONCE_LEN + CT_LEN,
              "signature": SIGNATURE_LEN, "mldsa_pk": PUBLIC_KEY_LEN, "mlkem_ek": EK_LEN, "mlkem_ct": CT_LEN}
D["bytes"]["total_v02"] = D["bytes"]["server_hello"] + D["bytes"]["client_msg"] + D["bytes"]["signature"]
D["bytes"]["total_kem_only"] = EK_LEN + NONCE_LEN + len(MAGIC) + NONCE_LEN + CT_LEN  # v0.1 shape: no ML-DSA key, no signature
json.dump(D, open("bench_data.json", "w"), indent=1)
print(json.dumps({k: v for k, v in D.items() if k != "handshake_raw"}, indent=1))
