<p align="center">
  <picture>
    <source
      media="(prefers-color-scheme: dark)"
      srcset="https://cdn.hackclub.com/01a0fdf1-15f9-7bcb-823a-fd6677f3ed64/pqsecure_logo.svg"
    />
    <source
      media="(prefers-color-scheme: light)"
      srcset="https://cdn.hackclub.com/01a0fdf8-060a-793d-b9c2-db9e2745af84/white.svg"
    />
    <img
      alt="pqsecure"
      src="https://cdn.hackclub.com/01a0fdf8-060a-793d-b9c2-db9e2745af84/white.svg"
      width="220"
    />
  </picture>
</p>



<div align="center">

# pqsecure

**An authenticated post-quantum secure channel in two lines of Python.**

ML-KEM-768 key exchange &middot; ML-DSA-65 server authentication &middot; HKDF-SHA256 &middot; AES-256-GCM

![version](https://img.shields.io/badge/version-0.2.0-blue) ![tests](https://img.shields.io/badge/tests-22%20passing-brightgreen) ![license](https://img.shields.io/badge/license-MIT-lightgrey) ![status](https://img.shields.io/badge/status-unaudited%20prototype-orange) ![python](https://img.shields.io/badge/python-3.9%2B-blue)

```python
import pqsecure as secure
secure.send("Hello")
```

<p align="center">
  <img src="https://cdn.hackclub.com/01a0fde5-e65e-7b25-bd15-bd579b40e369/ezgif-72401caceb05195e.gif" width="100%">
</p>

</div>

> **Status: unaudited prototype. Not production crypto. Do not use it to protect real secrets.**
> Every primitive comes from an existing library. We implement none ourselves. What we built is the protocol that binds them together, the trust model, the test suite, and the benchmark harness. All of it is small enough to read in one sitting (about 800 lines of Python including tests).

---

## Contents

1. [Why this exists](#why-this-exists)
2. [What you get](#what-you-get)
3. [Architecture](#architecture)
4. [The handshake, step by step](#the-handshake-step-by-step)
5. [Design decisions](#design-decisions)
6. [Trust model](#trust-model-how-the-client-gets-the-servers-public-key)
7. [Benchmarks](#benchmarks)
8. [How it is tested](#how-it-is-tested)
9. [Threat model](#threat-model)
10. [Quick start and API](#quick-start)
11. [Limitations](#limitations-read-these)
12. [Roadmap](#roadmap)
13. [Reproduce everything](#reproduce-everything)

---

## Why this exists

Two quantum-era problems, two different deadlines:

- **Harvest now, decrypt later.** An attacker can record encrypted traffic today and decrypt it years later if the key exchange falls to a quantum computer. This is why the key exchange moves first. pqsecure uses **ML-KEM-768** (NIST FIPS 203).
- **Impersonation.** A key exchange with no authentication is open to an active man-in-the-middle, quantum or not. Version 0.1 of this project had exactly that gap. Version 0.2 closes it with **ML-DSA-65** (NIST FIPS 204) signatures, so the client knows who it is talking to.

pqsecure is a small, readable reference for putting those two standardized algorithms together correctly, with tests that try to break it.

## What you get

| | |
|---|---|
| **Post-quantum key exchange** | ML-KEM-768, fresh key pair per connection |
| **Post-quantum server authentication** | ML-DSA-65 signature over the full handshake transcript |
| **Authenticated encryption** | AES-256-GCM, separate key per direction, counter nonces |
| **Key schedule** | HKDF-SHA256, salted with the transcript hash, domain-separated info string |
| **Pinning or trust-on-first-use** | pin a fingerprint or key file, or SSH-style TOFU |
| **Fail-closed** | bad signature, wrong key, malformed or tampered message: connection dropped, no application data sent |
| **Tiny surface** | `send()`, `serve()`, `Client`, `Server`, `Identity`, one CLI |
| **22 tests** | including active man-in-the-middle and impersonation attacks |

## Architecture

```
Your application
      |
  pqsecure            send() / serve() / Client / Server / Identity
      |
ML-KEM-768 key exchange + ML-DSA-65 server signature -> HKDF-SHA256 -> AES-256-GCM
      |
  TCP (4-byte length-prefixed frames)
      |
    Server
```

| Module | Lines | Job |
|---|---|---|
| `pqsecure/core.py` | 261 | handshake (both sides), record layer, `Client`, `Server` |
| `pqsecure/identity.py` | 160 | ML-DSA key pair, signing and verifying, pins, fingerprints, TOFU store |
| `pqsecure/__main__.py` | 28 | `serve`, `fingerprint`, `keygen` commands |
| `tests/` | 311 | 22 tests, 2 files |
| `benchmark.py`, `bench_full.py` | 34, 54 | handshake benchmark, detailed benchmark behind the charts |

Libraries: [`kyber-py`](https://github.com/GiacomoPope/kyber-py) (pure-Python ML-KEM, FIPS 203), [`dilithium-py`](https://github.com/GiacomoPope/dilithium-py) (pure-Python ML-DSA, FIPS 204), [`cryptography`](https://cryptography.io) (AES-GCM, HKDF).

## The handshake, step by step

![pqsecure v0.2 handshake](https://cdn.hackclub.com/01a0fd04-f710-76d0-82b4-bbd3c1859a5f/1-protocol-f8a7c943.png)

1. **ServerHello.** The server sends its long-term ML-DSA-65 public key (1,952 B), a fresh ML-KEM-768 encapsulation key (1,184 B) and a 32-byte nonce.
2. **The client checks the key before doing anything else.** If the ML-DSA key is not the one it trusts (pinned, or remembered under TOFU), it aborts here.
3. **ClientKey.** The client encapsulates a random shared secret to the ML-KEM key and sends a `PQS2` marker, its own 32-byte nonce and the 1,088-byte ciphertext.
4. **Signature.** The server signs the whole transcript (a domain label plus messages 1 and 2) with ML-DSA-65 and sends the 3,309-byte signature.
5. **The client verifies.** If the signature fails, the connection is dropped and no application data is ever sent.
6. **Key schedule.** Both sides run HKDF-SHA256 over the shared secret, salted with SHA-256 of the transcript, and split 64 bytes into two AES-256 keys, one per direction.
7. **Records.** Each message is an AES-256-GCM record. The 12-byte nonce is 4 zero bytes plus an 8-byte counter that both sides track, so tampered, replayed, reordered or dropped records fail to decrypt.

## Design decisions

These are the choices a reviewer should ask about, and why we made them.

| Decision | Why |
|---|---|
| **Sign the whole transcript, not just the KEM key** | The signature covers both nonces, the server's KEM key and the client's ciphertext. A man-in-the-middle cannot swap in its own KEM key, and a signature recorded from one session does not verify in another. Both are tested. |
| **Check the pin before encapsulating** | A client talking to the wrong key sends nothing secret-dependent. |
| **Domain-separated labels** | The signed transcript, the ML-DSA context string and the HKDF info string all carry a `pqsecure v0.2` label, so a signature or key from another use cannot be confused with this one. |
| **Salt HKDF with the transcript hash** | The derived keys are bound to exactly this handshake. |
| **Two directional keys** | The same AES key and counter nonce are never used by both sides. |
| **Counter nonces, checked on receive** | Replay, reordering and dropped records are detected, not just tampering. |
| **Fresh ML-KEM key per connection** | No long-lived KEM key to compromise. Only the ML-DSA identity key is long-lived. |
| **One-way authentication only** | Matches the common web model and keeps the protocol small enough to review. The cost is stated under limitations. |
| **Pure-Python primitives** | Zero native dependencies, readable end to end, `pip install` works anywhere. The cost is speed and constant-time guarantees, stated below. |
| **Reuse libraries, write no primitives** | The riskiest code to write is the primitive. We did not. |

## Trust model: how the client gets the server's public key

The signature only proves "whoever holds the secret key matching this public key signed this handshake". It is only as good as the client's knowledge of which public key is the real server's. pqsecure gives you two ways:

1. **Pin the key (recommended).** The server operator runs `python3 -m pqsecure fingerprint` and shares the fingerprint, or the `~/.pqsecure/server_key.pub` file, with clients over a channel you already trust (in person, a signed release, a config file you ship). Then:
   ```python
   secure.send("Hello", host, port, server_key="sha256:...")        # fingerprint
   secure.send("Hello", host, port, server_key="server_key.pub")    # public key file
   ```
   Only that key is accepted. An impostor with a different key is rejected.
2. **Trust on first use (the default for `secure.send("Hello")`).** With no `server_key`, the client remembers the key it sees on the first connection to each `host:port` (in `~/.pqsecure/known_servers.json`) and rejects any different key afterwards, like SSH. This does **not** protect the very first connection: an attacker present then can be pinned instead of the real server. Pass `tofu=False` to `Client` to refuse unpinned connections.

The server keeps its secret key in `~/.pqsecure/server_key` (mode 0600), created on first run. Set `PQSECURE_HOME` to use another directory. There is no certificate authority, revocation or key rotation: to change keys you give clients the new key.

## Benchmarks

Everything below was **measured by running this code** (`bench_full.py`, raw data in `bench_data.json`), on a 2 vCPU Intel Xeon @ 2.60 GHz cloud VM, Python 3.10.12, handshakes over localhost, with the pure-Python `kyber-py` and `dilithium-py` libraries. Absolute numbers depend on the machine: the committed `benchmark_results.txt` came from a different machine and shows a lower median. Treat the ratios as the stable part.

### Where the time goes

![Handshake time breakdown](https://cdn.hackclub.com/01a0fd05-2769-72fe-8161-2ee0f67dcd0c/2-handshake-breakdown-bd540d71.png)

ML-DSA-65 signing is the single biggest cost, at about 60% of the handshake. The ML-KEM-768 key exchange is fast by comparison: keygen, encaps and decaps together take about 16 ms.

### Per-operation cost

![Primitive costs](https://cdn.hackclub.com/01a0fd05-3fee-713a-8f45-b44b897c5ab2/3-primitive-costs-952cba5c.png)

| Operation | Median | min | p95 |
|---|---:|---:|---:|
| ML-KEM-768 keygen | 3.9 ms | 3.7 ms | 7.1 ms |
| ML-KEM-768 encaps | 5.0 ms | 4.9 ms | 5.5 ms |
| ML-KEM-768 decaps | 6.8 ms | 6.7 ms | 8.8 ms |
| ML-DSA-65 keygen | 11.7 ms | 11.5 ms | 12.5 ms |
| ML-DSA-65 sign | 60.2 ms | 25.8 ms | 174.6 ms |
| ML-DSA-65 verify | 12.9 ms | 12.5 ms | 13.2 ms |

Signing time varies a lot because ML-DSA signing retries until a candidate passes its checks (rejection sampling), so a signature takes a random number of attempts.

### Latency distribution

![Handshake latency distribution](https://cdn.hackclub.com/01a0fd05-57df-711d-b98a-04ba62e8b8cb/4-handshake-distribution-1efe7ab9.png)

Full authenticated handshake over 100 runs: **median 100 ms, p95 234 ms, min 52 ms, max 295 ms** on this VM. The long tail is the signing variance above. Two other runs of `benchmark.py` on different machines gave medians of 67.6 ms (committed `benchmark_results.txt`) and 91.9 ms (this VM, an earlier run), so expect roughly 70 to 100 ms for a median with this pure-Python stack.

### What authentication costs on the wire

![Handshake bytes](https://cdn.hackclub.com/01a0fd05-7176-7d27-ad97-ded37859c831/5-handshake-bytes-e13e9bf5.png)

| | v0.1 (no auth) | v0.2 (authenticated) |
|---|---:|---:|
| Handshake bytes | 2,272 | 7,601 |
| ML-DSA public key | - | 1,952 |
| ML-DSA signature | - | 3,309 |

Post-quantum signatures are big. That 7.6 KB, mostly the ML-DSA key and signature, is the honest price of authenticating the server with a standardized post-quantum scheme, and it is paid once per connection.

### After the handshake

Encrypted 100-byte request/reply round trips on localhost took a median of **0.11 ms** (p95 0.13 ms, 1,000 runs). Once the handshake is done, AES-256-GCM makes the channel cheap.

### What these numbers do not say

- The handshake time is dominated by pure-Python arithmetic. A native implementation such as liboqs would be much faster. We have **not** measured one, so we make no speedup claim.
- Localhost only. There is no network latency in these numbers.
- One machine, one Python version, 100 handshakes. No claims about throughput under load. The server signs on every connection, so a connection flood is expensive for it.

## How it is tested

`python3 -m pytest -q` runs **22 tests** (22 passed on the machine above, in about 11 seconds). They are split into the original channel tests and the authentication tests, and many of them are attacks:

**Honest paths**
- Round trips, many messages, unicode.
- Every pin form works: raw public key, hex, fingerprint, key file, `Identity`.
- TOFU pins on first connect.
- Keys are saved and loaded with correct file permissions, and the default server key is created once and reused.
- A transparent honest proxy changes nothing (the control for the MITM tests).

**Attacks that must fail**
- A server with a different ML-DSA key than the pinned one, both as a plain impostor and as a man-in-the-middle.
- A man-in-the-middle that keeps the real server's public key, swaps in its own ML-KEM key and forges the signature.
- A genuine signature relayed from a different transcript.
- Tampering with the ML-KEM ciphertext in flight.
- Garbage and truncated signatures, and a malformed server hello.
- A changed key under TOFU.
- Tampered records and replayed records.
- No plaintext on the wire.
- A garbage handshake does not kill the server, and the server keeps serving after rejecting a client.

One test also checks the signature is a real ML-DSA signature over the transcript, not just "some bytes".

## Threat model

| Attacker | Result |
|---|---|
| Passive eavesdropper recording traffic (harvest now, decrypt later) | Traffic is protected by ML-KEM-768 and AES-256-GCM. ML-KEM is a NIST post-quantum standard. We have not independently analyzed it. |
| Active man-in-the-middle with their own key | Rejected, provided the client has the real server key (pinned, or first connection was clean). |
| Active man-in-the-middle swapping the KEM key | Rejected: the signature covers the KEM key. |
| Replay of a recorded handshake signature | Rejected: the signature covers both fresh nonces. |
| Record tampering, replay, reordering, dropping | Rejected by AES-GCM and the counter nonce. |
| Attacker present on the very first TOFU connection | **Not protected.** Pin the key instead. |
| Impersonating the *client* | **Not protected.** The client is anonymous. |
| Side-channel attacker | **Not protected.** Pure-Python primitives are not constant-time. |
| Connection flood | **Not protected.** No rate limiting, and signing is slow. |

## Quick start

### Install from PyPI

```bash
pip install pqsecure
```

Server and client in one script, with the server's key pinned (the safe way to connect):

```python
import threading
import pqsecure as secure

# Server side: make an ML-DSA identity. Share identity.public_key with clients
# out of band. For a persistent key use Identity.load_or_create().
identity = secure.Identity.generate()
server = secure.Server("127.0.0.1", 9443, handler=lambda text: "got: " + text, identity=identity)
threading.Thread(target=server.serve_forever, daemon=True).start()

# Client side: pin that public key, so only this server is accepted.
print(secure.send("Hello", "127.0.0.1", 9443, server_key=identity.public_key))  # got: Hello

# A server with any other key is rejected.
try:
    secure.send("Hello", "127.0.0.1", 9443, server_key=secure.Identity.generate().public_key)
except secure.AuthenticationError as e:
    print("rejected:", e)
```

Without `server_key`, the client trusts the first key it sees (TOFU). Pin the key for anything that matters.

### From the repo

```bash
pip install -r requirements.txt
python3 server.py            # terminal 1: prints its key fingerprint
python3 client.py            # terminal 2
```

Server prints:
```
Server key fingerprint: sha256:...
Post-quantum connection established
Received: Hello from the future
```
Client prints:
```
Post-quantum connection established
Server authenticated with ML-DSA key: sha256:...
Server replied: received: Hello from the future
```

Or run `bash demo.sh` to do both in one terminal (it uses throwaway keys). From the pip package: `python3 -m pqsecure serve` in one terminal and `python3 -c "import pqsecure as secure; print(secure.send('Hello'))"` in another.

### API

- `secure.send(msg, host, port, server_key=None)` - connect, handshake, send, return the server's reply.
- `secure.Client(host, port, server_key=None, tofu=True)` - keep a connection open: `c.send(msg)`; `c.handshake_seconds`; `c.server_fingerprint`.
- `secure.Server(host, port, handler, identity=None)` / `secure.serve()` - `handler(text) -> reply text`. `server.fingerprint`, `server.public_key`.
- `secure.Identity` - the server's ML-DSA key pair: `Identity.generate()`, `.save(path)`, `.load(path)`, `.load_or_create()`, `.fingerprint`, `.public_key`.
- `secure.AuthenticationError` - raised when the server is not the trusted one.
- `python3 -m pqsecure serve | fingerprint | keygen`.

### Demo

[Watch the demo video](https://cdn.hackclub.com/01a0fcbb-161e-7628-9118-5477025d591f/1-pq-demo-0c6f8c0b.mp4). It shows the original 0.1 version, which had no server authentication. 0.2 adds it.

## Limitations (read these)

- **Unaudited.** No security review of this code or of the protocol design. The protocol is a simple one-way-authenticated design made for this prototype, not a standard such as TLS 1.3.
- **Only the server is authenticated.** The client is anonymous. There is no mutual authentication.
- **The first connection under trust on first use is unprotected.** Pin the key for anything that matters.
- **Pure-Python ML-KEM and ML-DSA are not constant-time** and have had no side-channel review. Use liboqs or a vetted native implementation for anything real.
- The server's secret key sits unencrypted (mode 0600) on disk. No key rotation or revocation.
- Not a replacement for TLS. Hybrid (X25519 + ML-KEM, with a classical or hybrid signature) is the recommended way to deploy in practice, and is not done here.
- Fresh ML-KEM key per connection, but no rekeying within a connection, no rate limiting (and signing is slow, so a flood of connections is easy to cause), simple length-prefixed framing.
- It protects data in transit only. "Harvest now, decrypt later" is the threat the key exchange is aimed at; the signature protects against active attackers during the handshake.
- Passing our tests shows the attacks we thought of fail. It does not prove there are no others.

## Roadmap

These are plans, not features. None of them exist yet.

- [ ] Swap the pure-Python primitives for a native, vetted library (for example liboqs) behind the same API, and re-run the benchmarks
- [ ] Hybrid mode: X25519 + ML-KEM-768 key exchange, classical + ML-DSA signature
- [ ] Mutual authentication (client identities)
- [ ] Key rotation and revocation
- [ ] Rekeying inside a long connection
- [ ] Rate limiting and handshake cost protection
- [ ] Independent security review

## Reproduce everything

```bash
pip install -r requirements.txt
python3 -m pytest -q           # 22 tests
python3 benchmark.py           # headline handshake numbers
python3 bench_full.py          # detailed numbers, writes bench_data.json
python3 charts.py              # regenerates docs/img/*.png from bench_data.json (needs matplotlib, numpy)
```

Every number and chart in this README comes from those commands.

## License

MIT. Copyright (c) 2026 Aryan Brite.
