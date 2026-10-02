# pqsecure

A small prototype of a post-quantum secure channel. Two lines for the developer:

```python
import pqsecure as secure
secure.send("Hello")
```

**Status: prototype. Not audited, not production crypto.** It uses existing libraries for everything cryptographic and does not implement any primitive itself.

## What it does

```
Your application
      |
  pqsecure
      |
ML-KEM-768 key exchange -> HKDF-SHA256 -> AES-256-GCM
      |
    Server
```

1. Server makes an ML-KEM-768 key pair and sends the public key.
2. Client uses it to encapsulate a random shared secret and sends back the ciphertext.
3. Server decapsulates it. Both sides now hold the same secret; a network observer only sees the public key and ciphertext.
4. HKDF-SHA256 (salted with a hash of the handshake) turns the secret into two AES-256 keys, one per direction.
5. Messages are AES-256-GCM records with a counter nonce. Tampered, replayed, reordered or dropped records fail to decrypt.

Libraries: [`kyber-py`](https://github.com/GiacomoPope/kyber-py) (pure-Python ML-KEM, FIPS 203) and [`cryptography`](https://cryptography.io) (AES-GCM, HKDF).

## Run it

```bash
pip install -r requirements.txt
python server.py            # terminal 1
python client.py            # terminal 2
```

Server prints:
```
Post-quantum connection established
Received: Hello from the future
```
Client prints:
```
Post-quantum connection established
Server replied: received: Hello from the future
```

Or run `bash demo.sh` to do both in one terminal. Tests: `python -m pytest`. Handshake benchmark: `python benchmark.py`.

## API

- `secure.send(msg, host, port)` - connect, handshake, send, return the server's reply.
- `secure.Client(host, port)` - keep a connection open: `c.send(msg)`; `c.handshake_seconds`.
- `secure.Server(port, handler)` / `secure.serve()` - `handler(text) -> reply text`.

## Benchmark

`python benchmark.py` times a full client-side handshake over localhost (see output in `benchmark_results.txt`; on the build machine, median about 10 ms, p95 about 20 ms). That is with a pure-Python ML-KEM, so it is slower than a native library such as liboqs; swapping the backend is the obvious speedup.

## Limitations (read these)

- **No authentication.** ML-KEM gives key exchange only. Nothing proves the server is the real server, so an active man-in-the-middle can sit between you. A real design needs server authentication, e.g. a post-quantum signature (ML-DSA) over the handshake or certificates.
- **Pure-Python ML-KEM is not constant-time** and has had no side-channel review. Use liboqs or a vetted native implementation for anything real.
- Not a replacement for TLS. Hybrid (X25519 + ML-KEM) is the recommended way to deploy in practice, and is not done here.
- No key rotation, no forward-secrecy beyond a fresh key pair per connection, no rate limiting, simple length-prefixed framing.
- It protects data in transit only. "Harvest now, decrypt later" is the threat this key exchange is aimed at.
