# pqsecure

A small prototype of an authenticated post-quantum secure channel. Two lines for the developer:

```python
import pqsecure as secure
secure.send("Hello")
```

**Status: unaudited prototype. Not production crypto.** It uses existing libraries for every primitive and implements none itself. Do not use it to protect real secrets.

## Demo

[Watch the demo video](https://cdn.hackclub.com/01a0fcbb-161e-7628-9118-5477025d591f/1-pq-demo-0c6f8c0b.mp4)

(The video shows the original 0.1 version, which had no server authentication. 0.2 adds it.)

## What it does

```
Your application
      |
  pqsecure
      |
ML-KEM-768 key exchange + ML-DSA-65 server signature -> HKDF-SHA256 -> AES-256-GCM
      |
    Server
```

1. The server sends its long-term ML-DSA-65 public key, a fresh ML-KEM-768 key and a nonce.
2. The client checks that ML-DSA public key against the key it trusts (see "Trust model"). If it is not that key, the client stops.
3. The client encapsulates a random shared secret to the ML-KEM key and sends the ciphertext plus its own nonce.
4. The server signs the whole handshake transcript with its ML-DSA key and sends the signature.
5. The client verifies the signature with the trusted key. If it fails, the connection is dropped and no application data is ever sent.
6. HKDF-SHA256 (salted with a hash of the transcript) turns the shared secret into two AES-256 keys, one per direction.
7. Messages are AES-256-GCM records with a counter nonce. Tampered, replayed, reordered or dropped records fail to decrypt.

The signature covers both nonces, the server's KEM key and the client's ciphertext. So an attacker cannot swap in its own KEM key, and a signature recorded from one session does not verify in another.

Libraries: [`kyber-py`](https://github.com/GiacomoPope/kyber-py) (pure-Python ML-KEM, FIPS 203), [`dilithium-py`](https://github.com/GiacomoPope/dilithium-py) (pure-Python ML-DSA, FIPS 204) and [`cryptography`](https://cryptography.io) (AES-GCM, HKDF).

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

## Run it

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

Tests: `python3 -m pytest -q` (22 tests, including man-in-the-middle and impersonation tests). Benchmark: `python3 benchmark.py`.

## API

- `secure.send(msg, host, port, server_key=None)` - connect, handshake, send, return the server's reply.
- `secure.Client(host, port, server_key=None, tofu=True)` - keep a connection open: `c.send(msg)`; `c.handshake_seconds`; `c.server_fingerprint`.
- `secure.Server(host, port, handler, identity=None)` / `secure.serve()` - `handler(text) -> reply text`. `server.fingerprint`, `server.public_key`.
- `secure.Identity` - the server's ML-DSA key pair: `Identity.generate()`, `.save(path)`, `.load(path)`, `.load_or_create()`, `.fingerprint`, `.public_key`.
- `secure.AuthenticationError` - raised when the server is not the trusted one.
- `python3 -m pqsecure serve | fingerprint | keygen`.

## What is tested

- Honest connections work with every pin form (public key, hex, fingerprint, file, `Identity`) and with trust on first use.
- A server using a different ML-DSA key than the pinned one is rejected, both when it just runs its own server and when it sits in the middle.
- An active man-in-the-middle that keeps the real server's public key but swaps in its own ML-KEM key and signs with its own key is rejected, and the client sends nothing beyond the handshake.
- A genuine signature recorded from an earlier session and replayed is rejected.
- Garbage, truncated and tampered handshake messages are rejected, and the server keeps serving other clients.
- A changed key under trust on first use is rejected.
- The earlier tests (round trips, no plaintext on the wire, tampered and replayed records) still pass.

## Benchmark

`python3 benchmark.py` times a full authenticated client-side handshake over localhost (output in `benchmark_results.txt`; on the build machine the median was about 60 ms, with ML-DSA signing about 53 ms on the server and verifying about 10 ms on the client). That is with pure-Python ML-KEM and ML-DSA, so it is much slower than a native library such as liboqs. The v0.1 handshake had no signature and took about 11 ms. Handshake size grows from about 2.3 KB to about 7.6 KB.

## Limitations (read these)

- **Unaudited.** No security review of this code or of the protocol design. The protocol is a simple one-way-authenticated design made for this prototype, not a standard such as TLS 1.3.
- **Only the server is authenticated.** The client is anonymous. There is no mutual authentication.
- **The first connection under trust on first use is unprotected.** Pin the key for anything that matters.
- **Pure-Python ML-KEM and ML-DSA are not constant-time** and have had no side-channel review. Use liboqs or a vetted native implementation for anything real.
- The server's secret key sits unencrypted (mode 0600) on disk. No key rotation or revocation.
- Not a replacement for TLS. Hybrid (X25519 + ML-KEM, with a classical or hybrid signature) is the recommended way to deploy in practice, and is not done here.
- Fresh ML-KEM key per connection, but no rekeying within a connection, no rate limiting (and signing is slow, so a flood of connections is easy to cause), simple length-prefixed framing.
- It protects data in transit only. "Harvest now, decrypt later" is the threat the key exchange is aimed at; the signature protects against active attackers during the handshake.
