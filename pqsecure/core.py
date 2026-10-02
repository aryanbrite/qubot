"""Authenticated post-quantum channel: ML-KEM-768 + ML-DSA-65 + HKDF-SHA256 + AES-256-GCM.

Wire format: every frame is a 4-byte big-endian length followed by that many bytes.

Handshake (v0.2)
  1. server -> client : server ML-DSA public key (1952) || ML-KEM encapsulation key (1184)
                        || server_nonce (32)
     client checks the ML-DSA public key against its pin (or trust-on-first-use)
     and aborts here if it is not the key it trusts.
  2. client -> server : "PQS2" || client_nonce (32) || ML-KEM ciphertext (1088)
  3. server -> client : ML-DSA signature over the whole transcript (messages 1 and 2)
     client verifies it with the pinned key; if it fails, no application data is ever sent.
  both               : shared secret -> HKDF-SHA256 (salt = SHA256(transcript))
                       -> two AES-256 keys (client->server, server->client)
Records
  AES-256-GCM, 12-byte nonce = 4 zero bytes + 8-byte message counter.
  The counter is checked, so replayed/reordered/dropped records fail.

The signature covers both nonces, the KEM key and the ciphertext, so it cannot be
replayed to another session and a man-in-the-middle cannot swap in its own KEM key.
Unaudited prototype (see README).
"""
import hashlib
import os
import socket
import socketserver
import struct
import threading
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

from .identity import (PUBLIC_KEY_LEN, SIGNATURE_LEN, AuthenticationError, Identity,
                       fingerprint, matches_pin, resolve_pin, tofu_check, verify)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9443
MAX_FRAME = 1 << 20
EK_LEN = 1184
CT_LEN = 1088
NONCE_LEN = 32
MAGIC = b"PQS2"
_INFO = b"pqsecure v0.2 ML-KEM-768 ML-DSA-65 AES-256-GCM"
_SIG_LABEL = b"pqsecure v0.2 server signature\x00"


def _read_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def _send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_frame(sock):
    (n,) = struct.unpack(">I", _read_exact(sock, 4))
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    return _read_exact(sock, n)


def _transcript(server_hello, client_msg):
    return _SIG_LABEL + server_hello + client_msg


def _derive(shared, transcript):
    okm = HKDF(algorithm=hashes.SHA256(), length=64,
               salt=hashlib.sha256(transcript).digest(), info=_INFO).derive(shared)
    return okm[:32], okm[32:]  # client->server key, server->client key


class _Channel:
    """Encrypted, ordered message channel over a connected socket."""

    def __init__(self, sock, send_key, recv_key, server_fingerprint=None):
        self.sock = sock
        self._tx, self._rx = AESGCM(send_key), AESGCM(recv_key)
        self._tx_n = self._rx_n = 0
        self.server_fingerprint = server_fingerprint

    @staticmethod
    def _nonce(n):
        return b"\x00" * 4 + n.to_bytes(8, "big")

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        ct = self._tx.encrypt(self._nonce(self._tx_n), data, None)
        self._tx_n += 1
        _send_frame(self.sock, ct)

    def recv(self):
        ct = _recv_frame(self.sock)
        pt = self._rx.decrypt(self._nonce(self._rx_n), ct, None)  # raises InvalidTag if tampered
        self._rx_n += 1
        return pt

    def close(self):
        self.sock.close()


def server_handshake(sock, identity=None):
    """Server side. `identity` is the server's ML-DSA key pair (default: ~/.pqsecure/server_key)."""
    identity = identity or Identity.load_or_create()
    ek, dk = ML_KEM_768.keygen()
    server_hello = identity.public_key + ek + os.urandom(NONCE_LEN)
    _send_frame(sock, server_hello)
    client_msg = _recv_frame(sock)
    if len(client_msg) != len(MAGIC) + NONCE_LEN + CT_LEN or not client_msg.startswith(MAGIC):
        raise ValueError("bad client message")
    ct = client_msg[len(MAGIC) + NONCE_LEN:]
    transcript = _transcript(server_hello, client_msg)
    _send_frame(sock, identity.sign(transcript))
    shared = ML_KEM_768.decaps(dk, ct)
    c2s, s2c = _derive(shared, transcript)
    return _Channel(sock, send_key=s2c, recv_key=c2s, server_fingerprint=identity.fingerprint)


def client_handshake(sock, server_key=None, peer="default", tofu=True):
    """Client side. Raises AuthenticationError unless the server proves it holds the trusted key.

    server_key: the server's public key or fingerprint (see identity.resolve_pin). When given,
                it is the only key accepted.
    tofu:       when no server_key is given, pin the key seen on first connection to `peer`
                ('host:port') and reject any different key afterwards.
    """
    pin = resolve_pin(server_key) if server_key is not None else None
    if pin is None and not tofu:
        raise AuthenticationError("no server_key given and trust-on-first-use is off")
    server_hello = _recv_frame(sock)
    if len(server_hello) != PUBLIC_KEY_LEN + EK_LEN + NONCE_LEN:
        raise AuthenticationError("malformed server hello")
    pk = server_hello[:PUBLIC_KEY_LEN]
    ek = server_hello[PUBLIC_KEY_LEN:PUBLIC_KEY_LEN + EK_LEN]
    # 1. Is this the key we trust? Decide before sending anything secret-dependent.
    if pin is not None:
        if not matches_pin(pin, pk):
            raise AuthenticationError(
                f"server presented key {fingerprint(pk)}, which is not the pinned key")
    # (TOFU is recorded only after the signature checks out, below.)
    shared, ct = ML_KEM_768.encaps(ek)
    client_msg = MAGIC + os.urandom(NONCE_LEN) + ct
    _send_frame(sock, client_msg)
    sig = _recv_frame(sock)
    transcript = _transcript(server_hello, client_msg)
    # 2. Did that key's owner sign this exact handshake?
    if len(sig) != SIGNATURE_LEN or not verify(pk, transcript, sig):
        raise AuthenticationError("server signature is invalid; the handshake was not authenticated")
    if pin is None:
        tofu_check(peer, pk)
    c2s, s2c = _derive(shared, transcript)
    return _Channel(sock, send_key=c2s, recv_key=s2c, server_fingerprint=fingerprint(pk))


class Client:
    """Connect, run the authenticated handshake, then send() text.

    Client(host, port, server_key=...) pins the server's public key or fingerprint.
    Without server_key it uses trust-on-first-use (~/.pqsecure/known_servers.json).
    """

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, server_key=None, timeout=10, tofu=True):
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            t0 = time.perf_counter()
            self._ch = client_handshake(sock, server_key, peer=f"{host}:{port}", tofu=tofu)
            self.handshake_seconds = time.perf_counter() - t0
        except BaseException:
            sock.close()
            raise
        self.server_fingerprint = self._ch.server_fingerprint

    def send(self, message):
        self._ch.send(message)
        return self._ch.recv().decode()  # server reply

    def close(self):
        self._ch.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def send(message, host=DEFAULT_HOST, port=DEFAULT_PORT, server_key=None):
    """One-liner: secure.send("Hello") -> the server's reply (a str)."""
    with Client(host, port, server_key) as c:
        return c.send(message)


class Server:
    """Threaded server. handler(text) -> reply text. Default handler acknowledges.

    identity: the server's ML-DSA key pair. Default: load (or create) ~/.pqsecure/server_key.
    """

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, handler=None, verbose=False, identity=None):
        handler = handler or (lambda m: "received: " + m)
        verbose_ = verbose
        self.identity = identity or Identity.load_or_create()
        ident = self.identity

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    ch = server_handshake(self.request, ident)
                    if verbose_:
                        print("Post-quantum connection established", flush=True)
                    while True:
                        try:
                            msg = ch.recv().decode()
                        except ConnectionError:
                            return
                        if verbose_:
                            print("Received:", msg, flush=True)
                        ch.send(handler(msg))
                except Exception as e:  # bad handshake / tampering: drop this connection only
                    if verbose_:
                        print("connection dropped:", type(e).__name__, flush=True)

        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self._srv = socketserver.ThreadingTCPServer((host, port), H)
        self._srv.daemon_threads = True
        self.address = self._srv.server_address

    @property
    def public_key(self):
        return self.identity.public_key

    @property
    def fingerprint(self):
        return self.identity.fingerprint

    def serve_forever(self):
        self._srv.serve_forever()

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


def serve(host=DEFAULT_HOST, port=DEFAULT_PORT, handler=None, verbose=True, identity=None):
    srv = Server(host, port, handler, verbose, identity)
    if verbose:
        print("Server key fingerprint:", srv.fingerprint, flush=True)
    srv.serve_forever()
