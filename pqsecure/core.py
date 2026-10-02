"""ML-KEM-768 handshake + AES-256-GCM records over TCP.

Wire format: every frame is a 4-byte big-endian length followed by that many bytes.

Handshake
  server -> client : ML-KEM-768 encapsulation (public) key   (1184 bytes)
  client -> server : ML-KEM ciphertext                       (1088 bytes)
  both             : shared secret -> HKDF-SHA256 (salt = SHA256(ek || ct))
                     -> two AES-256 keys (client->server, server->client)
Records
  AES-256-GCM, 12-byte nonce = 4 zero bytes + 8-byte message counter.
  The counter is checked, so replayed/reordered/dropped records fail.

NOT authenticated: nothing proves the server is who you think it is (see README).
"""
import hashlib
import socket
import socketserver
import struct
import threading
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9443
MAX_FRAME = 1 << 20
_INFO = b"pqsecure v0 ML-KEM-768 AES-256-GCM"


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


def _derive(shared, ek, ct):
    okm = HKDF(algorithm=hashes.SHA256(), length=64,
               salt=hashlib.sha256(ek + ct).digest(), info=_INFO).derive(shared)
    return okm[:32], okm[32:]  # client->server key, server->client key


class _Channel:
    """Encrypted, ordered message channel over a connected socket."""

    def __init__(self, sock, send_key, recv_key):
        self.sock = sock
        self._tx, self._rx = AESGCM(send_key), AESGCM(recv_key)
        self._tx_n = self._rx_n = 0

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


def server_handshake(sock):
    ek, dk = ML_KEM_768.keygen()
    _send_frame(sock, ek)
    ct = _recv_frame(sock)
    shared = ML_KEM_768.decaps(dk, ct)
    c2s, s2c = _derive(shared, ek, ct)
    return _Channel(sock, send_key=s2c, recv_key=c2s)


def client_handshake(sock):
    ek = _recv_frame(sock)
    shared, ct = ML_KEM_768.encaps(ek)
    _send_frame(sock, ct)
    c2s, s2c = _derive(shared, ek, ct)
    return _Channel(sock, send_key=c2s, recv_key=s2c)


class Client:
    """Connect, run the post-quantum handshake, then send()/recv() text."""

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=10):
        sock = socket.create_connection((host, port), timeout=timeout)
        t0 = time.perf_counter()
        self._ch = client_handshake(sock)
        self.handshake_seconds = time.perf_counter() - t0

    def send(self, message):
        self._ch.send(message)
        return self._ch.recv().decode()  # server reply

    def close(self):
        self._ch.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def send(message, host=DEFAULT_HOST, port=DEFAULT_PORT):
    """One-liner: secure.send("Hello") -> the server's reply (a str)."""
    with Client(host, port) as c:
        return c.send(message)


class Server:
    """Threaded server. handler(text) -> reply text. Default handler acknowledges."""

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, handler=None, verbose=False):
        handler = handler or (lambda m: "received: " + m)
        verbose_ = verbose

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    ch = server_handshake(self.request)
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

    def serve_forever(self):
        self._srv.serve_forever()

    def start(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


def serve(host=DEFAULT_HOST, port=DEFAULT_PORT, handler=None, verbose=True):
    Server(host, port, handler, verbose).serve_forever()
