"""Server authentication tests: pinning, trust-on-first-use, and man-in-the-middle attempts."""
import os
import socket
import stat
import struct
import threading

import pytest
from kyber_py.ml_kem import ML_KEM_768

import pqsecure as secure
from pqsecure import AuthenticationError, Identity
from pqsecure.core import (CT_LEN, EK_LEN, MAGIC, NONCE_LEN, _recv_frame, _send_frame,
                           _transcript, client_handshake)
from pqsecure.identity import PUBLIC_KEY_LEN, SIGNATURE_LEN, home_dir, verify


@pytest.fixture
def real():
    ident = Identity.generate()
    s = secure.Server(port=0, identity=ident).start()
    yield s
    s.stop()


# ---------- the honest path ----------

def test_pin_by_public_key_fingerprint_hex_and_file(real, tmp_path):
    h, p = real.address
    pub = tmp_path / "server_key.pub"
    pub.write_text(real.public_key.hex())
    for pin in (real.public_key, real.fingerprint, real.fingerprint[7:], real.identity, str(pub), pub,
                real.public_key.hex()):
        assert secure.send("Hello", h, p, server_key=pin) == "received: Hello"


def test_client_learns_the_authenticated_fingerprint(real):
    with secure.Client(*real.address, server_key=real.public_key) as c:
        assert c.server_fingerprint == real.fingerprint


def test_signature_is_real_ml_dsa_over_the_transcript():
    a, b = socket.socketpair()
    ident = Identity.generate()
    from pqsecure.core import server_handshake
    t = threading.Thread(target=lambda: server_handshake(b, ident)); t.start()
    server_hello = _recv_frame(a)
    ek = server_hello[PUBLIC_KEY_LEN:PUBLIC_KEY_LEN + EK_LEN]
    _, ct = ML_KEM_768.encaps(ek)
    msg = MAGIC + os.urandom(NONCE_LEN) + ct
    _send_frame(a, msg)
    sig = _recv_frame(a); t.join()
    assert len(sig) == SIGNATURE_LEN
    assert verify(ident.public_key, _transcript(server_hello, msg), sig)
    # a different message, or a different key, must not verify
    assert not verify(ident.public_key, _transcript(server_hello, msg + b"x"), sig)
    assert not verify(Identity.generate().public_key, _transcript(server_hello, msg), sig)


# ---------- trust on first use ----------

def test_tofu_pins_on_first_connect_and_rejects_a_changed_key(real):
    h, p = real.address
    assert secure.send("one", h, p) == "received: one"          # first sight: pinned
    assert real.fingerprint in (home_dir() / "known_servers.json").read_text()
    assert secure.send("two", h, p) == "received: two"          # same key: fine
    # an impostor now answers at the same host:port with its own key
    real.stop()
    evil = secure.Server(host=h, port=p, identity=Identity.generate()).start()
    try:
        with pytest.raises(AuthenticationError, match="changed"):
            secure.send("secret", h, p)
    finally:
        evil.stop()


def test_tofu_off_and_no_key_is_refused(real):
    with pytest.raises(AuthenticationError):
        secure.Client(*real.address, tofu=False)


# ---------- impersonation / man-in-the-middle ----------

def test_wrong_pinned_key_is_rejected(real):
    other = Identity.generate()
    for pin in (other.public_key, other.fingerprint):
        with pytest.raises(AuthenticationError, match="not the pinned key"):
            secure.send("secret", *real.address, server_key=pin)


def test_impersonator_with_its_own_key_is_rejected():
    """Attacker runs a complete, well-behaved server with its own ML-DSA key."""
    trusted = Identity.generate()                      # the key the client pinned
    evil = secure.Server(port=0, identity=Identity.generate()).start()
    try:
        with pytest.raises(AuthenticationError):
            secure.send("top secret", *evil.address, server_key=trusted.public_key)
    finally:
        evil.stop()


class Mitm:
    """A one-connection TCP proxy between client and the real server.

    `mutate(direction, index, frame)` may rewrite any frame. `seen_c2s` records every frame
    the client sent, so tests can check that no application data reached the attacker.
    """

    def __init__(self, upstream, mutate=None):
        self.upstream, self.mutate = upstream, mutate or (lambda d, i, f: f)
        self.seen_c2s = []
        self.srv = socket.socket(); self.srv.bind(("127.0.0.1", 0)); self.srv.listen(1)
        self.address = self.srv.getsockname()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            c, _ = self.srv.accept()
            s = socket.create_connection(self.upstream)
            s2c = threading.Thread(target=self._pump, args=(s, c, "s2c"), daemon=True)
            s2c.start()
            self._pump(c, s, "c2s")
        except Exception:
            pass

    def _pump(self, src, dst, direction):
        i = 0
        try:
            while True:
                frame = _recv_frame(src)
                if direction == "c2s":
                    self.seen_c2s.append(frame)
                dst.sendall(struct.pack(">I", len(f := self.mutate(direction, i, frame))) + f)
                i += 1
        except Exception:
            for x in (src, dst):
                try: x.close()
                except Exception: pass

    def close(self):
        self.srv.close()


def test_control_honest_proxy_is_transparent(real):
    m = Mitm(real.address)
    assert secure.send("Hello", *m.address, server_key=real.public_key) == "received: Hello"
    m.close()


def test_mitm_swapping_in_its_own_kem_key_and_forging_the_signature_is_rejected(real):
    """The attacker keeps the real server's public key (so the pin check passes), substitutes its
    own ML-KEM key, and signs with its own ML-DSA key. The client must refuse and send nothing."""
    attacker = Identity.generate()
    ek_a, dk_a = ML_KEM_768.keygen()
    def mutate(direction, i, frame):
        if direction == "s2c" and i == 0:                      # server hello -> swap KEM key
            return frame[:PUBLIC_KEY_LEN] + ek_a + frame[PUBLIC_KEY_LEN + EK_LEN:]
        if direction == "s2c" and i == 1:                      # signature -> attacker's forgery
            return attacker.sign(b"whatever the attacker likes")
        return frame
    m = Mitm(real.address, mutate)
    with pytest.raises(AuthenticationError, match="signature"):
        secure.send("top secret", *m.address, server_key=real.public_key)
    assert len(m.seen_c2s) == 1                                # only the handshake message
    assert b"top secret" not in b"".join(m.seen_c2s)
    m.close()


def test_mitm_relaying_a_valid_signature_for_a_different_transcript_is_rejected(real):
    """Replay: the attacker records a genuine server signature from an earlier session and
    plays it back to a new client. It signs a different transcript, so it must fail."""
    h, p = real.address
    # record a legitimate handshake's signature
    s = socket.create_connection((h, p))
    server_hello = _recv_frame(s)
    ek = server_hello[PUBLIC_KEY_LEN:PUBLIC_KEY_LEN + EK_LEN]
    _, ct = ML_KEM_768.encaps(ek)
    _send_frame(s, MAGIC + os.urandom(NONCE_LEN) + ct)
    old_sig = _recv_frame(s); s.close()
    def mutate(direction, i, frame):
        return old_sig if (direction == "s2c" and i == 1) else frame
    m = Mitm(real.address, mutate)
    with pytest.raises(AuthenticationError, match="signature"):
        secure.send("top secret", *m.address, server_key=real.public_key)
    m.close()


def test_mitm_tampering_with_the_ciphertext_breaks_the_handshake(real):
    def mutate(direction, i, frame):
        if direction == "c2s" and i == 0:                      # client's KEM ciphertext
            b = bytearray(frame); b[-1] ^= 1
            return bytes(b)
        return frame
    m = Mitm(real.address, mutate)
    with pytest.raises(Exception):                             # bad signature / closed connection
        secure.send("top secret", *m.address, server_key=real.public_key)
    m.close()


def test_garbage_signature_and_short_signature_are_rejected(real):
    for bad in (b"", b"\x00" * SIGNATURE_LEN, os.urandom(SIGNATURE_LEN), b"short"):
        m = Mitm(real.address, lambda d, i, f, bad=bad: bad if (d == "s2c" and i == 1) else f)
        with pytest.raises(AuthenticationError):
            secure.send("x", *m.address, server_key=real.public_key)
        m.close()


def test_malformed_server_hello_is_rejected(real):
    m = Mitm(real.address, lambda d, i, f: f[:-1] if (d == "s2c" and i == 0) else f)
    with pytest.raises(AuthenticationError, match="malformed"):
        secure.send("x", *m.address, server_key=real.public_key)
    m.close()


def test_server_survives_a_rejected_client(real):
    with pytest.raises(AuthenticationError):
        secure.send("x", *real.address, server_key=Identity.generate().public_key)
    assert secure.send("still up", *real.address, server_key=real.public_key) == "received: still up"


# ---------- key storage ----------

def test_identity_save_load_roundtrip_and_permissions(tmp_path):
    ident = Identity.generate()
    path = ident.save(tmp_path / "k")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    again = Identity.load(path)
    assert again.public_key == ident.public_key and again.fingerprint == ident.fingerprint
    assert (tmp_path / "k.pub").read_text().strip() == ident.public_key.hex()


def test_default_server_key_is_created_once_and_reused():
    a = Identity.load_or_create()
    b = Identity.load_or_create()
    assert a.public_key == b.public_key
