"""Server identity: an ML-DSA-65 signing key pair (FIPS 204, via dilithium-py).

The server keeps the secret key. Clients learn the public key (or its SHA-256
fingerprint) and pin it. Nothing here implements a primitive; it only stores keys.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

PUBLIC_KEY_LEN = 1952   # ML-DSA-65 public key
SECRET_KEY_LEN = 4032   # ML-DSA-65 secret key
SIGNATURE_LEN = 3309    # ML-DSA-65 signature
SIG_CONTEXT = b"pqsecure-v0.2-handshake"


class AuthenticationError(Exception):
    """The server could not prove it holds the key the client trusts."""


def home_dir():
    """Where keys live. Override with the PQSECURE_HOME environment variable."""
    return Path(os.environ.get("PQSECURE_HOME") or Path.home() / ".pqsecure")


def fingerprint(public_key):
    """SHA-256 fingerprint of a server public key, as 'sha256:<hex>'."""
    return "sha256:" + hashlib.sha256(public_key).hexdigest()


def _write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)


class Identity:
    """A server's long-term ML-DSA-65 key pair."""

    def __init__(self, public_key, secret_key):
        if len(public_key) != PUBLIC_KEY_LEN or len(secret_key) != SECRET_KEY_LEN:
            raise ValueError("not an ML-DSA-65 key pair")
        self.public_key = bytes(public_key)
        self._secret_key = bytes(secret_key)

    @classmethod
    def generate(cls):
        pk, sk = ML_DSA_65.keygen()
        return cls(pk, sk)

    @property
    def fingerprint(self):
        return fingerprint(self.public_key)

    def sign(self, message):
        return ML_DSA_65.sign(self._secret_key, message, ctx=SIG_CONTEXT)

    def save(self, path=None):
        """Write the secret key (mode 0600) and a '.pub' file you can give to clients."""
        path = Path(path) if path else home_dir() / "server_key"
        _write_private(path, json.dumps({"alg": "ML-DSA-65",
                                         "public_key": self.public_key.hex(),
                                         "secret_key": self._secret_key.hex()}))
        path.with_name(path.name + ".pub").write_text(self.public_key.hex() + "\n")
        return path

    @classmethod
    def load(cls, path=None):
        path = Path(path) if path else home_dir() / "server_key"
        d = json.loads(path.read_text())
        return cls(bytes.fromhex(d["public_key"]), bytes.fromhex(d["secret_key"]))

    @classmethod
    def load_or_create(cls, path=None):
        """Load the default server key, creating and saving one on first use."""
        path = Path(path) if path else home_dir() / "server_key"
        if path.exists():
            return cls.load(path)
        ident = cls.generate()
        ident.save(path)
        return ident


def verify(public_key, message, signature):
    """True only if `signature` is a valid ML-DSA-65 signature. Never raises."""
    if len(public_key) != PUBLIC_KEY_LEN or len(signature) != SIGNATURE_LEN:
        return False
    try:
        return bool(ML_DSA_65.verify(public_key, message, signature, ctx=SIG_CONTEXT))
    except Exception:
        return False


def resolve_pin(server_key):
    """Turn whatever the caller passed into ('pk', bytes) or ('fp', 32 bytes).

    Accepts: an Identity, a public key (bytes or hex), a fingerprint
    ('sha256:<hex>' or 64 hex chars, or 32 raw bytes), or a path to a .pub file.
    """
    if isinstance(server_key, Identity):
        return "pk", server_key.public_key
    if isinstance(server_key, (bytes, bytearray)):
        b = bytes(server_key)
        if len(b) == PUBLIC_KEY_LEN:
            return "pk", b
        if len(b) == 32:
            return "fp", b
        raise ValueError("server_key bytes must be a 1952-byte public key or a 32-byte fingerprint")
    if isinstance(server_key, os.PathLike) or (isinstance(server_key, str) and os.path.isfile(server_key)):
        return resolve_pin(Path(server_key).read_text().strip())
    if isinstance(server_key, str):
        s = server_key.strip()
        if s.lower().startswith("sha256:"):
            s = s[7:]
        try:
            raw = bytes.fromhex(s)
        except ValueError:
            raise ValueError("server_key is not a path, hex public key, or sha256 fingerprint") from None
        return resolve_pin(raw)
    raise TypeError("unsupported server_key type")


def matches_pin(pin, public_key):
    kind, value = pin
    if kind == "pk":
        return hmac.compare_digest(value, public_key)
    return hmac.compare_digest(value, hashlib.sha256(public_key).digest())


# --- trust on first use -------------------------------------------------------

def _known_path():
    return home_dir() / "known_servers.json"


def _load_known():
    p = _known_path()
    return json.loads(p.read_text()) if p.exists() else {}


def tofu_check(peer, public_key):
    """Trust-on-first-use. Pin `peer` ('host:port') on first sight; reject any later change."""
    known = _load_known()
    fp = fingerprint(public_key)
    if peer not in known:
        known[peer] = fp
        p = _known_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(known, indent=2))
        return
    if not hmac.compare_digest(known[peer].encode(), fp.encode()):
        raise AuthenticationError(
            f"server key for {peer} changed (pinned {known[peer]}, got {fp}). "
            "Possible impersonation. If the server key was rotated on purpose, "
            f"remove the entry from {_known_path()}.")
