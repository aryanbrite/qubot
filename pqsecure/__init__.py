"""pqsecure: a tiny authenticated post-quantum secure channel (unaudited prototype).

    import pqsecure as secure
    secure.send("Hello")
"""
from .core import Client, Server, send, serve, DEFAULT_HOST, DEFAULT_PORT
from .identity import AuthenticationError, Identity, fingerprint

__version__ = "0.2.0"
__all__ = ["Client", "Server", "send", "serve", "DEFAULT_HOST", "DEFAULT_PORT",
           "AuthenticationError", "Identity", "fingerprint", "__version__"]
