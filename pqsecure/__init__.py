"""pqsecure: a tiny post-quantum secure channel (prototype).

    import pqsecure as secure
    secure.send("Hello")
"""
from .core import Client, Server, send, serve, DEFAULT_HOST, DEFAULT_PORT

__all__ = ["Client", "Server", "send", "serve", "DEFAULT_HOST", "DEFAULT_PORT"]
