"""python3 -m pqsecure serve | fingerprint | keygen"""
import sys

from . import Identity, serve
from .identity import home_dir

USAGE = """usage:
  python3 -m pqsecure serve         run a server (creates ~/.pqsecure/server_key on first run)
  python3 -m pqsecure fingerprint   print this machine's server key fingerprint and public key file
  python3 -m pqsecure keygen        create the server key if it does not exist"""


def main(argv=None):
    cmd = (argv or sys.argv[1:] or [""])[0]
    if cmd == "serve":
        print("Waiting for a post-quantum connection on 127.0.0.1:9443 ...", flush=True)
        serve()
    elif cmd in ("fingerprint", "keygen"):
        ident = Identity.load_or_create()
        print(ident.fingerprint)
        print("public key file:", home_dir() / "server_key.pub")
    else:
        print(USAGE)
        return 2


if __name__ == "__main__":
    sys.exit(main())
