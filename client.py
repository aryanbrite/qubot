import pqsecure as secure
with secure.Client() as c:
    print("Post-quantum connection established")
    print("Server authenticated with ML-DSA key:", c.server_fingerprint)
    print("Server replied:", c.send("Hello from the future"))
