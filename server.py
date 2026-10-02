import pqsecure as secure
print("Waiting for a post-quantum connection on 127.0.0.1:9443 ...", flush=True)
secure.serve(verbose=True)
