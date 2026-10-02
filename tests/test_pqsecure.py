import socket, struct
import pytest
from cryptography.exceptions import InvalidTag
import pqsecure as secure
from pqsecure.core import Client, _recv_frame, _send_frame, client_handshake, server_handshake

@pytest.fixture
def srv():
    s = secure.Server(port=0).start()
    yield s
    s.stop()

def test_one_liner(srv):
    h, p = srv.address
    assert secure.send("Hello", h, p) == "received: Hello"

def test_many_messages_and_unicode(srv):
    with Client(*srv.address) as c:
        for m in ["a", "héllo ✓", "x" * 50000]:
            assert c.send(m) == "received: " + m

def test_wire_is_not_plaintext(srv):
    # sniff by wrapping the channel's socket send
    seen = []
    c = Client(*srv.address)
    class Spy:
        def __init__(s, sock): s.sock = sock
        def sendall(s, d): seen.append(d); s.sock.sendall(d)
        def __getattr__(s, n): return getattr(s.sock, n)
    c._ch.sock = Spy(c._ch.sock)
    c.send("super secret words")
    c.close()
    assert seen and all(b"super secret" not in d for d in seen)

def test_tampered_record_rejected():
    a, b = socket.socketpair()
    import threading
    out = {}
    t = threading.Thread(target=lambda: out.update(s=server_handshake(b)))
    t.start(); cl = client_handshake(a); t.join()
    cl.send("hi")
    raw = _recv_frame(out["s"].sock)
    bad = bytearray(raw); bad[0] ^= 1
    # re-feed tampered bytes
    c2, d2 = socket.socketpair()
    _send_frame(c2, bytes(bad))
    out["s"].sock = d2
    with pytest.raises(InvalidTag):
        out["s"].recv()

def test_replay_rejected():
    a, b = socket.socketpair()
    import threading
    out = {}
    t = threading.Thread(target=lambda: out.update(s=server_handshake(b)))
    t.start(); cl = client_handshake(a); t.join()
    cl.send("one")
    frame = _recv_frame(out["s"].sock)
    c2, d2 = socket.socketpair()
    _send_frame(c2, frame); _send_frame(c2, frame)
    out["s"].sock = d2
    assert out["s"].recv() == b"one"
    with pytest.raises(InvalidTag):
        out["s"].recv()

def test_garbage_handshake_does_not_kill_server(srv):
    s = socket.create_connection(srv.address)
    _recv_frame(s); _send_frame(s, b"garbage"); s.close()
    assert secure.send("still up", *srv.address) == "received: still up"
