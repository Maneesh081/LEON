"""Offline tests for the L7 active honeypot (no root)."""
import socket
import tempfile
import threading
import time
from pathlib import Path

from core.config import Config
from core.events import EventStore
from prevention.honeypot import Honeypot


def chk(cond, msg):
    if not cond:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ok: {msg}")


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_probe_detected():
    print("test: connecting to the honeypot fires on_probe with the peer IP")
    cfg = Config()
    port = free_port()
    cfg.honeypot_ports = [port]
    cfg.honeypot_dwell_secs = 0.2
    peers = []
    got = threading.Event()
    td = tempfile.TemporaryDirectory()
    store = EventStore(str(Path(td.name) / "events.jsonl"))
    hp = Honeypot(cfg, store, on_probe=lambda ip: (peers.append(ip), got.set()))
    hp.start()
    time.sleep(0.3)
    conn = socket.create_connection(("127.0.0.1", port), timeout=2.0)
    conn.sendall(b"hello")
    conn.close()
    fired = got.wait(3.0)
    hp.stop()
    chk(fired, "on_probe fired on connection")
    chk("127.0.0.1" in peers, f"peer IP recorded, got {peers}")
    recs = store.recent()
    chk(any(r["type"] == "honeypot.probe" for r in recs), "probe event emitted")
    td.cleanup()


def test_stop_clean():
    print("test: stop() closes listeners cleanly")
    cfg = Config()
    port = free_port()
    cfg.honeypot_ports = [port]
    cfg.honeypot_dwell_secs = 0.2
    hp = Honeypot(cfg)
    hp.start()
    time.sleep(0.3)
    hp.stop()
    # port should be released
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
        print("  ok: port released after stop")
    finally:
        sock.close()


if __name__ == "__main__":
    test_probe_detected()
    test_stop_clean()
    print("\nALL HONEYPOT TESTS PASSED")
