"""Offline tests for the L6 decision engine (no root, no nftables)."""
import json
import tempfile
from pathlib import Path

from core.config import Config
from core.events import EventStore
from prevention.decision import (
    ALLOW,
    ALERT,
    BLOCK,
    SRC_HONEYPOT,
    SRC_MODEL,
    SRC_NOVELTY,
    SRC_WHITELIST,
    DecisionEngine,
)
from sensor.flow import Flow


def chk(cond, msg):
    if not cond:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ok: {msg}")


def mkflow(**overrides) -> Flow:
    params = dict(
        key=("10.0.0.1", "10.0.0.2", 12345, 80, 6),
        protocol=6, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=12345, dst_port=80, start_ts=0.0, last_ts=1.0,
        fwd_packets=4, bwd_packets=2, fwd_bytes=400, bwd_bytes=200,
        syn_count=1, ack_count=5, fin_count=1, rst_count=0,
    )
    params.update(overrides)
    return Flow(**params)


def make_engine():
    cfg = Config()
    cfg.whitelist = ["127.0.0.1"]
    cfg.block_confidence = 0.90
    cfg.alert_confidence = 0.50
    td = tempfile.TemporaryDirectory()
    store = EventStore(str(Path(td.name) / "events.jsonl"))
    engine = DecisionEngine(cfg, store)
    return cfg, engine, store, td


def verdict(label, conf, alert, novelty=False):
    return {"label": label, "confidence": conf, "alert": alert,
            "novelty": novelty, "features": {}}


def test_whitelist():
    print("test: whitelisted host is never blocked")
    cfg, engine, store, td = make_engine()
    cfg.whitelist = ["10.0.0.1"]
    d = engine.decide(verdict("ANOMALY", 1.0, True), mkflow())
    chk(d.action == ALLOW, f"allow, got {d.action}")
    chk(d.source == SRC_WHITELIST, f"source=whitelist, got {d.source}")
    td.cleanup()


def test_high_conf_block():
    print("test: high-confidence ANOMALY blocks the flow initiator")
    cfg, engine, store, td = make_engine()
    flow = mkflow()
    d = engine.decide(verdict("ANOMALY", 0.99, True), flow)
    chk(d.action == BLOCK, f"block, got {d.action}")
    chk(d.attacker_ip == flow.src_ip, f"attacker is src_ip, got {d.attacker_ip}")
    chk(d.source == SRC_MODEL, f"source=model, got {d.source}")
    td.cleanup()


def test_below_block_threshold():
    print("test: ANOMALY below block threshold alerts instead")
    cfg, engine, store, td = make_engine()
    d = engine.decide(verdict("ANOMALY", 0.60, True), mkflow())
    chk(d.action == ALERT, f"alert, got {d.action}")
    chk(d.source == SRC_MODEL, f"source=model, got {d.source}")
    td.cleanup()


def test_novelty_never_blocks():
    print("test: novelty-only alert never blocks")
    cfg, engine, store, td = make_engine()
    d = engine.decide(verdict("BENIGN", 0.99, True, novelty=True), mkflow())
    chk(d.action == ALERT, f"alert, got {d.action}")
    chk(d.source == SRC_NOVELTY, f"source=novelty, got {d.source}")
    td.cleanup()


def test_honeypot_block():
    print("test: honeypot probe is a deterministic block")
    cfg, engine, store, td = make_engine()
    d = engine.decide(verdict("ANOMALY", 1.0, True), attacker_ip="5.6.7.8",
                      source="honeypot")
    chk(d.action == BLOCK, f"block, got {d.action}")
    chk(d.attacker_ip == "5.6.7.8", f"attacker from explicit ip, got {d.attacker_ip}")
    chk(d.source == SRC_HONEYPOT, f"source=honeypot, got {d.source}")
    td.cleanup()


def test_normal_allow():
    print("test: normal flow is allowed")
    cfg, engine, store, td = make_engine()
    d = engine.decide(verdict("BENIGN", 0.99, False), mkflow())
    chk(d.action == ALLOW, f"allow, got {d.action}")
    td.cleanup()


def test_event_logged():
    print("test: every decision is written to the event store")
    cfg, engine, store, td = make_engine()
    engine.decide(verdict("ANOMALY", 0.99, True), mkflow())
    recs = store.recent()
    chk(recs, "events recorded")
    last = recs[-1]
    chk(last["layer"] == "L6" and last["type"] == "decision", f"layered as L6 decision: {last.get('type')}")
    chk(last["action"] == BLOCK, "action persisted")
    td.cleanup()


def test_json_serializable():
    print("test: decision is JSON-serializable")
    cfg, engine, store, td = make_engine()
    d = engine.decide(verdict("ANOMALY", 0.99, True), mkflow())
    json.dumps(d.to_dict())
    print("  ok: decision to_dict JSON-serializable")
    td.cleanup()


if __name__ == "__main__":
    test_whitelist()
    test_high_conf_block()
    test_below_block_threshold()
    test_novelty_never_blocks()
    test_honeypot_block()
    test_normal_allow()
    test_event_logged()
    test_json_serializable()
    print("\nALL DECISION TESTS PASSED")
