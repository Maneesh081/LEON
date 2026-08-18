"""LEON IPS - the full prevention pipeline.

Chain: capture -> flows -> features -> classify -> explain -> decide -> block.

usage:
  sudo .venv/bin/python -m prevention.run_ips --live -i wlan0 -d 30 [--explain] [--prevent] [--honeypot]
  .venv/bin/python -m prevention.run_ips --list-blocks
  .venv/bin/python -m prevention.run_ips --unblock 1.2.3.4

Default is detect mode: every flow is classified and decided (ALLOW/ALERT/
BLOCK) and logged, but no nftables rule is created. Add --prevent (or set
LEON_PREVENT=1) to actually block attacker IPs.
"""
from __future__ import annotations

import argparse
import sys
import time
from typing import Any

from core.config import Config, load_config
from core.events import EventStore
from sensor.capture import CaptureSession
from sensor.extractor import extract_features
from sensor.flow import FlowTable

from prevention.blocker import NftablesBlocker
from prevention.decision import BLOCK, DecisionEngine
from prevention.honeypot import Honeypot


def show(decision: Any, verdict: dict, flow: Any = None) -> None:
    tag = decision.action.upper()
    line = f"[{tag:<5}] label={verdict['label']:<8} conf={verdict['confidence']:.4f}"
    if "anomaly_score" in verdict:
        line += f"  novelty={'YES' if verdict['novelty'] else 'no '} score={verdict['anomaly_score']:.4f}"
    print(line)
    if flow is not None:
        print(f"      {flow.describe()}")
    if verdict.get("novelty") and verdict["label"] == "BENIGN":
        print("      note: novelty flag - unusual pattern, NOT a known attack")
    print(f"      action: {decision.action} - {decision.reason}")
    why = verdict.get("explanation")
    if why:
        print(f"      why: {why}")


def handle_probe(ip: str, engine: Any, blocker: Any, enforce: bool, store: EventStore) -> None:
    verdict = {"label": "ANOMALY", "confidence": 1.0, "benign_probability": 0.0,
               "alert": True, "novelty": False, "anomaly_score": 0.0, "features": {}}
    decision = engine.decide(verdict, attacker_ip=ip, source="honeypot")
    store.emit("L4", "verdict", label="ANOMALY", confidence=1.0, novelty=False,
               anomaly_score=0.0, flow={"honeypot": ip})
    print(f"[HONEYPOT] probe from {ip} -> {decision.action.upper()}: {decision.reason}")
    if decision.action == BLOCK and enforce:
        blocker.block(ip)


def run_live(cfg: Config, args: Any, clf: Any, engine: DecisionEngine,
             blocker: Any, enforce: bool, explainer: Any, store: EventStore) -> None:
    iface = args.iface or (cfg.interfaces[0] if cfg.interfaces else "lo")
    duration = args.duration or 10.0
    ft = FlowTable(idle_timeout=cfg.flow_idle_timeout, active_timeout=cfg.flow_active_timeout)
    cap = CaptureSession(iface, cfg.include_icmp, cfg.port_allowlist, cfg.drop_link_local)
    cap.start()
    print(f"capturing {iface} for {duration:.0f}s, classifying + deciding each completed flow…\n")

    def handle(flow: Any) -> None:
        feats = extract_features(flow)
        verdict = clf.predict(feats)
        if explainer is not None and (args.explain or verdict["alert"]):
            contribs = explainer.contributions(verdict["features"])
            verdict["explanation"] = explainer.readable(contribs, verdict["features"])
        decision = engine.decide(verdict, flow)
        store.emit("L4", "verdict", label=verdict["label"], confidence=verdict["confidence"],
                   novelty=verdict.get("novelty", False),
                   anomaly_score=verdict.get("anomaly_score"), flow=flow.to_dict(), features=feats)
        show(decision, verdict, flow)
        if decision.action == BLOCK and enforce:
            blocker.block(decision.attacker_ip)

    try:
        deadline = time.monotonic() + duration
        last_expire = 0.0
        while True:
            got = False
            for pkt in cap.packets(timeout=0.5):
                got = True
                if pkt is None:
                    now = time.time()
                    if now - last_expire > 0.5:
                        for flow in ft.expire(now):
                            handle(flow)
                        last_expire = now
                    break
                ft.update(pkt, pkt.ts)
                if pkt.ts - last_expire > 0.5:
                    for flow in ft.expire(pkt.ts):
                        handle(flow)
                    last_expire = pkt.ts
            if time.monotonic() >= deadline:
                break
    finally:
        cap.stop()
    for flow in ft.flush_all():
        handle(flow)


def main() -> int:
    parser = argparse.ArgumentParser(prog="run_ips", description="LEON IPS: detect -> decide -> block")
    parser.add_argument("--live", action="store_true", help="run capture -> classify -> decide (needs sudo)")
    parser.add_argument("-i", "--iface", default=None, help="capture interface (default: config first)")
    parser.add_argument("-d", "--duration", type=float, default=None, help="capture seconds (default 10)")
    parser.add_argument("--explain", action="store_true",
                        help="add SHAP reasons for EVERY flow (alerts always get them)")
    parser.add_argument("--prevent", action="store_true", help="enable nftables blocking (default: detect-only)")
    parser.add_argument("--honeypot", action="store_true", help="start the decoy honeypot listener")
    parser.add_argument("--list-blocks", action="store_true", help="show currently blocked IPs")
    parser.add_argument("--unblock", metavar="IP", help="remove a blocked IP")
    args = parser.parse_args()

    cfg = load_config()
    blocker = NftablesBlocker(cfg)

    if args.list_blocks:
        for ip in blocker.list_blocked():
            print(ip)
        return 0

    if args.unblock:
        ok = blocker.unblock(args.unblock)
        print(f"{'removed' if ok else 'not present'}: {args.unblock}")
        return 0

    if args.live:
        from model.explain import FlowExplainer
        from model.model import FlowClassifier

        store = EventStore()
        engine = DecisionEngine(cfg, store)
        enforce = cfg.prevent_mode or args.prevent
        if enforce:
            blocker.ensure()
            restored = blocker.restore()
            print(f"prevent mode: nftables active, {restored} persisted blocks restored")
        else:
            print("detect mode: decisions logged, blocking disabled (use --prevent)")
        clf = FlowClassifier()
        explainer = FlowExplainer(clf.classifier)

        honeypot = None
        if args.honeypot:
            if not cfg.block_honeypot_enabled:
                print("honeypot disabled by config (LEON_HONEYPOT_ENABLED=0)")
            else:
                honeypot = Honeypot(cfg, store, on_probe=lambda ip: handle_probe(
                    ip, engine, blocker, enforce, store))
                honeypot.start()
                print(f"honeypot active on ports {cfg.honeypot_ports}")
        try:
            run_live(cfg, args, clf, engine, blocker, enforce, explainer, store)
        finally:
            if honeypot is not None:
                honeypot.stop()
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
