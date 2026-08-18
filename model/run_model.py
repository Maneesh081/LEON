"""Classify live L3 feature rows with our trained model.

usage:
  .venv/bin/python -m model.run_model --features '{"flow_duration":0.1,...}'
  .venv/bin/python -m model.run_model --live         # sudo: sensor capture then classify
  .venv/bin/python -m model.run_model --jsonl flows.jsonl   # one feature dict per line
  .venv/bin/python -m model.run_model --live --explain     # + SHAP per-flow reasons
Alerts always print the flow summary (5-tuple) and, with --explain, the SHAP
reasons. With --live every ALERT is explained regardless of the flag.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from model.model import BENIGN, FlowClassifier


def show(verdict: dict, explainer: Any = None, flow: Any = None, explain: bool = False) -> None:
    tag = "ALERT" if verdict["alert"] else "ok   "
    line = f"[{tag}] label={verdict['label']:<8} conf={verdict['confidence']:.4f}"
    if "anomaly_score" in verdict:
        line += f"  novelty={'YES' if verdict['novelty'] else 'no '} score={verdict['anomaly_score']:.4f}"
    print(line)
    if not verdict["alert"]:
        return
    if flow is not None:
        print(f"      {flow.describe()}")
    if verdict.get("novelty") and verdict["label"] == BENIGN:
        print("      note: novelty flag - unusual pattern, NOT a known attack")
    if explainer is not None and (explain or verdict["alert"]):
        contribs = explainer.contributions(verdict["features"])
        print(f"      why: {explainer.readable(contribs, verdict['features'])}")


def main() -> int:
    parser = argparse.ArgumentParser(description="LEON model: classify L3 feature rows")
    parser.add_argument("--features", help="single JSON feature dict")
    parser.add_argument("--jsonl", help="file with one feature dict per line")
    parser.add_argument("--live", action="store_true",
                        help="run sensor capture -> features -> classify (needs sudo)")
    parser.add_argument("-i", "--iface", default=None, help="capture interface (default: config first)")
    parser.add_argument("-d", "--duration", type=float, default=None,
                        help="capture seconds (default: 10)")
    parser.add_argument("--explain", action="store_true",
                        help="add SHAP per-feature reasons (live mode explains all ALERTs anyway)")
    args = parser.parse_args()

    clf = FlowClassifier()
    explainer = None
    if args.live or args.explain:
        from model.explain import FlowExplainer
        explainer = FlowExplainer(clf.classifier)

    if args.features:
        show(clf.predict(json.loads(args.features)), explainer, explain=args.explain)
        return 0

    if args.jsonl:
        with open(args.jsonl) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                show(clf.predict(json.loads(line)), explainer, explain=args.explain)
        return 0

    if args.live:
        return run_live(clf, args.iface, args.duration, explainer)

    parser.print_help()
    return 2


def run_live(clf: FlowClassifier, iface: str | None = None, duration: float | None = None,
             explainer: Any = None) -> int:
    import time

    from core.config import load_config
    from sensor.capture import CaptureSession
    from sensor.extractor import extract_features
    from sensor.flow import FlowTable

    cfg = load_config()
    if iface is None:
        iface = cfg.interfaces[0] if cfg.interfaces else "lo"
    if duration is None:
        duration = 10.0
    ft = FlowTable(idle_timeout=cfg.flow_idle_timeout, active_timeout=cfg.flow_active_timeout)
    cap = CaptureSession(iface, cfg.include_icmp, cfg.port_allowlist, cfg.drop_link_local)
    cap.start()
    print(f"capturing {iface} for {duration:.0f}s, classifying each completed flow…\n")
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
                            show(clf.predict(extract_features(flow)), explainer, flow)
                        last_expire = now
                    break
                ft.update(pkt, pkt.ts)
                if pkt.ts - last_expire > 0.5:
                    for flow in ft.expire(pkt.ts):
                        show(clf.predict(extract_features(flow)), explainer, flow)
                    last_expire = pkt.ts
            if not got and time.monotonic() >= deadline:
                break
            if time.monotonic() >= deadline:
                break
    finally:
        cap.stop()
    for flow in ft.flush_all():
        show(clf.predict(extract_features(flow)), explainer, flow)
    return 0


if __name__ == "__main__":
    sys.exit(main())
