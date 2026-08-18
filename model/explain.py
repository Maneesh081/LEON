"""L5 - SHAP explainability for live LEON verdicts.

Explains a single flow's prediction: which of the 11 features pushed the
verdict toward ANOMALY and which toward BENIGN, and by how much (in log-odds).
The saved classifier is a Pipeline([("preprocess", imputer+scaler), ("model", RF)]),
so the explainer applies the same preprocess before asking SHAP.

usage:
  .venv/bin/python -m model.explain --features '{"flow_duration":0.1,...}'
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import pandas as pd
import shap

from sensor.feature_spec import FEATURE_NAMES

BENIGN = "BENIGN"
ANOMALY = "ANOMALY"

FEATURE_LABELS = {
    "flow_duration": "duration",
    "protocol": "protocol",
    "dst_port": "dest port",
    "total_fwd_packets": "packets sent",
    "total_bwd_packets": "reply packets",
    "total_fwd_bytes": "bytes sent",
    "total_bwd_bytes": "reply bytes",
    "packets_per_second": "speed",
    "syn_count": "SYN flags",
    "ack_count": "ACK flags",
    "rst_count": "RST flags",
}


def strength(value: float) -> str:
    mag = abs(value)
    if mag < 0.05:
        return "weak"
    if mag < 0.20:
        return "moderate"
    return "strong"


def _label(name: str) -> str:
    return FEATURE_LABELS.get(name, name)


class FlowExplainer:
    """SHAP-based per-feature explanation of a LEON verdict."""

    def __init__(self, classifier: Any) -> None:
        self.preprocess = classifier.named_steps["preprocess"]
        self.model = classifier.named_steps["model"]
        self.features = list(FEATURE_NAMES)
        classes = list(self.model.classes_)
        if len(classes) == 2 and BENIGN in classes and ANOMALY in classes:
            self.anomaly_index = classes.index(ANOMALY)
        else:  # binary int-encoded (XGBoost) -> single array, anomaly is class 1
            self.anomaly_index = 1
        self.explainer = shap.TreeExplainer(self.model)

    def _scaled(self, features: dict) -> pd.DataFrame:
        frame = pd.DataFrame(
            [{name: float(features.get(name, 0.0)) for name in self.features}],
            columns=self.features,
        )
        return self.preprocess.transform(frame)

    def contributions(self, features: dict) -> dict[str, float]:
        """SHAP value per feature (log-odds, raw model output); positive pushes toward ANOMALY."""
        scaled = self._scaled(features)
        values = self.explainer.shap_values(scaled)
        if isinstance(values, list):
            row = values[self.anomaly_index][0]
        else:
            row = values[0]
        if row.ndim > 1:
            # binary raw output gives a [class0, class1] pair per feature
            row = row[:, self.anomaly_index]
        return {name: float(v) for name, v in zip(self.features, row)}

    @staticmethod
    def top(contributions: dict[str, float], n: int = 3) -> str:
        pos = sorted(((v, k) for k, v in contributions.items()), reverse=True)
        neg = sorted(((v, k) for k, v in contributions.items()))
        parts = []
        pushing = [(v, k) for v, k in pos if v > 0][:n]
        if pushing:
            parts.append("toward ANOMALY: " + ", ".join(
                f"{k}={v:+.3f}" for v, k in pushing))
        pulling = [(v, k) for v, k in neg if v < 0][:n]
        if pulling:
            parts.append("toward BENIGN:  " + ", ".join(
                f"{k}={v:+.3f}" for v, k in pulling))
        return " | ".join(parts) if parts else "all features ~neutral"

    @staticmethod
    def readable(contributions: dict[str, float], features: dict | None = None, n: int = 3) -> str:
        ranked = sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)
        bits = []
        for k, v in ranked[:n]:
            label = _label(k)
            raw = features.get(k) if features else None
            shown = f"{label}={raw:g}" if raw is not None else label
            word = strength(v)
            if v > 0.01:
                bits.append(f"{shown} → ATTACK-like ({word})")
            elif v < -0.01:
                bits.append(f"{shown} → NORMAL ({word})")
            else:
                bits.append(f"{shown} → neutral")
        return " · ".join(bits) if bits else "all features ~neutral"


def main() -> int:
    parser = argparse.ArgumentParser(description="LEON SHAP explanation for one flow")
    parser.add_argument("--features", required=True, help="single JSON feature dict")
    args = parser.parse_args()

    from model.model import FlowClassifier

    feats = json.loads(args.features)
    clf = FlowClassifier()
    expl = FlowExplainer(clf.classifier)
    contribs = expl.contributions(feats)
    print(expl.readable(contribs, feats))
    return 0


if __name__ == "__main__":
    sys.exit(main())
