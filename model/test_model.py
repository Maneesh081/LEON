"""Offline unit tests for the model layer (no root, no big training)."""
import json
import tempfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from model.explain import FlowExplainer
from model.model import BENIGN, ANOMALY, FlowClassifier
from sensor.extractor import extract_features, feature_vector
from sensor.flow import Flow
from sensor.feature_spec import FEATURE_NAMES


def chk(cond, msg):
    if not cond:
        raise AssertionError(f"FAIL: {msg}")
    print(f"  ok: {msg}")


def mkflow(duration: float, **overrides) -> Flow:
    params = dict(
        key=("10.0.0.1", "10.0.0.2", 12345, 80, 6),
        protocol=6, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=12345, dst_port=80, start_ts=0.0, last_ts=duration,
        fwd_packets=4, bwd_packets=2, fwd_bytes=400, bwd_bytes=200,
        syn_count=1, ack_count=5, fin_count=1, rst_count=0,
    )
    params.update(overrides)
    return Flow(**params)


def make_toy_artifact(tmp: Path) -> Path:
    rows = [
        extract_features(mkflow(duration=1.0, dst_port=80, fwd_packets=2, ack_count=3)),
        extract_features(mkflow(duration=2.0, dst_port=443, fwd_packets=5, ack_count=6)),
        extract_features(mkflow(duration=0.5, dst_port=8080, fwd_packets=1, syn_count=1)),
        extract_features(mkflow(duration=0.1, dst_port=22, fwd_packets=3, syn_count=1, rst_count=1)),
    ]
    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = pd.Series([BENIGN, BENIGN, ANOMALY, ANOMALY])
    pipe = Pipeline([
        ("preprocess", Pipeline([("imputer", SimpleImputer(strategy="median")),
                                 ("scale", StandardScaler())])),
        ("model", RandomForestClassifier(n_estimators=5, random_state=1)),
    ])
    pipe.fit(X, y)
    artifact = {"model": "RandomForest", "features": list(FEATURE_NAMES),
                "classifier": pipe, "anomaly_threshold": -1.0,
                "anomaly_detector": None, "anomaly_preprocess": None}
    path = tmp / "best_model.joblib"
    joblib.dump(artifact, path)
    return path


def test_feature_contract():
    print("test: model features == sensor FEATURE_NAMES")
    clf = FlowClassifier(make_toy_artifact(Path(tempfile.mkdtemp())))
    chk(clf.features == FEATURE_NAMES, "artifact feature list matches sensor spec")
    vec = feature_vector(extract_features(mkflow(duration=1.0)))
    chk(len(vec) == 11 and all(isinstance(v, float) for v in vec), "feature vector is 11 floats")


def test_predict_structure():
    print("test: predict() returns expected fields")
    with tempfile.TemporaryDirectory() as td:
        clf = FlowClassifier(make_toy_artifact(Path(td)))
        v = clf.predict(extract_features(mkflow(duration=2.0)))
        for key in ("label", "confidence", "benign_probability", "alert", "features"):
            chk(key in v, f"verdict has {key}")
        chk(v["label"] in (BENIGN, ANOMALY), "label is BENIGN or ANOMALY")
        chk(0.0 <= v["confidence"] <= 1.0, "confidence in [0,1]")
        chk(len(v["features"]) == 11, "features echoed back")


def test_alert_logic():
    print("test: alert requires ANOMALY label + confidence >= threshold")
    with tempfile.TemporaryDirectory() as td:
        clf = FlowClassifier(make_toy_artifact(Path(td)))
        anomaly = extract_features(mkflow(duration=0.1, dst_port=22, syn_count=1, rst_count=1))
        v = clf.predict(anomaly)
        chk(v["alert"] == (v["label"] == ANOMALY and v["confidence"] >= 0.5),
            "alert matches rule (no novelty detector in toy)")


def test_roundtrip_json():
    print("test: verdict serializes to JSON")
    with tempfile.TemporaryDirectory() as td:
        clf = FlowClassifier(make_toy_artifact(Path(td)))
        v = clf.predict(extract_features(mkflow(duration=1.0)))
        json.dumps(v)
    print("  ok: verdict JSON-serializable")


def test_explainer():
    print("test: SHAP explainer returns 11 per-feature contributions")
    with tempfile.TemporaryDirectory() as td:
        clf = FlowClassifier(make_toy_artifact(Path(td)))
        expl = FlowExplainer(clf.classifier)
        feats = extract_features(mkflow(duration=0.1, dst_port=22, syn_count=1, rst_count=1))
        contribs = expl.contributions(feats)
        chk(set(contribs) == set(FEATURE_NAMES), "one SHAP value per sensor feature")
        chk(all(np.isfinite(v) for v in contribs.values()), "all contributions finite")
        text = expl.top(contribs)
        chk("ANOMALY" in text or "BENIGN" in text or "neutral" in text, "top() renders a readable reason")
        plain = expl.readable(contribs, feats)
        chk(any(w in plain for w in ("NORMAL", "ATTACK", "neutral")), "readable() renders plain-words reason")
        chk("protocol" in plain or "port" in plain or "bytes" in plain, "readable() uses feature labels/values")


def test_live_artifact_explains():
    print("test: real saved artifact explains a flow (model.models.best_model.joblib)")
    from model.model import BASE as MODEL_BASE
    path = MODEL_BASE / "models" / "best_model.joblib"
    if not path.exists():
        print("  skip: no trained artifact present")
        return
    clf = FlowClassifier(path)
    expl = FlowExplainer(clf.classifier)
    feats = {name: float(i + 1) for i, name in enumerate(FEATURE_NAMES)}
    contribs = expl.contributions(feats)
    chk(set(contribs) == set(FEATURE_NAMES), "real artifact: one value per feature")
    print(f"  sample reason: {expl.top(contribs)}")


if __name__ == "__main__":
    test_feature_contract()
    test_predict_structure()
    test_alert_logic()
    test_roundtrip_json()
    test_explainer()
    test_live_artifact_explains()
    print("\nALL MODEL TESTS PASSED")
