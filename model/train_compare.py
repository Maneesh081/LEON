"""Train RandomForest, XGBoost and IsolationForest on the same data and compare.

Binary anomaly detection: BENIGN vs ANOMALY, using the exact 11-feature
contract produced by the LEON sensor (sensor/extractor.py). All three models
are evaluated on the identical 70/15/15 stratified split.

  - RandomForest  : supervised classifier
  - XGBoost       : supervised classifier (gradient boosting)
  - IsolationForest : unsupervised novelty detector (trained on BENIGN only)

The comparison report (model/comparison_report.json) reports accuracy,
macro/weighted F1, per-class precision/recall, benign false-alert rate and
attack alert recall for each model.  The best supervised model is saved to
model/models/best_model.joblib for live detection.
"""
from __future__ import annotations

import argparse
import glob
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

from sensor.feature_spec import CSV_COLUMN_MAP as COLUMN_ALIASES
from sensor.feature_spec import FEATURE_NAMES

BENIGN = "BENIGN"
ANOMALY = "ANOMALY"

BASE = Path(__file__).resolve().parent


def binary_label(value: str) -> str:
    return BENIGN if value.strip().upper() == BENIGN else ANOMALY


def load_cleaned(data_dir: Path, per_class: int, seed: int) -> pd.DataFrame:
    paths = sorted(glob.glob(str(data_dir / "*_cleaned.csv")))
    if not paths:
        raise RuntimeError(f"No *_cleaned.csv files found in {data_dir}")
    rng = np.random.default_rng(seed)
    buckets: dict[str, pd.DataFrame] = {}
    for path in paths:
        frame = pd.read_csv(path)
        frame["Label"] = frame["Label"].astype(str).map(binary_label)
        print(f"  {Path(path).name}: {len(frame):,} rows", flush=True)
        for label, group in frame.groupby("Label", sort=False):
            if len(group) > per_class:
                group = group.sample(per_class, random_state=int(rng.integers(2**31)))
            buckets[label] = pd.concat([buckets.get(label), group], ignore_index=True)
    if not buckets:
        raise RuntimeError("No labeled rows found in cleaned data")
    return pd.concat(buckets.values(), ignore_index=True)


def make_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    X = pd.DataFrame(index=df.index)
    for feature in FEATURE_NAMES:
        X[feature] = pd.to_numeric(df[COLUMN_ALIASES[feature]], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    y = df["Label"].astype(str).str.upper()
    return X, y


def make_pipeline(model) -> Pipeline:
    return Pipeline([
        ("preprocess", Pipeline([("imputer", SimpleImputer(strategy="median")),
                                 ("scale", StandardScaler())])),
        ("model", model),
    ])


def decide(y_true: np.ndarray, labels: np.ndarray, confidence: np.ndarray,
           threshold: float) -> tuple[dict, float]:
    benign = y_true == BENIGN
    attack = ~benign
    alert = (labels == ANOMALY) & (confidence >= threshold)
    safe = ~alert
    return {
        "benign_false_alert_rate": float(alert[benign].mean()) if benign.any() else 0.0,
        "attack_alert_recall": float(alert[attack].mean()) if attack.any() else 0.0,
        "safe_flow_rate": float(safe[benign].mean()) if benign.any() else 0.0,
        "attack_alert_precision": float(alert[attack].sum() / max(alert.sum(), 1)),
    }, threshold


def run() -> None:
    parser = argparse.ArgumentParser(description="RF vs XGBoost vs IsolationForest comparison")
    parser.add_argument("--data-dir", type=Path, default=BASE / "data" / "cleaned")
    parser.add_argument("--per-class", type=int, default=40_000,
                        help="max rows sampled per binary class (BENIGN/ANOMALY)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--quick", action="store_true",
                        help="small trees/estimators for a fast smoke run")
    parser.add_argument("--output", type=Path, default=BASE / "models")
    args = parser.parse_args()

    print(f"Loading cleaned CICIDS flows from {args.data_dir} (cap {args.per_class}/class)…")
    raw = load_cleaned(args.data_dir, args.per_class, args.seed)
    print(f"Training set: {len(raw):,} rows\n{raw['Label'].value_counts().to_string()}\n")

    X, y = make_features(raw)
    X_train, X_holdout, y_train, y_holdout = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=args.seed)
    X_valid, X_test, y_valid, y_test = train_test_split(
        X_holdout, y_holdout, test_size=0.50, stratify=y_holdout, random_state=args.seed)
    print(f"train={len(X_train):,} valid={len(X_valid):,} test={len(X_test):,}\n")

    n_est = 100 if args.quick else 400
    rf = make_pipeline(RandomForestClassifier(
        n_estimators=n_est, min_samples_leaf=2, max_features="sqrt",
        class_weight="balanced_subsample", n_jobs=-1, random_state=args.seed))
    print("Training RandomForest…", flush=True)
    t0 = time.monotonic()
    rf.fit(X_train, y_train)
    print(f"  done in {time.monotonic()-t0:.1f}s")

    import xgboost as xgb
    scale_pos = float((y_train == BENIGN).sum() / max((y_train != BENIGN).sum(), 1))
    y_train_enc = (y_train == ANOMALY).astype(int).to_numpy()
    y_valid_enc = (y_valid == ANOMALY).astype(int).to_numpy()
    xgb_pre = Pipeline([("imputer", SimpleImputer(strategy="median")),
                        ("scale", StandardScaler())]).fit(X_train)
    Xtr = xgb_pre.transform(X_train)
    Xva = xgb_pre.transform(X_valid)
    Xte = xgb_pre.transform(X_test)
    xgb_model = xgb.XGBClassifier(
        objective="binary:logistic", n_estimators=n_est, max_depth=6,
        learning_rate=0.1, subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=scale_pos, eval_metric="logloss",
        early_stopping_rounds=20, n_jobs=-1, random_state=args.seed,
        verbosity=0)
    xgb_pipe = Pipeline([("preprocess", xgb_pre), ("model", xgb_model)])
    print("Training XGBoost…", flush=True)
    t0 = time.monotonic()
    xgb_model.fit(Xtr, y_train_enc, eval_set=[(Xva, y_valid_enc)], verbose=False)
    print(f"  done in {time.monotonic()-t0:.1f}s")

    iso_pre = Pipeline([("imputer", SimpleImputer(strategy="median")),
                        ("scale", StandardScaler())])
    benign_train = X_train[y_train.eq(BENIGN)]
    iso_train = iso_pre.fit_transform(benign_train)
    iso = IsolationForest(n_estimators=300, max_samples=256, contamination="auto",
                          n_jobs=-1, random_state=args.seed).fit(iso_train)
    benign_valid = X_valid[y_valid.eq(BENIGN)]
    iso_threshold = float(np.quantile(
        iso.decision_function(iso_pre.transform(benign_valid)), 0.01))
    print(f"IsolationForest done (anomaly threshold {iso_threshold:.5f})\n")

    results: dict[str, dict] = {}

    def supervised(name, pipe, threshold):
        labels = pipe.predict(X_test)
        if labels.dtype.kind in "iu":
            labels = np.where(labels == 1, ANOMALY, BENIGN)
        conf = pipe.predict_proba(X_test).max(axis=1)
        acc = float(accuracy_score(y_test, labels))
        macro = float(f1_score(y_test, labels, average="macro", zero_division=0))
        weighted = float(f1_score(y_test, labels, average="weighted", zero_division=0))
        report = classification_report(y_test, labels, output_dict=True, zero_division=0)
        alert_stats, th = decide(y_test.to_numpy(), labels, conf, threshold)
        results[name] = {
            "kind": "supervised", "accuracy": acc, "macro_f1": macro,
            "weighted_f1": weighted, "threshold": th,
            **alert_stats,
            "per_class": {k: {"precision": v["precision"], "recall": v["recall"],
                              "f1": v["f1-score"], "support": int(v["support"])}
                          for k, v in report.items() if k in {BENIGN, ANOMALY}},
        }
        print(f"  {name:18s} acc={acc:.4f} macroF1={macro:.4f} weightedF1={weighted:.4f}")

    print("Evaluating supervised models on held-out test…")
    supervised("RandomForest", rf, 0.50)
    supervised("XGBoost", xgb_pipe, 0.50)
    print("Evaluating IsolationForest (novelty) on held-out test…")
    y_test_arr = y_test.to_numpy()
    benign_test = y_test_arr == BENIGN
    attack_test = ~benign_test
    iso_scores = iso.decision_function(iso_pre.transform(X_test))
    iso_labels = np.where(iso_scores < iso_threshold, ANOMALY, BENIGN)
    iso_conf = np.where(iso_labels == ANOMALY, (iso_threshold - iso_scores) / iso_threshold, 1.0)
    iso_conf = np.clip(iso_conf, 0.0, 1.0)
    iso_acc = float(accuracy_score(y_test_arr, iso_labels))
    iso_macro = float(f1_score(y_test_arr, iso_labels, average="macro", zero_division=0))
    iso_weighted = float(f1_score(y_test_arr, iso_labels, average="weighted", zero_division=0))
    report = classification_report(y_test_arr, iso_labels, output_dict=True, zero_division=0)
    alert_stats, _ = decide(y_test_arr, iso_labels, iso_conf, 0.0)
    results["IsolationForest"] = {
        "kind": "novelty", "accuracy": iso_acc, "macro_f1": iso_macro,
        "weighted_f1": iso_weighted, "threshold": iso_threshold, **alert_stats,
        "per_class": {k: {"precision": v["precision"], "recall": v["recall"],
                          "f1": v["f1-score"], "support": int(v["support"])}
                      for k, v in report.items() if k in {BENIGN, ANOMALY}},
    }
    print(f"  {'IsolationForest':18s} acc={iso_acc:.4f} macroF1={iso_macro:.4f} weightedF1={iso_weighted:.4f}")

    report_data = {
        "per_class_cap": args.per_class, "seed": args.seed, "quick": args.quick,
        "train": int(len(X_train)), "valid": int(len(X_valid)), "test": int(len(X_test)),
        "classes": [BENIGN, ANOMALY], "results": results,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "comparison_report.json").write_text(json.dumps(report_data, indent=2) + "\n")

    print("\n===== COMPARISON =====")
    hdr = f"{'model':18s} {'kind':11s} {'acc':>7s} {'macroF1':>8s} {'wtF1':>7s} {'benignFAR':>10s} {'attackRec':>10s}"
    print(hdr)
    for name, m in results.items():
        print(f"{name:18s} {m['kind']:11s} {m['accuracy']:7.4f} {m['macro_f1']:8.4f} "
              f"{m['weighted_f1']:7.4f} {m['benign_false_alert_rate']:10.4f} {m['attack_alert_recall']:10.4f}")

    supervised_best = max((m for m in results.values() if m["kind"] == "supervised"),
                          key=lambda m: m["macro_f1"])
    print(f"\nBest supervised model: "
          f"{[k for k, v in results.items() if v is supervised_best][0]} "
          f"(macroF1 {supervised_best['macro_f1']:.4f})")
    best_name = [k for k, v in results.items() if v is supervised_best][0]
    best_pipe = rf if best_name == "RandomForest" else xgb_pipe
    best_pipe.named_steps["model"].set_params(n_jobs=1)
    artifact = {"model": best_name, "features": list(FEATURE_NAMES),
                "classifier": best_pipe, "metrics": supervised_best,
                "anomaly_threshold": iso_threshold, "anomaly_detector": iso,
                "anomaly_preprocess": iso_pre}
    joblib.dump(artifact, args.output / "best_model.joblib")
    print(f"Saved live artifact: {args.output / 'best_model.joblib'}")
    print(f"Report: {args.output / 'comparison_report.json'}")


if __name__ == "__main__":
    run()
