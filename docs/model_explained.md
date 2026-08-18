# LEON — How the Models Work (L4 + L5)

Plain-English walkthrough of the machine-learning layer: what the models are,
how the code trains and evaluates them, what the saved files (artifacts) are,
and how a live verdict gets explained. Read this when you forget how a piece
fits together.

---

## 1. The goal

The LEON sensor (L1–L3) turns network traffic into **flows** and then into an
**11-number fingerprint** per flow. L4's job: answer one question per flow —

> **"Is this flow normal (BENIGN) or an attack (ANOMALY)?"**

L5's job: answer a second question —

> **"Which of the 11 numbers made the model say that?"** (SHAP)

---

## 2. The 11 features (the input to every model)

Defined once in `sensor/feature_spec.py`. The sensor *produces* them
(`sensor/extractor.py`) and the model *consumes* them — same order, always.

| # | Feature | Meaning |
|---|---------|---------|
| 1 | `flow_duration` | flow length in seconds |
| 2 | `protocol` | 6 = TCP, 17 = UDP |
| 3 | `dst_port` | the port being talked to (service under attack) |
| 4 | `total_fwd_packets` | packets from the side that started the flow |
| 5 | `total_bwd_packets` | packets from the reply side |
| 6 | `total_fwd_bytes` | bytes from the initiating side |
| 7 | `total_bwd_bytes` | bytes from the reply side |
| 8 | `packets_per_second` | flow speed (packets ÷ duration) |
| 9 | `syn_count` | TCP "start connection" flags |
| 10 | `ack_count` | TCP "acknowledge" flags |
| 11 | `rst_count` | TCP "reset" flags |

Attackers leave fingerprints here: SYN floods pile up `syn_count`, port scans
produce `rst`, DDoS floods push `packets_per_second` and bytes through the roof.

---

## 3. Training — `model/train_compare.py`

Runs once per training session. Four stages.

### 3a. Load + label (`load_cleaned`, `binary_label`)
- Reads the 8 cleaned CICIDS2017 CSVs from `model/data/cleaned/`.
- Collapses all attack names into one class: **ANOMALY**. So it is a binary
  problem: `BENIGN` vs `ANOMALY`.
- Caps each class at 40,000 rows (`--per-class`) so the 1.96M-row BENIGN class
  doesn't swamp the rare attacks.

### 3b. Build feature matrix (`make_features`)
- Maps teammate CSV column names → our sensor names via `COLUMN_ALIASES`.
- Coerces everything to numbers; turns junk (`inf`) into `NaN` for the imputer.

### 3c. Split (`train_test_split`)
```
100% ── 70% train  (models learn here)
      └─ 30% holdout
            └─ 50% valid  (XGBoost early-stops on this)
            └─ 50% test   (final exam, never seen during training)
```

### 3d. Train three models on the SAME split

| Model | Kind | How it learns |
|-------|------|---------------|
| RandomForest (`rf`) | supervised | 400 decision trees vote; `balanced_subsample` upweights attacks |
| XGBoost (`xgb_model`) | supervised | boosting: each tree fixes the previous one's mistakes; `scale_pos_weight` compensates the rare class; early-stop 20 rounds |
| IsolationForest (`iso`) | unsupervised | trained on **BENIGN only**; measures how "strange" a flow is vs normal traffic |

RandomForest and XGBoost are wrapped in sklearn `Pipeline`s so the exact same
preprocessing (imputer + StandardScaler) runs at train and predict time.

### 3e. Honest evaluation on the test set

- `accuracy` — fraction correct.
- `macro_f1` — average of the two classes' F1 (treats BENIGN and ANOMALY
  equally; the honest headline number).
- `weighted_f1` — same, weighted by class size.
- `benign_false_alert_rate` — % of normal flows falsely alerted.
- `attack_alert_recall` — % of attacks actually caught.

### 3f. Save the artifacts

- `model/models/comparison_report.json` — human-readable summary of 3e.
- `model/models/best_model.joblib` — the winner + the safety net (next section).

---

## 4. The artifacts (`model/models/`)

### `comparison_report.json`
A JSON dump of every metric in section 3e, plus split sizes, seed, and cap.
This is the "report card" of the training run.

### `best_model.joblib`
Python's serialized dictionary (like a save-game). Keys:

| Key | Contents | Who uses it |
|-----|----------|-------------|
| `model` | `"RandomForest"` (the winner) | logging |
| `features` | the 11 feature names | live input construction |
| `classifier` | full Pipeline (imputer+scaler+400 trees) | `FlowClassifier` |
| `metrics` | the winner's scores | reports |
| `anomaly_threshold` | `-0.16208` | live novelty check |
| `anomaly_detector` | trained IsolationForest | live novelty check |
| `anomaly_preprocess` | its imputer+scaler | live novelty check |

One artifact = main detector + novelty safety net in one box.

---

## 5. Live detection — `model/model.py` + `model/run_model.py`

`run_model.py --live` chain:

```
capture (sensor) → FlowTable → extract_features → FlowClassifier.predict(features)
   ├─ 1. build 1-row DataFrame from the 11 features      (_frame)
   ├─ 2. predict_proba → P(BENIGN), P(ANOMALY)
   ├─ 3. label = argmax class; confidence = max proba
   ├─ 4. alert₁ = label==ANOMALY and conf >= 0.50
   ├─ 5. anomaly_score = IsolationForest.decision_function
   ├─ 6. novelty = anomaly_score < anomaly_threshold
   └─ 7. alert = alert₁ OR novelty
```

`FlowClassifier` already handles whichever class order the artifact has
(`['ANOMALY','BENIGN']` here — alphabetical — vs `['BENIGN','ANOMALY']`).

Output for each completed flow:
```
[ok   ] label=BENIGN   conf=0.9911  novelty=no  score=-0.0354
[ALERT] label=BENIGN   conf=0.9957  novelty=YES score=-0.1716
      flow TCP 192.168.1.5:52814 -> 192.168.1.1:443  ...
      note: novelty flag - unusual pattern, NOT a known attack
      why: reply packets=44 → NORMAL (moderate) · dest port=443 → NORMAL (moderate) · protocol=6 → ATTACK-like (weak)
```

Alerts always print the flow summary (5-tuple) and a `note:` when the alert
comes from the novelty net (not a known attack). `--explain` (or any live
alert) adds the SHAP reason in plain words.

### Reading the live output — every number explained

| Field | Meaning | How it's computed |
|-------|---------|-------------------|
| `label` | RandomForest's verdict | the class with the higher `predict_proba` probability |
| `conf` | how sure RF is | the winner's probability (e.g. 0.99 = 99% sure) |
| `score` | "how unusual" | IsolationForest `decision_function()`; **negative = unusual**, near 0 = typical, positive = normal |
| `novelty` | unusual-pattern flag | `score < anomaly_threshold` (−0.16208 in the saved artifact) |
| `ALERT` | final decision | `(label==ANOMALY and conf>=0.50) OR novelty` |
| `flow …` | raw flow counters | 5-tuple, fwd/bwd packets+bytes, SYN/ACK/FIN/RST counts, duration — no ML |
| `note:` | novelty annotation | shown only when `label==BENIGN` but novelty flagged it |
| `why:` | SHAP reason (plain words) | top features by |SHAP value|, each with its value, direction (NORMAL/ATTACK-like), and strength |

In the JSON verdict (`model/model.py`) there's also `benign_probability` — the
other class's probability (1 − conf in the binary case) — and `features`, the
echoed 11 values.

**Confidence caveat:** `conf` is about the *RandomForest's* opinion only. A
novelty alert can fire even when `conf` is 0.99 BENIGN — the two models answer
different questions (see next section).

---

## 6. Explainability — `model/explain.py` (L5)

`FlowExplainer` wraps `shap.TreeExplainer` over the pipeline's RandomForest:

1. Preprocess the flow exactly like training (same pipeline step).
2. `explainer.shap_values(scaled)` → per-feature contribution.
3. Positive contribution = pushes toward ANOMALY; negative = toward BENIGN.
   Values are in log-odds units, so magnitude = strength.
4. `FlowExplainer.readable()` renders the top movers in plain words:
   `reply packets=44 → NORMAL (moderate) · dest port=443 → NORMAL (moderate)`.
   Strength buckets: |v| < 0.05 → weak, < 0.20 → moderate, else strong.
   (`top()` keeps the raw numeric version for scripts/tests.)

**What SHAP does NOT do:** it explains the RandomForest's reasoning, not the
IsolationForest novelty flag. A `label=BENIGN` + `novelty=YES` alert therefore
shows mild, mostly-"NORMAL" reasons — that's expected, and the `note:` line
tells you the alert came from the novelty net, not a known attack.

Correctness notes (bugs we hit):
- The saved RF has classes `['ANOMALY', 'BENIGN']` (alphabetical) — the
  anomaly SHAP array is index **0**, not 1. The explainer derives the index
  from `model.classes_`.
- shap returns each feature as a `[class0, class1]` pair — we take the anomaly
  column (`row[:, anomaly_index]`), not the first feature's pair.

Example on a real attack row:
```
verdict: ANOMALY conf 1.0
key drivers: total_bwd_bytes=+0.286, dst_port=+0.129, protocol=+0.055, total_fwd_bytes=+0.029
```

---

## 7. Real numbers from the current trained model

```
RandomForest    supervised  acc=0.9916  macroF1=0.9899  benignFAR=0.0092  attackRec=0.9937
XGBoost         supervised  acc=0.9913  macroF1=0.9896  benignFAR=0.0106  attackRec=0.9959
IsolationForest novelty     acc=0.7014  macroF1=0.4128  benignFAR=0.0106  attackRec=0.0006
```

- **RandomForest** won (best macroF1) → live artifact.
- XGBoost essentially tied (slightly better attack recall).
- IsolationForest looks "bad" as a classifier because that is NOT its job. It
  never sees attacks during training; it flags *unusual* traffic. Its ~1%
  benign-false-alert rate is a deliberate, tunable safety-net budget.

---

## 8. The files

| File | Role |
|------|------|
| `model/train_compare.py` | train + compare + save artifacts |
| `model/model.py` | `FlowClassifier` live adapter |
| `model/explain.py` | `FlowExplainer` SHAP reasons (L5) |
| `model/run_model.py` | CLI: `--features`, `--jsonl`, `--live`, `--explain` |
| `model/test_model.py` | offline tests (incl. SHAP) |
| `model/data/cleaned/` | training CSVs (fetched by `fetch_data.sh`) |
| `model/models/` | `best_model.joblib` + `comparison_report.json` |
| `sensor/feature_spec.py` | the 11-feature contract (single source of truth) |

CLI cheat-sheet:
```bash
./test_model.sh                                    # offline tests
./train_compare.sh                                 # full retrain (minutes)
sudo ./run_model.sh -i wlan0 -d 30 --explain       # live + SHAP reasons
.venv/bin/python -m model.explain --features '{"flow_duration":0.1,...}'
```
