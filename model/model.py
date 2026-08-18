from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sensor.feature_spec import FEATURE_NAMES

BENIGN = "BENIGN"
ANOMALY = "ANOMALY"

BASE = Path(__file__).resolve().parent


class FlowClassifier:
    """Live adapter over our trained artifact (model/models/best_model.joblib)."""

    def __init__(self, path: Path | None = None) -> None:
        self.artifact = joblib.load(path or (BASE / "models" / "best_model.joblib"))
        self.features = list(self.artifact["features"])
        self.classifier = self.artifact["classifier"]
        self.anomaly_detector = self.artifact.get("anomaly_detector")
        self.anomaly_preprocess = self.artifact.get("anomaly_preprocess")
        self.anomaly_threshold = self.artifact.get("anomaly_threshold", 0.0)
        self.model_name = self.artifact.get("model", "unknown")
        self.alert_threshold = 0.50
        classes = list(self.classifier.classes_)
        if classes == [0, 1] or classes == [1, 0]:  # XGBoost int-encoded binary
            self.benign_class, self.anomaly_class = (0, 1) if 0 in classes else (1, 0)
            self.benign_index = classes.index(self.benign_class)
            self.anomaly_index = classes.index(self.anomaly_class)
        else:
            if BENIGN not in classes:
                raise ValueError(f"model classes {classes} do not include {BENIGN}")
            if len(classes) != 2 or ANOMALY not in classes:
                raise ValueError(f"model is not binary BENIGN/ANOMALY: {classes}")
            self.benign_class, self.anomaly_class = BENIGN, ANOMALY
            self.benign_index = classes.index(BENIGN)
            self.anomaly_index = 1 - self.benign_index

    def _frame(self, features: dict) -> pd.DataFrame:
        row = {name: float(features.get(name, 0.0)) for name in self.features}
        return pd.DataFrame([row], columns=self.features)

    def predict(self, features: dict) -> dict:
        frame = self._frame(features)
        proba = self.classifier.predict_proba(frame)[0]
        benign_prob = float(proba[self.benign_index])
        index = int(np.argmax(proba))
        predicted = self.classifier.classes_[index]
        label = self.anomaly_class if predicted == self.anomaly_class else self.benign_class
        if label == 1:
            label = ANOMALY
        elif label == 0:
            label = BENIGN
        confidence = float(proba[index])
        result = {
            "benign_probability": benign_prob,
            "label": label,
            "confidence": confidence,
            "alert": bool(label == ANOMALY and confidence >= self.alert_threshold),
            "features": {name: float(features.get(name, 0.0)) for name in self.features},
        }
        if self.anomaly_detector is not None:
            score = float(self.anomaly_detector.decision_function(
                self.anomaly_preprocess.transform(frame))[0])
            result["anomaly_score"] = score
            result["novelty"] = bool(score < self.anomaly_threshold)
            result["alert"] = result["alert"] or result["novelty"]
        return result
