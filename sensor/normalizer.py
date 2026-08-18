import joblib
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

from sensor.feature_spec import FEATURE_NAMES


class FeatureNormalizer:
    def __init__(self) -> None:
        self.scaler = MinMaxScaler()
        self.feature_names = list(FEATURE_NAMES)
        self._fitted = False

    @property
    def fitted(self) -> bool:
        return self._fitted

    def fit(self, rows: list[dict]) -> "FeatureNormalizer":
        df = pd.DataFrame(rows, columns=self.feature_names)
        self.scaler.fit(df)
        self._fitted = True
        return self

    def transform(self, features: dict) -> list[float]:
        df = pd.DataFrame([features], columns=self.feature_names)
        return self.scaler.transform(df)[0].tolist()

    def transform_many(self, rows: list[dict]) -> list[list[float]]:
        df = pd.DataFrame(rows, columns=self.feature_names)
        return self.scaler.transform(df).tolist()

    def save(self, path: str) -> None:
        joblib.dump(self.scaler, path)

    def load(self, path: str) -> "FeatureNormalizer":
        self.scaler = joblib.load(path)
        self._fitted = True
        return self
