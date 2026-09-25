"""Train a baseline user-behavior anomaly model.

Input:
datasets/behavior/behavior.csv

Numeric columns are treated as normal-behavior features. The model is an
Isolation Forest trained primarily on the user's normal activity.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets" / "behavior"
MODELS = ROOT / "trained_models"


def main() -> None:
    files = sorted(DATA.glob("*.csv"))
    if not files:
        raise SystemExit("Add normal user behavior data as datasets/behavior/behavior.csv")

    df = pd.concat([pd.read_csv(p) for p in files], ignore_index=True)
    X = df.select_dtypes(include="number").replace([float("inf"), float("-inf")], 0).fillna(0)
    if X.empty:
        raise SystemExit("behavior.csv must contain numeric activity features")

    model = IsolationForest(
        n_estimators=300,
        contamination="auto",
        random_state=42,
        n_jobs=4,
    )
    model.fit(X)

    MODELS.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "columns": list(X.columns)}, MODELS / "behavior_isolation_forest.joblib")
    print("[done] behavior_isolation_forest.joblib")


if __name__ == "__main__":
    main()
