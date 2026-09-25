""""Train practical tabular Cyber Guard models.

Usage:
    python -m ml_training.train_tabular --network
    python -m ml_training.train_tabular --malware
    python -m ml_training.train_tabular --phishing-url

Models:
- CIC-IDS2017 -> XGBoost
- EMBER 2018 -> LightGBM using the official EMBER vectorized features
- Phishing URL -> LightGBM over lexical URL features

Large model files are written to trained_models/ and are ignored by Git.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets"
MODELS = ROOT / "trained_models"
RESULTS = ROOT / "training_results"


def save_result(name: str, payload: dict) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{name}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def train_network() -> None:
    try:
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise SystemExit("Install xgboost first: python -m pip install xgboost") from exc

    folder = DATA / "network" / "cic_ids2017"
    files = sorted(folder.glob("*.csv"))
    if not files:
        raise SystemExit("No CIC-IDS2017 CSV files found in datasets/network/cic_ids2017")

    frames = []
    for file in files:
        try:
            df = pd.read_csv(file, low_memory=False)
            df.columns = [str(c).strip() for c in df.columns]
            frames.append(df)
        except Exception as exc:
            print(f"[skip] {file.name}: {exc}")

    df = pd.concat(frames, ignore_index=True)
    label_col = next((c for c in df.columns if c.lower() == "label"), None)
    if not label_col:
        raise SystemExit("CIC-IDS2017 label column not found")

    y_raw = df[label_col].astype(str).str.strip()
    X = df.drop(columns=[label_col]).replace([np.inf, -np.inf], np.nan)
    X = X.select_dtypes(include=[np.number]).fillna(0)

    le = LabelEncoder()
    y = le.fit_transform(y_raw)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softprob",
        eval_metric="mlogloss",
        tree_method="hist",
        n_jobs=4,
    )
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    report = classification_report(
        y_test, pred, target_names=le.classes_, output_dict=True, zero_division=0
    )

    MODELS.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": model, "label_encoder": le, "columns": list(X.columns)},
        MODELS / "network_xgboost.joblib",
    )
    save_result(
        "network_xgboost",
        {"classes": list(le.classes_), "classification_report": report},
    )
    print("[done] network_xgboost.joblib")


def train_malware() -> None:
    try:
        import ember
    except ImportError as exc:
        raise SystemExit(
            "Install EMBER first: python -m pip install git+https://github.com/elastic/ember.git"
        ) from exc

    try:
        import lightgbm as lgb
    except ImportError as exc:
        raise SystemExit("Install lightgbm first: python -m pip install lightgbm") from exc

    candidates = [
        DATA / "malware" / "ember" / "ember2018",
        DATA / "malware" / "ember",
    ]
    dataset = next((p for p in candidates if p.exists()), None)
    if dataset is None:
        raise SystemExit("EMBER dataset folder not found")

    vector_files = [
        dataset / "X_train.dat",
        dataset / "y_train.dat",
        dataset / "X_test.dat",
        dataset / "y_test.dat",
    ]
    if all(path.exists() for path in vector_files):
        print("[ember] using existing vectorized features")
    else:
        print(f"[ember] vectorized features not found; preparing them in {dataset}")
        ember.create_vectorized_features(str(dataset))

    X_train, y_train, X_test, y_test = ember.read_vectorized_features(str(dataset))

    # EMBER uses -1 for unlabeled training samples. They must not be passed
    # to a binary classifier. The test split is already fully labeled.
    train_mask = np.isin(y_train, [0, 1])
    test_mask = np.isin(y_test, [0, 1])
    X_train = X_train[train_mask]
    y_train = y_train[train_mask].astype(np.int32)
    X_test = X_test[test_mask]
    y_test = y_test[test_mask].astype(np.int32)

    print(f"[ember] labeled training samples: {len(y_train):,}")
    print(f"[ember] labeled test samples: {len(y_test):,}")

    model = lgb.LGBMClassifier(
        n_estimators=1000,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=-1,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary",
        n_jobs=4,
    )
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    MODELS.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(MODELS / "ember_lightgbm.txt"))
    save_result(
        "ember_lightgbm",
        {
            "roc_auc": float(roc_auc_score(y_test, proba)),
            "train_samples": int(len(y_train)),
            "test_samples": int(len(y_test)),
            "classification_report": classification_report(
                y_test, pred, output_dict=True, zero_division=0
            ),
        },
    )
    print("[done] ember_lightgbm.txt")


def url_features(urls: pd.Series) -> pd.DataFrame:
    def one(url: str) -> list[float]:
        u = str(url)
        low = u.lower()
        host = re.sub(r"^https?://", "", low).split("/")[0]
        return [
            len(u),
            len(host),
            u.count("."),
            u.count("-"),
            u.count("@"),
            u.count("?"),
            u.count("="),
            u.count("&"),
            u.count("/"),
            sum(ch.isdigit() for ch in u),
            int("https" in low),
            int("@" in u),
            int(bool(re.search(r"\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b", host))),
            int(any(k in low for k in ["login", "verify", "secure", "account", "update", "bank"])),
        ]

    return pd.DataFrame([one(u) for u in urls])


def train_phishing_url() -> None:
    try:
        import lightgbm as lgb
    except ImportError as exc:
        raise SystemExit("Install lightgbm first: python -m pip install lightgbm") from exc

    folder = DATA / "phishing" / "urls"
    csvs = sorted(folder.glob("*.csv"))
    if not csvs:
        raise SystemExit("Put a labelled phishing/benign URL CSV in datasets/phishing/urls")

    frames = [pd.read_csv(p) for p in csvs]
    df = pd.concat(frames, ignore_index=True)

    url_col = next((c for c in df.columns if str(c).lower() in {"url", "urls"}), None)
    label_col = next(
        (c for c in df.columns if str(c).lower() in {"label", "class", "target", "status"}), None
    )
    if not url_col or not label_col:
        raise SystemExit("URL CSV needs URL and label/class/target/status columns")

    y_raw = df[label_col].astype(str).str.lower().str.strip()
    y = y_raw.map(
        lambda v: 1 if any(x in v for x in ["phish", "malicious", "bad", "1"]) else 0
    ).astype(int)

    work = pd.DataFrame({"url": df[url_col].fillna("").astype(str), "label": y})
    max_samples = 50_000
    parts = []
    per_class = max_samples // 2
    for label in (0, 1):
        cls = work[work["label"] == label]
        parts.append(cls.sample(n=min(per_class, len(cls)), random_state=42))
    work = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=42)
    print(f"[phishing-url] selected {len(work):,} samples")
    X = url_features(work["url"])
    y = work["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = lgb.LGBMClassifier(
        n_estimators=500,
        learning_rate=0.05,
        num_leaves=31,
        objective="binary",
        n_jobs=4,
    )
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    MODELS.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(MODELS / "phishing_url_lightgbm.txt"))
    save_result(
        "phishing_url_lightgbm",
        {
            "roc_auc": float(roc_auc_score(y_test, proba)),
            "classification_report": classification_report(
                y_test, pred, output_dict=True, zero_division=0
            ),
        },
    )
    print("[done] phishing_url_lightgbm.txt")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--malware", action="store_true")
    parser.add_argument("--phishing-url", action="store_true")
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.error("Select --network, --malware, or --phishing-url")

    if args.network:
        train_network()
    if args.malware:
        train_malware()
    if args.phishing_url:
        train_phishing_url()


if __name__ == "__main__":
    main()
