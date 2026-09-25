

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


ROOT = Path(__file__).resolve().parents[1]

DATA = ROOT / "datasets" / "phishing" / "emails"
MODELS = ROOT / "trained_models"
RESULTS = ROOT / "training_results"

MAX_SAMPLES = 10_000


def main() -> None:
    # Prefer the prepared 10,000-sample dataset.
    prepared_file = DATA / "phishing_emails_10000.csv"

    if prepared_file.exists():
        files = [prepared_file]
    else:
        files = sorted(DATA.glob("*.csv"))

    if not files:
        raise SystemExit(
            "No email dataset found in datasets/phishing/emails."
        )

    print("[email] loading dataset...")

    df = pd.concat(
        [pd.read_csv(path) for path in files],
        ignore_index=True,
    )

    text_col = next(
        (
            column
            for column in df.columns
            if str(column).lower() in {"text", "body", "content"}
        ),
        None,
    )

    label_col = next(
        (
            column
            for column in df.columns
            if str(column).lower() in {"label", "class", "target"}
        ),
        None,
    )

    if not text_col or not label_col:
        raise SystemExit(
            "Email CSV must contain text/body/content "
            "and label/class/target columns."
        )

    text = df[text_col].fillna("").astype(str)

    labels = (
        df[label_col]
        .astype(str)
        .str.lower()
        .str.strip()
    )

    y = labels.map(
        lambda value: (
            1
            if any(
                word in value
                for word in ["phish", "spam", "malicious", "1"]
            )
            else 0
        )
    )

    work = pd.DataFrame(
        {
            "text": text,
            "label": y,
        }
    )

    # Remove empty emails.
    work = work[work["text"].str.strip() != ""]

    # Create a balanced 10,000-sample dataset.
    per_class = MAX_SAMPLES // 2

    parts = []

    for label in (0, 1):
        class_data = work[work["label"] == label]

        if len(class_data) < per_class:
            raise SystemExit(
                f"Not enough samples for label {label}. "
                f"Required: {per_class}, available: {len(class_data)}"
            )

        parts.append(
            class_data.sample(
                n=per_class,
                random_state=42,
            )
        )

    work = (
        pd.concat(parts, ignore_index=True)
        .sample(frac=1, random_state=42)
        .reset_index(drop=True)
    )

    text = work["text"]
    y = work["label"]

    print(f"[email] selected {len(work):,} samples")
    print("[email] label distribution:")
    print(y.value_counts())

    x_train, x_test, y_train, y_test = train_test_split(
        text,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print(
        f"[email] training samples: {len(x_train):,}"
    )
    print(
        f"[email] testing samples: {len(x_test):,}"
    )

    model = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=200_000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                ),
            ),
        ]
    )

    print("[email] training TF-IDF + Logistic Regression...")

    model.fit(x_train, y_train)

    proba = model.predict_proba(x_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    MODELS.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)

    model_path = MODELS / "phishing_email_tfidf_logreg.joblib"

    result_path = RESULTS / "phishing_email_tfidf_logreg.json"

    joblib.dump(model, model_path)

    results = {
        "samples": len(work),
        "training_samples": len(x_train),
        "testing_samples": len(x_test),
        "phishing_samples": int((y == 1).sum()),
        "legitimate_samples": int((y == 0).sum()),
        "roc_auc": float(
            roc_auc_score(y_test, proba)
        ),
        "classification_report": classification_report(
            y_test,
            pred,
            output_dict=True,
            zero_division=0,
        ),
    }

    result_path.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    print()
    print("[done] phishing_email_tfidf_logreg.joblib")
    print(f"[model] {model_path}")
    print(f"[results] {result_path}")
    print(f"[ROC-AUC] {results['roc_auc']:.4f}")


if __name__ == "__main__":
    main()