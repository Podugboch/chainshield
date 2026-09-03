"""Research-only baseline on the PhiUSIIL phishing URL dataset.

WHAT THIS IS NOT
----------------
Nothing in the ChainShield app loads a model. The URL and message scanners are
the rule-based detectors in src/lib/phishingDetector.js and
src/lib/urlHeuristics.js, and every score they produce is traceable to a named
rule. This file used to sit next to a src/lib/mlPhishingClassifier.js that
presented hand-written constants as trained weights; that file has been deleted,
and this script is kept only as an honest baseline you can run yourself.

Do not quote its accuracy figure as a property of ChainShield. The features it
trains on are dataset columns computed offline by the PhiUSIIL authors -- the
browser has no way to compute most of them for a URL a user pastes in, so this
model could not be deployed even if you wanted to.

WHY THE HEADLINE ACCURACY IS DROPPED
------------------------------------
PhiUSIIL ships a URLSimilarityIndex column that is derived with knowledge of the
label, so any model given it scores ~100% and learns nothing. That number is the
single most-quoted figure about this dataset and it is an artefact. The leaky
columns are dropped by default; pass --keep-leaky-features to see the inflated
score for yourself, side by side with the honest one.

USAGE
-----
    pip install pandas scikit-learn
    python scripts/train_phiusiil.py --data PhiUSIIL_Phishing_URL_Dataset.csv

Download the dataset from the UCI ML Repository (id 967) or Kaggle. It is not
committed here.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    from sklearn.model_selection import train_test_split
except ImportError:
    # kagglehub and numpy used to be imported here as well and never called;
    # requiring them meant the script refused to start over dependencies it
    # did not use.
    print("Dependencies required: pip install pandas scikit-learn", file=sys.stderr)
    raise SystemExit(1)

# Identifier / free-text columns, plus the label itself.
NON_FEATURE_COLUMNS = ["FILENAME", "URL", "Domain", "TLD", "Title", "label"]

# Computed by the dataset authors against the labelled set. Keeping these is how
# a Random Forest on PhiUSIIL "achieves" 99.9%.
LEAKY_COLUMNS = ["URLSimilarityIndex"]


def load_dataset(path: str) -> "pd.DataFrame":
    if not os.path.exists(path):
        print(
            f"Dataset not found at {path}.\n"
            "Download PhiUSIIL_Phishing_URL_Dataset.csv (UCI ML Repository id 967) "
            "and pass it with --data.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return pd.read_csv(path)


def train(df, keep_leaky: bool, sample: int | None, seed: int):
    if "label" not in df.columns:
        print("The dataset has no 'label' column -- is this the right file?", file=sys.stderr)
        raise SystemExit(1)

    if sample and sample < len(df):
        df = df.sample(n=sample, random_state=seed)

    dropped_leaky = [] if keep_leaky else [c for c in LEAKY_COLUMNS if c in df.columns]
    drop = [c for c in NON_FEATURE_COLUMNS if c in df.columns] + dropped_leaky

    X = df.drop(columns=drop, errors="ignore").select_dtypes(include="number").fillna(0)
    y = df["label"]

    # Stratified, so a class-imbalanced sample does not quietly produce a test
    # split with almost no phishing rows in it.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=100, max_depth=12, random_state=seed, n_jobs=-1
    )
    clf.fit(X_train, y_train)

    predictions = clf.predict(X_test)
    probabilities = clf.predict_proba(X_test)[:, 1]
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, predictions).ravel()

    return {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "rows_total": int(len(df)),
        "rows_train": int(len(X_train)),
        "rows_test": int(len(X_test)),
        "features_used": list(X.columns),
        "leaky_features_dropped": dropped_leaky,
        "accuracy": report["accuracy"],
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        # False positives are the number that matters for a scanner: each one is
        # a legitimate URL called phishing in front of a user.
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "per_class": {k: v for k, v in report.items() if k not in ("accuracy",)},
        "top_features": (
            pd.Series(clf.feature_importances_, index=X.columns)
            .sort_values(ascending=False)
            .head(15)
            .round(5)
            .to_dict()
        ),
    }, clf


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", default="PhiUSIIL_Phishing_URL_Dataset.csv")
    parser.add_argument("--out", default="scripts/phiusiil_baseline.json",
                        help="Where to write the metrics report.")
    parser.add_argument("--model-out", default=None,
                        help="Optional joblib path for the fitted model. Nothing in the app reads it.")
    parser.add_argument("--sample", type=int, default=None,
                        help="Train on a random subset of N rows.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--keep-leaky-features", action="store_true",
                        help=f"Keep {', '.join(LEAKY_COLUMNS)} to reproduce the inflated score.")
    args = parser.parse_args()

    df = load_dataset(args.data)
    metrics, clf = train(df, args.keep_leaky_features, args.sample, args.seed)

    print(f"rows: {metrics['rows_total']}  features: {len(metrics['features_used'])}")
    if metrics["leaky_features_dropped"]:
        print(f"dropped as label-leaking: {', '.join(metrics['leaky_features_dropped'])}")
    else:
        print("WARNING: leaky features kept -- this accuracy is an artefact, not a result.")
    print(f"accuracy: {metrics['accuracy'] * 100:.2f}%   roc_auc: {metrics['roc_auc']:.4f}")
    print(f"false positives: {metrics['false_positives']}   false negatives: {metrics['false_negatives']}")
    print("\ntop features:")
    for name, importance in metrics["top_features"].items():
        print(f"  {importance:.5f}  {name}")

    # The old train_and_export() exported nothing at all -- it printed an
    # accuracy figure and threw the model away, which is how an unverifiable
    # number ends up quoted in a README.
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"\nmetrics written to {args.out}")

    if args.model_out:
        try:
            import joblib
        except ImportError:
            print("joblib not installed; skipping model export.", file=sys.stderr)
            return 0
        joblib.dump(clf, args.model_out)
        print(f"model written to {args.model_out} (not loaded by the app)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
