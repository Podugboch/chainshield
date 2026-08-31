import pandas as pd
import numpy as np
import os
import json

try:
    import kagglehub
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.model_selection import train_test_split
except ImportError:
    print("Dependencies required: pip install pandas scikit-learn kagglehub")
    exit(1)

def train_and_export():
    print("=== Training PhiUSIIL Phishing ML Classifier ===")
    
    # 1. Look for local dataset or download
    dataset_file = "PhiUSIIL_subset.csv"
    if not os.path.exists(dataset_file) and os.path.exists("PhiUSIIL_Phishing_URL_Dataset.csv"):
        print("Creating balanced subset from full dataset...")
        df_full = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")
        df = df_full.sample(n=min(5000, len(df_full)), random_state=42)
        df.to_csv(dataset_file, index=False)
    elif not os.path.exists(dataset_file):
        print("Note: Provide PhiUSIIL_Phishing_URL_Dataset.csv or PhiUSIIL_subset.csv in current directory.")
        return

    print(f"Loading {dataset_file}...")
    df = pd.read_csv(dataset_file)
    
    drop_cols = ["FILENAME", "URL", "Domain", "TLD", "Title", "label"]
    X = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")
    y = df["label"]
    X = X.fillna(0)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print(f"Training Random Forest on {len(X_train)} samples across {X.shape[1]} features...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=12)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n✓ Model Training Complete! Validation Accuracy: {acc * 100:.2f}%")
    print("\nFeature Importances (Top 10):")
    importances = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False)
    print(importances.head(10))

if __name__ == "__main__":
    train_and_export()
