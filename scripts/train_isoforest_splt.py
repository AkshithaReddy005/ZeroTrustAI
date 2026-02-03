#!/usr/bin/env python3
"""Train SPLT IsolationForest + scaler from data/processed/splt_features.csv.

Outputs (written to ./models/):
- splt_scaler.joblib
- splt_isoforest.joblib

This is used by the detector for real-time SPLT anomaly scoring.
"""
import pathlib
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

CSV_PATH = pathlib.Path("data/processed/splt_features.csv")
LABELED_CSV_PATH = pathlib.Path("data/processed/splt_features_labeled.csv")
MODEL_DIR = pathlib.Path("models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

OUT_SCALER = MODEL_DIR / "splt_scaler.joblib"
OUT_ISO = MODEL_DIR / "splt_isoforest.joblib"

SEQ_LEN = 20


def main():
    if LABELED_CSV_PATH.exists():
        df = pd.read_csv(LABELED_CSV_PATH)
    else:
        if not CSV_PATH.exists():
            raise FileNotFoundError(CSV_PATH)
        df = pd.read_csv(CSV_PATH)

    len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN + 1)]
    iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN + 1)]

    X_len = df[len_cols].fillna(0.0).to_numpy(dtype=np.float32)
    X_iat = df[iat_cols].fillna(0.0).to_numpy(dtype=np.float32)
    X = np.concatenate([X_len, X_iat], axis=1)  # [N, 40]

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # Train on benign subset
    if "label" in df.columns:
        benign_mask = df["label"].fillna(0).astype(int) == 0
        X_benign = Xs[benign_mask.to_numpy()]
    else:
        duration = df.get("duration", pd.Series([0] * len(df))).astype(float).replace(0, 1e-3)
        pps = df.get("total_packets", pd.Series([0] * len(df))).astype(float) / duration
        entropy = df.get("avg_entropy", pd.Series([0] * len(df))).astype(float)
        benign_mask = (entropy < 5.5) & (pps < 150)
        X_benign = Xs[benign_mask.to_numpy()]
    if X_benign.shape[0] < 50:
        X_benign = Xs

    iso = IsolationForest(n_estimators=300, contamination=0.05, random_state=42)
    iso.fit(X_benign)

    joblib.dump(scaler, OUT_SCALER)
    joblib.dump(iso, OUT_ISO)
    print(f"Saved {OUT_SCALER} and {OUT_ISO}. Trained on {X_benign.shape[0]} benign-proxy samples (of {len(df)} total).")


if __name__ == "__main__":
    main()
