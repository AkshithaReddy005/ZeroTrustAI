#!/usr/bin/env python3
"""Train hierarchical meta-fusion using GAN lens (AE + GAN) -> Anomaly Expert -> (TCN + Anomaly Expert) -> Final.

This script reads the GAN fusion CSV and trains a two-stage logistic regression hierarchy:
- Stage 1: Anomaly Expert (AE + GAN)
- Stage 2: Zero Trust PDP (TCN + Anomaly Expert)

Outputs:
- c2_ddos/scripts/models/hierarchical_meta_fuser_gan.joblib
"""

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, classification_report

REPO_ROOT = Path(__file__).resolve().parent
CSV_PATH = REPO_ROOT / "data" / "processed" / "gan_fusion_training_50k_unseen.csv"
OUT_PATH = REPO_ROOT / "c2_ddos" / "scripts" / "models" / "hierarchical_meta_fuser_gan.joblib"

def main():
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"GAN fusion CSV not found: {CSV_PATH}")

    df = pd.read_csv(CSV_PATH, low_memory=False)
    required = {"tcn_score", "ae_score", "gan_attack", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns in CSV: {missing}")

    y = df["label"].values

    print("=== Stage 1: Training Anomaly Expert (AE + GAN) ===")
    X_stage1 = df[["ae_score", "gan_attack"]].values
    stage1_model = LogisticRegression(
        solver="liblinear",
        class_weight="balanced",
        max_iter=200,
        random_state=42,
    )
    stage1_model.fit(X_stage1, y)
    stage1_probs = stage1_model.predict_proba(X_stage1)[:, 1]
    try:
        auc1 = roc_auc_score(y, stage1_probs)
    except Exception:
        auc1 = float("nan")
    print(f"Stage 1 AUC: {auc1:.4f}")

    print("\n=== Stage 2: Training High-Performance Zero Trust PDP (MLP) ===")
    X_stage2_raw = np.stack([df["tcn_score"].values, stage1_probs], axis=1)
    scaler_stage2 = StandardScaler()
    X_stage2 = scaler_stage2.fit_transform(X_stage2_raw)
    stage2_model = MLPClassifier(
        hidden_layer_sizes=(16, 8),
        activation="relu",
        max_iter=1000,
        random_state=42,
        learning_rate_init=0.001,
    )
    stage2_model.fit(X_stage2, y)
    final_probs = stage2_model.predict_proba(X_stage2)[:, 1]
    try:
        final_auc = roc_auc_score(y, final_probs)
    except Exception:
        final_auc = float("nan")
    print(f"Final Hierarchical AUC: {final_auc:.4f}")

    print("\nFinal Metrics (Training Data):")
    print(classification_report(y, (final_probs > 0.5).astype(int), zero_division=0))

    artifact = {
        "stage1": stage1_model,
        "stage2": stage2_model,
        "stage2_scaler": scaler_stage2,
        "stage1_features": ["ae_score", "gan_attack"],
        "stage2_features": ["tcn_score", "anomaly_expert_score"],
        "auc": final_auc,
        "architecture": "hierarchical_gan_mlp",
        "threshold": 0.40,  # Optimized threshold for higher recall/accuracy
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, OUT_PATH)
    print(f"\n✅ SUCCESS: Saved to {OUT_PATH}")

if __name__ == "__main__":
    main()
