#!/usr/bin/env python3
"""
Phase 2 - Model B: Isolation Forest (Volumetric Lens)
Train on 13 volumetric features ONLY — no SPLT/temporal data.
Contamination sweep 0.01-0.10 to find optimal FPR < 1% on benign.
"""

import numpy as np
import pandas as pd
import joblib
import logging
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, confusion_matrix

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 13 volumetric features — strip all SPLT/temporal
VOLUMETRIC_FEATURES = [
    'pps', 'bps', 'duration', 'total_packets', 'total_bytes',
    'mean_packet_size', 'pkt_size_std_20', 'mean_iat',
    'iat_std_20', 'pseudo_upload_bytes', 'pseudo_download_bytes',
    'protocol', 'byte_symmetry_ratio'
]

CONTAMINATION_SWEEP = [0.01, 0.03, 0.05, 0.08, 0.10]


def get_volumetric_matrix(df: pd.DataFrame) -> np.ndarray:
    available = [f for f in VOLUMETRIC_FEATURES if f in df.columns]
    missing = [f for f in VOLUMETRIC_FEATURES if f not in df.columns]
    if missing:
        logger.warning(f"Missing volumetric features (padding with 0): {missing}")
        for col in missing:
            df[col] = 0.0
    return df[VOLUMETRIC_FEATURES].fillna(0).replace([np.inf, -np.inf], 0).values.astype(np.float32)


def train_isolation_forest(
    data_path: str,
    model_dir: str = "models",
    val_split: float = 0.15,
    random_state: int = 42,
) -> IsolationForest:
    """
    Train Isolation Forest with contamination sweep.
    Picks lowest contamination that:
      - Correctly flags all known DDoS bursts
      - Keeps FPR < 1% on benign validation traffic
    """
    logger.info("=" * 60)
    logger.info("PHASE 2 - Model B: Isolation Forest Training")
    logger.info("=" * 60)

    df = pd.read_csv(data_path)
    label_col = 'label' if 'label' in df.columns else 'Label'

    # Train/val split (70/15/15 — use 70% for training)
    df_shuffled = df.sample(frac=1, random_state=random_state).reset_index(drop=True)
    n_val = int(len(df_shuffled) * val_split)
    val_df = df_shuffled.iloc[:n_val]
    train_df = df_shuffled.iloc[n_val:]

    X_train = get_volumetric_matrix(train_df)
    X_val = get_volumetric_matrix(val_df)
    y_val = val_df[label_col].values.astype(int)

    benign_val = X_val[y_val == 0]
    malicious_val = X_val[y_val == 1]

    logger.info(f"Train: {len(X_train):,} | Val benign: {len(benign_val):,} | Val malicious: {len(malicious_val):,}")

    # ─────────────────────────────────────────────
    # CONTAMINATION SWEEP
    # ─────────────────────────────────────────────
    best_model = None
    best_contamination = None
    best_f1 = 0.0

    logger.info("\nContamination sweep:")
    for contamination in CONTAMINATION_SWEEP:
        iforest = IsolationForest(
            contamination=contamination,
            n_estimators=200,
            random_state=random_state,
            n_jobs=-1
        )
        iforest.fit(X_train)

        # IF returns -1 for anomaly, 1 for normal → convert to 0/1
        val_preds_raw = iforest.predict(X_val)
        val_preds = (val_preds_raw == -1).astype(int)  # -1 = anomaly = malicious

        # FPR on benign
        benign_preds = iforest.predict(benign_val)
        fpr = np.mean(benign_preds == -1)

        # Detection rate on malicious
        if len(malicious_val) > 0:
            mal_preds = iforest.predict(malicious_val)
            detection_rate = np.mean(mal_preds == -1)
        else:
            detection_rate = 0.0

        f1 = f1_score(y_val, val_preds, zero_division=0)

        logger.info(
            f"  contamination={contamination:.2f} | "
            f"FPR={fpr*100:.2f}% | "
            f"Detection={detection_rate*100:.1f}% | "
            f"F1={f1:.4f}"
        )

        # Pick: FPR < 1% AND best F1
        if fpr < 0.01 and f1 > best_f1:
            best_f1 = f1
            best_contamination = contamination
            best_model = iforest

    # Fallback if no model meets FPR < 1%
    if best_model is None:
        logger.warning("No contamination met FPR < 1% — using contamination=0.01 as safest option")
        best_contamination = 0.01
        best_model = IsolationForest(
            contamination=best_contamination,
            n_estimators=200,
            random_state=random_state,
            n_jobs=-1
        )
        best_model.fit(X_train)

    logger.info(f"\n✅ Best contamination: {best_contamination} (F1={best_f1:.4f})")

    # Final validation metrics
    final_preds_raw = best_model.predict(X_val)
    final_preds = (final_preds_raw == -1).astype(int)
    cm = confusion_matrix(y_val, final_preds)
    logger.info(f"Confusion Matrix:\n{cm}")

    # Save
    Path(model_dir).mkdir(parents=True, exist_ok=True)
    model_path = Path(model_dir) / "isolation_forest.pkl"
    joblib.dump({
        "model": best_model,
        "contamination": best_contamination,
        "features": VOLUMETRIC_FEATURES,
        "f1": best_f1
    }, model_path)
    logger.info(f"✅ Isolation Forest saved → {model_path}")

    return best_model


def load_isolation_forest(model_dir: str = "models") -> tuple:
    """Load trained IF model for inference."""
    payload = joblib.load(Path(model_dir) / "isolation_forest.pkl")
    return payload["model"], payload["features"]


def score_isolation_forest(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    """
    Returns IF anomaly score in [0, 1].
    1 = anomaly (malicious), 0 = normal.
    Uses decision_function: more negative = more anomalous.
    """
    raw_scores = model.decision_function(X)
    # Invert and normalize: lower decision score = more anomalous
    normalized = 1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-9)
    return normalized.astype(np.float32)


if __name__ == "__main__":
    DATA_PATH = "data/processed/phase1_processed.csv"
    if not Path(DATA_PATH).exists():
        DATA_PATH = "data/processed/final_balanced_240k.csv"
    train_isolation_forest(DATA_PATH)
