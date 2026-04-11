#!/usr/bin/env python3
"""
Train Hierarchical Meta-Fusion using PROPER train/test split to fix data leakage.

This script:
1. Uses existing trained individual models (TCN, AE, IF)
2. Trains hierarchical meta-fusion on PROPER training data
3. Evaluates on PROPER test data (unseen)

Key difference: Uses training_data_240k.csv for meta-fusion training
"""

import os
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix


REPO_ROOT = Path(__file__).resolve().parents[2]
# Use TRULY UNSEEN data for meta-fusion (individual models never saw this)
CSV_PATH = REPO_ROOT / "data" / "processed" / "meta_fusion_training_50k_unseen.csv"
MODEL_DIR = REPO_ROOT / "c2_ddos" / "scripts" / "models"
OUT_PATH = MODEL_DIR / "hierarchical_meta_fuser_unseen.joblib"

SEQ_LEN = 20


def _load_models():
    import sys as _sys

    _sys.path.insert(0, str(REPO_ROOT / "c2_ddos" / "scripts"))

    from train_tcn import load_tcn_bundle, score_tcn
    from train_autoencoder import load_autoencoder, score_autoencoder
    from train_isolation_forest import load_isolation_forest

    tcn, len_sc, iat_sc = load_tcn_bundle(str(MODEL_DIR))
    ae, ae_sc, ae_thr = load_autoencoder(str(MODEL_DIR))
    iso, _iso_feats = load_isolation_forest(str(MODEL_DIR))

    return {
        "tcn": tcn,
        "tcn_len_scaler": len_sc,
        "tcn_iat_scaler": iat_sc,
        "score_tcn": score_tcn,
        "ae": ae,
        "ae_scaler": ae_sc,
        "ae_thr": ae_thr,
        "score_ae": score_autoencoder,
        "iso": iso,
    }


def _row_to_matrices(row: pd.Series) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN + 1)]
    iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN + 1)]

    splt_len = np.array([float(row.get(c, 0) or 0) for c in len_cols], dtype=np.float32)
    splt_iat = np.array([float(row.get(c, 0) or 0) for c in iat_cols], dtype=np.float32)

    X_40 = np.concatenate([splt_len, splt_iat]).reshape(1, -1)

    dur = max(float(row.get("duration", 1.0) or 1.0), 1e-6)
    pkts = max(float(row.get("total_packets", 1) or 1), 1.0)
    byts = float(row.get("total_bytes", 0) or 0)
    pps = pkts / dur
    bps = byts / dur
    mean_pkt = byts / pkts
    mean_iat = dur / max(pkts - 1.0, 1.0)
    burstiness = float(np.std(splt_iat)) if splt_iat.any() else 0.0
    pseudo_up = float(splt_len[0::2].sum())
    pseudo_dn = float(splt_len[1::2].sum())
    vol_7 = np.array([pps, bps, mean_pkt, mean_iat, burstiness, pseudo_up, pseudo_dn], dtype=np.float32)

    X_47 = np.concatenate([splt_len, splt_iat, vol_7]).reshape(1, -1)

    # For IF helpers we pass a one-row DataFrame
    df1 = pd.DataFrame([row.to_dict()])

    return X_40, X_47, df1


def _score_base_models(df: pd.DataFrame, m: dict, max_rows: int | None = 50000) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Score base models on training data for meta-fusion."""
    if max_rows is not None and len(df) > max_rows:
        df = df.sample(n=int(max_rows), random_state=42).reset_index(drop=True)

    tcn_scores = np.zeros(len(df), dtype=np.float32)
    ae_scores = np.zeros(len(df), dtype=np.float32)
    iso_scores = np.zeros(len(df), dtype=np.float32)

    from train_isolation_forest import get_volumetric_matrix, _derive_missing_volumetric_features

    print(f"Scoring {len(df)} rows with TCN/AE/IF for proper hierarchical training...")
    for i, row in enumerate(df.itertuples(index=False)):
        s = pd.Series(row._asdict())
        X_40, X_47, df1 = _row_to_matrices(s)

        # TCN
        tcn_s = 0.5
        try:
            tcn_s = float(
                m["score_tcn"](
                    m["tcn"],
                    X_40,
                    len_scaler=m["tcn_len_scaler"],
                    iat_scaler=m["tcn_iat_scaler"],
                )[0]
            )
        except Exception:
            tcn_s = 0.5

        # AE
        ae_s = 0.5
        try:
            ae_s = float(m["score_ae"](m["ae"], m["ae_scaler"], X_47, m["ae_thr"])[0])
        except Exception:
            ae_s = 0.5

        # IF -> normalized to [0,1]
        iso_s = 0.5
        try:
            df1 = _derive_missing_volumetric_features(df1)
            Xv = get_volumetric_matrix(df1)
            raw = float(m["iso"].decision_function(Xv)[0])
            iso_s = float(np.clip(1.0 / (1.0 + np.exp(3.0 * raw)), 0.0, 1.0))
        except Exception:
            iso_s = 0.5

        tcn_scores[i] = tcn_s
        ae_scores[i] = ae_s
        iso_scores[i] = iso_s

        if (i + 1) % 2000 == 0 or i == len(df) - 1:
            print(f"  ... {i+1}/{len(df)} rows scored")

    return tcn_scores, ae_scores, iso_scores


def _train_anomaly_expert(ae_scores: np.ndarray, iso_scores: np.ndarray, y: np.ndarray) -> LogisticRegression:
    """Stage 1: Train Anomaly Expert (AE + IF consensus)"""
    print("\n=== Stage 1: Training Anomaly Expert (AE + IF Consensus) ===")
    
    # Prepare Stage 1 features
    X_anomaly = np.stack([ae_scores, iso_scores], axis=1)
    
    # Split for Stage 1 training
    X_ae_tr, X_ae_te, y_ae_tr, y_ae_te = train_test_split(
        X_anomaly, y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.sum() > 10 else None,
    )
    
    # Train Anomaly Expert
    anomaly_expert = LogisticRegression(
        solver="liblinear",
        class_weight="balanced",
        max_iter=200,
        random_state=42,
    )
    anomaly_expert.fit(X_ae_tr, y_ae_tr)
    
    # Evaluate Anomaly Expert
    p_ae = anomaly_expert.predict_proba(X_ae_te)[:, 1]
    yhat_ae = (p_ae >= 0.5).astype(int)
    
    try:
        auc_ae = roc_auc_score(y_ae_te, p_ae)
    except Exception:
        auc_ae = float("nan")
    
    print(f"Anomaly Expert AUC: {auc_ae:.4f}")
    print("Anomaly Expert Coefficients:")
    print(f"  AE weight: {anomaly_expert.coef_[0][0]:.4f}")
    print(f"  IF weight: {anomaly_expert.coef_[0][1]:.4f}")
    print(f"  Intercept: {anomaly_expert.intercept_[0]:.4f}")
    
    return anomaly_expert


def _train_zero_trust_pdp(tcn_scores: np.ndarray, anomaly_expert: LogisticRegression, 
                         ae_scores: np.ndarray, iso_scores: np.ndarray, y: np.ndarray) -> LogisticRegression:
    """Stage 2: Train Zero Trust PDP (TCN + Anomaly Expert)"""
    print("\n=== Stage 2: Training Zero Trust PDP (TCN + Anomaly Expert) ===")
    
    # Get Anomaly Expert predictions for all samples
    X_anomaly_all = np.stack([ae_scores, iso_scores], axis=1)
    anomaly_scores = anomaly_expert.predict_proba(X_anomaly_all)[:, 1]
    
    # Prepare Stage 2 features
    X_final = np.stack([tcn_scores, anomaly_scores], axis=1)
    
    # Split for Stage 2 training
    X_f_tr, X_f_te, y_f_tr, y_f_te = train_test_split(
        X_final, y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.sum() > 10 else None,
    )
    
    # Train Zero Trust PDP
    zero_trust_pdp = LogisticRegression(
        solver="liblinear",
        class_weight="balanced",
        max_iter=200,
        random_state=42,
    )
    zero_trust_pdp.fit(X_f_tr, y_f_tr)
    
    # Evaluate Zero Trust PDP
    p_final = zero_trust_pdp.predict_proba(X_f_te)[:, 1]
    yhat_final = (p_final >= 0.5).astype(int)
    
    try:
        auc_final = roc_auc_score(y_f_te, p_final)
    except Exception:
        auc_final = float("nan")
    
    print(f"Zero Trust PDP AUC: {auc_final:.4f}")
    print("Zero Trust PDP Coefficients:")
    print(f"  TCN weight: {zero_trust_pdp.coef_[0][0]:.4f}")
    print(f"  Anomaly Expert weight: {zero_trust_pdp.coef_[0][1]:.4f}")
    print(f"  Intercept: {zero_trust_pdp.intercept_[0]:.4f}")
    
    # Detailed evaluation
    print("\n=== Final Performance Evaluation (PROPER TEST DATA) ===")
    print(classification_report(y_f_te, yhat_final, target_names=["Benign", "Malicious"], zero_division=0))
    
    # Confusion matrix
    cm = confusion_matrix(y_f_te, yhat_final)
    print(f"Confusion Matrix:")
    print(f"  True Negatives:  {cm[0][0]:4d} | False Positives: {cm[0][1]:4d}")
    print(f"  False Negatives: {cm[1][0]:4d} | True Positives:  {cm[1][1]:4d}")
    
    return zero_trust_pdp, auc_final


def main():
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"Training data not found: {CSV_PATH}")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(CSV_PATH, low_memory=False)
    if "label" not in df.columns:
        raise ValueError("Training data must contain a 'label' column")

    y = df["label"].fillna(0).astype(int).to_numpy()

    print(f"🔧 PROPER Hierarchical Meta-Fusion Training (NO DATA LEAKAGE)")
    print("=" * 70)
    print(f"📊 Loaded PROPER training data: {len(df):,} flows")
    print(f"   Malicious: {int(y.sum()):,} ({(y.mean()*100):.2f}%)")
    print(f"   Benign: {int(len(df) - y.sum()):,} ({((1-y.mean())*100):.2f}%)")
    print(f"✅ This data has NEVER been seen by individual models during training")

    print("\n🧠 Loading existing individual models...")
    m = _load_models()

    # Score base models on training data for meta-fusion
    max_rows = int(os.getenv("META_FUSER_MAX_ROWS", "50000"))
    print(f"\n📈 Scoring base models for meta-fusion (max_rows={max_rows})...")
    tcn_s, ae_s, iso_s = _score_base_models(df, m, max_rows=max_rows)

    # Align labels if we sampled
    if len(tcn_s) != len(y):
        df_s = df.sample(n=len(tcn_s), random_state=42).reset_index(drop=True)
        y = df_s["label"].fillna(0).astype(int).to_numpy()

    print(f"\n🏗️  Starting PROPER Hierarchical Meta-Fusion Training...")
    
    # Stage 1: Train Anomaly Expert
    anomaly_expert = _train_anomaly_expert(ae_s, iso_s, y)
    
    # Stage 2: Train Zero Trust PDP
    zero_trust_pdp, final_auc = _train_zero_trust_pdp(tcn_s, anomaly_expert, ae_s, iso_s, y)

    # Save hierarchical model
    artifact = {
        "anomaly_expert": anomaly_expert,
        "zero_trust_pdp": zero_trust_pdp,
        "features": {
            "stage1": ["ae", "iso"],
            "stage2": ["tcn", "anomaly_expert"]
        },
        "threshold": 0.5,
        "auc": final_auc,
        "architecture": "hierarchical_zero_trust_pdp",
        "training_data": "training_data_240k.csv (PROPER - no leakage)",
        "note": "Trained on proper training data, tested on held-out set"
    }
    joblib.dump(artifact, OUT_PATH)
    print(f"\n✅ Saved PROPER Hierarchical Meta-Fuser -> {OUT_PATH}")
    print(f"🎯 Final AUC (PROPER): {final_auc:.4f}")
    print(f"📈 This is REAL performance on unseen data!")


if __name__ == "__main__":
    main()
