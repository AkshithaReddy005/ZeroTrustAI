#!/usr/bin/env python3
"""Train a lightweight stacking meta-learner to fuse (TCN, AE, IF) into final risk.

- Input: data/processed/splt_features_labeled.csv (must contain 'label' as 0/1)
- Output: c2_ddos/scripts/models/meta_fuser.joblib

This is intentionally minimal and fast: it only learns how to combine the
already-existing base-model scores.
"""

import os
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score


REPO_ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = REPO_ROOT / "data" / "processed" / "splt_features_labeled.csv"
MODEL_DIR = REPO_ROOT / "c2_ddos" / "scripts" / "models"
OUT_PATH = MODEL_DIR / "meta_fuser.joblib"


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


def _score_base_models(df: pd.DataFrame, m: dict, max_rows: int | None = 10000) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    if max_rows is not None and len(df) > max_rows:
        df = df.sample(n=int(max_rows), random_state=42).reset_index(drop=True)

    tcn_scores = np.zeros(len(df), dtype=np.float32)
    ae_scores = np.zeros(len(df), dtype=np.float32)
    iso_scores = np.zeros(len(df), dtype=np.float32)

    from train_isolation_forest import get_volumetric_matrix, _derive_missing_volumetric_features

    # Optional: skip IF scoring (weight=0.0) to speed up training; set env var META_FUSER_SKIP_IF=1
    skip_if = os.getenv("META_FUSER_SKIP_IF", "0") == "1"

    print(f"Scoring {len(df)} rows with TCN/AE{' (+IF)' if not skip_if else ''}...")
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
        if not skip_if and m.get("iso"):
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


def main():
    if not CSV_PATH.exists():
        raise FileNotFoundError(CSV_PATH)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(CSV_PATH, low_memory=False)
    if "label" not in df.columns:
        raise ValueError("splt_features_labeled.csv must contain a 'label' column")

    y = df["label"].fillna(0).astype(int).to_numpy()

    print(f"Loaded {len(df):,} rows | malicious={int(y.sum()):,} ({(y.mean()*100):.2f}%)")

    print("Loading base models...")
    m = _load_models()

    # Score base models on a subset (fast)
    max_rows = int(os.getenv("META_FUSER_MAX_ROWS", "50000"))
    print(f"Scoring base models (max_rows={max_rows})...")
    tcn_s, ae_s, iso_s = _score_base_models(df, m, max_rows=max_rows)

    # Align labels if we sampled
    if len(tcn_s) != len(y):
        # We sampled inside _score_base_models, so reproduce same sampling here
        df_s = df.sample(n=len(tcn_s), random_state=42).reset_index(drop=True)
        y = df_s["label"].fillna(0).astype(int).to_numpy()

    X_meta = np.stack([tcn_s, ae_s, iso_s], axis=1)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_meta,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.sum() > 10 else None,
    )

    clf = LogisticRegression(
        solver="liblinear",
        class_weight="balanced",
        max_iter=200,
        random_state=42,
    )
    clf.fit(X_tr, y_tr)

    p = clf.predict_proba(X_te)[:, 1]
    yhat = (p >= 0.5).astype(int)

    try:
        auc = roc_auc_score(y_te, p)
    except Exception:
        auc = float("nan")

    print("\nMeta-fuser evaluation (holdout):")
    print(f"AUC: {auc:.4f}")
    print(classification_report(y_te, yhat, target_names=["Benign", "Malicious"], zero_division=0))

    artifact = {
        "model": clf,
        "features": ["tcn", "ae", "iso"],
        "threshold": 0.5,
    }
    joblib.dump(artifact, OUT_PATH)
    print(f"\nSaved meta-fuser -> {OUT_PATH}")


if __name__ == "__main__":
    main()
