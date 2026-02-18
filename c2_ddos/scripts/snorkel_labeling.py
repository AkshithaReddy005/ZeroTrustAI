#!/usr/bin/env python3
"""
Phase 1: Snorkel Weak Supervision Labeling Functions
5 conflict-aware LFs for probabilistic ground truth generation.
"""

import numpy as np
import pandas as pd
import joblib
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Label constants
MALICIOUS = 1
BENIGN = 0
ABSTAIN = -1

# ─────────────────────────────────────────────
# LABELING FUNCTIONS
# ─────────────────────────────────────────────

def LF_C2(row):
    """
    Beaconing detection: IAT variance < 0.01 → clockwork timing = C2.
    Confidence: 0.90  |  MITRE: T1071
    """
    iat_cols = [c for c in row.index if c.startswith('splt_iat_')]
    if not iat_cols:
        return ABSTAIN
    iats = row[iat_cols].values.astype(float)
    iats = iats[iats > 0]
    if len(iats) < 3:
        return ABSTAIN
    variance = np.var(iats)
    return MALICIOUS if variance < 0.01 else ABSTAIN


def LF_DDoS(row):
    """
    Volumetric flood: packets_per_sec > 5000 → DDoS.
    Confidence: 0.95  |  MITRE: T1498
    """
    duration = float(row.get('duration', 0))
    total_packets = float(row.get('total_packets', 0))
    pps = total_packets / (duration + 1e-6)
    return MALICIOUS if pps > 5000 else ABSTAIN


def LF_Recon(row):
    """
    Port scanning: unique_dst_ports > 50 in 10s → reconnaissance.
    Confidence: 0.70  |  MITRE: T1046
    Uses dst_port_entropy as proxy when raw port list unavailable.
    """
    dst_port_entropy = float(row.get('dst_port_entropy', 0))
    duration = float(row.get('duration', 1))
    # High entropy on dst ports within short window = port sweep
    if dst_port_entropy > 3.5 and duration <= 10:
        return MALICIOUS
    return ABSTAIN


def LF_Exfil(row):
    """
    Data exfiltration: upload/download > 10 AND duration > 30s.
    Confidence: 0.65  |  MITRE: T1041
    """
    upload = float(row.get('upload_bytes', 0))
    download = float(row.get('download_bytes', 1))
    duration = float(row.get('duration', 0))
    ratio = upload / (download + 1e-6)
    if ratio > 10 and duration > 30:
        return MALICIOUS
    return ABSTAIN


def LF_Calibration(row):
    """
    Conflict-aware calibration: flow_duration > 60s.
    Fires on BOTH benign (long HTTP sessions) and C2 (long beaconing).
    Forces LabelModel to compute real accuracy weights — NOT a signal LF.
    Returns BENIGN for calibration to create conflict.
    """
    duration = float(row.get('duration', 0))
    return BENIGN if duration > 60 else ABSTAIN


# ─────────────────────────────────────────────
# LABEL MATRIX BUILDER
# ─────────────────────────────────────────────

ALL_LFS = [LF_C2, LF_DDoS, LF_Recon, LF_Exfil, LF_Calibration]
LF_NAMES = ['LF_C2', 'LF_DDoS', 'LF_Recon', 'LF_Exfil', 'LF_Calibration']
LF_CONFIDENCES = [0.90, 0.95, 0.70, 0.65, 0.55]


def build_label_matrix(df: pd.DataFrame) -> np.ndarray:
    """
    Apply all LFs to every row → returns L matrix of shape (N, num_LFs).
    Values: MALICIOUS=1, BENIGN=0, ABSTAIN=-1
    """
    logger.info(f"Building label matrix for {len(df):,} samples...")
    L = np.full((len(df), len(ALL_LFS)), ABSTAIN, dtype=int)
    for j, lf in enumerate(ALL_LFS):
        L[:, j] = df.apply(lf, axis=1).values
        coverage = np.mean(L[:, j] != ABSTAIN) * 100
        malicious_rate = np.mean(L[:, j] == MALICIOUS) * 100
        logger.info(f"  {LF_NAMES[j]}: coverage={coverage:.1f}%, malicious={malicious_rate:.1f}%")
    return L


# ─────────────────────────────────────────────
# LABEL MODEL (Majority Vote with Confidence Weights)
# ─────────────────────────────────────────────

def fit_label_model(L: np.ndarray, confidences: list = None) -> np.ndarray:
    """
    Weighted majority vote label model.
    Returns probabilistic soft labels in [0, 1] for each sample.
    Replace with snorkel.labeling.LabelModel for full Snorkel integration.
    """
    if confidences is None:
        confidences = LF_CONFIDENCES

    weights = np.array(confidences)
    N = L.shape[0]
    soft_labels = np.zeros(N)

    for i in range(N):
        votes = L[i]
        weighted_malicious = 0.0
        weighted_total = 0.0
        for j, vote in enumerate(votes):
            if vote != ABSTAIN:
                weighted_total += weights[j]
                if vote == MALICIOUS:
                    weighted_malicious += weights[j]
        if weighted_total > 0:
            soft_labels[i] = weighted_malicious / weighted_total
        else:
            soft_labels[i] = 0.5  # No LF fired → uncertain

    return soft_labels


# ─────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────

def run_snorkel_pipeline(data_path: str, output_path: str = None) -> pd.DataFrame:
    """
    Full Phase 1 Snorkel pipeline:
    1. Load dataset
    2. Build label matrix
    3. Fit label model → soft labels
    4. Save labeled dataset
    """
    logger.info("=" * 60)
    logger.info("PHASE 1: Snorkel Weak Supervision Pipeline")
    logger.info("=" * 60)

    df = pd.read_csv(data_path)
    logger.info(f"Loaded {len(df):,} samples from {data_path}")

    # Derive upload/download bytes from SPLT if not present
    if 'upload_bytes' not in df.columns:
        splt_len_cols = [c for c in df.columns if c.startswith('splt_len_')]
        if splt_len_cols:
            # Odd-indexed packets = upload, even = download (heuristic)
            upload_cols = [c for i, c in enumerate(splt_len_cols) if i % 2 == 0]
            download_cols = [c for i, c in enumerate(splt_len_cols) if i % 2 != 0]
            df['upload_bytes'] = df[upload_cols].sum(axis=1)
            df['download_bytes'] = df[download_cols].sum(axis=1)
            logger.info("Derived upload_bytes and download_bytes from SPLT features")

    # Derive dst_port_entropy proxy if not present
    if 'dst_port_entropy' not in df.columns:
        # Use IAT std as proxy for scanning behavior
        iat_cols = [c for c in df.columns if c.startswith('splt_iat_')]
        if iat_cols:
            df['dst_port_entropy'] = df[iat_cols].std(axis=1)

    # Build label matrix
    L = build_label_matrix(df)

    # Fit label model → soft labels
    soft_labels = fit_label_model(L)
    df['snorkel_prob'] = soft_labels
    df['snorkel_label'] = (soft_labels >= 0.5).astype(int)

    # Coverage and conflict stats
    coverage = np.mean(np.any(L != ABSTAIN, axis=1)) * 100
    conflicts = np.mean(
        np.any(L == MALICIOUS, axis=1) & np.any(L == BENIGN, axis=1)
    ) * 100
    logger.info(f"\nLabel Model Summary:")
    logger.info(f"  Total coverage:  {coverage:.1f}%")
    logger.info(f"  Conflict rate:   {conflicts:.1f}%")
    logger.info(f"  Malicious (>=0.5): {df['snorkel_label'].sum():,} ({df['snorkel_label'].mean()*100:.1f}%)")
    logger.info(f"  Benign (<0.5):     {(df['snorkel_label']==0).sum():,} ({(df['snorkel_label']==0).mean()*100:.1f}%)")

    # Save
    if output_path is None:
        output_path = str(Path(data_path).parent / "snorkel_labeled.csv")
    df.to_csv(output_path, index=False)
    logger.info(f"\n✅ Snorkel-labeled dataset saved → {output_path}")

    # Save label matrix
    lm_path = str(Path(output_path).parent / "label_matrix.npy")
    np.save(lm_path, L)
    logger.info(f"✅ Label matrix saved → {lm_path}")

    return df


if __name__ == "__main__":
    DATA_PATH = "../../data/processed/final_balanced_240k.csv"
    run_snorkel_pipeline(DATA_PATH)
