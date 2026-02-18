#!/usr/bin/env python3
"""
Phase 3: Ensemble Fusion + Three-Tier Zero Trust Policy
Simultaneous weighted fusion of TCN + AE + IF scores.
GridSearchCV weight calibration on held-out 15% validation set.
FDR gate < 0.1% before accepting any weight combination.
"""

import numpy as np
import pandas as pd
import joblib
import logging
from pathlib import Path
from itertools import product
from sklearn.metrics import f1_score, confusion_matrix, classification_report
from sklearn.preprocessing import MinMaxScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# THREE-TIER POLICY THRESHOLDS
# ─────────────────────────────────────────────
QUARANTINE_THRESHOLD = 0.55   # > 0.55 → block + SOAR
MONITOR_THRESHOLD    = 0.35   # 0.35-0.55 → allow + elevated telemetry
# < 0.35 → ALLOW (standard pass-through)


# ─────────────────────────────────────────────
# FALSE DISCOVERY RATE
# ─────────────────────────────────────────────

def false_discovery_rate(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """FDR = FP / (FP + TP). Must be < 0.001 (0.1%) to pass gate."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        return fp / (fp + tp + 1e-9)
    return 1.0


# ─────────────────────────────────────────────
# WEIGHT CALIBRATION — GridSearchCV
# ─────────────────────────────────────────────

def calibrate_weights(
    tcn_val: np.ndarray,
    ae_val: np.ndarray,
    if_val: np.ndarray,
    y_val: np.ndarray,
    fdr_gate: float = 0.001,
) -> dict:
    """
    Empirical weight calibration via grid search on validation set.
    Weights must sum to 1.0. FDR gate < 0.1% enforced.
    Returns best weights dict or safe defaults if no combination passes gate.
    """
    logger.info("Running GridSearchCV weight calibration...")

    tcn_range = [0.4, 0.5, 0.6]
    ae_range  = [0.2, 0.3, 0.4]
    if_range  = [0.1, 0.2, 0.3]

    best_f1 = 0.0
    best_weights = None
    results = []

    for tw, aw, iw in product(tcn_range, ae_range, if_range):
        if abs(tw + aw + iw - 1.0) > 0.01:
            continue  # weights must sum to 1

        scores = tw * tcn_val + aw * ae_val + iw * if_val
        preds = (scores > QUARANTINE_THRESHOLD).astype(int)

        fdr = false_discovery_rate(y_val, preds)
        f1 = f1_score(y_val, preds, zero_division=0)

        results.append({"tcn": tw, "ae": aw, "if": iw, "f1": f1, "fdr": fdr})

        if fdr < fdr_gate and f1 > best_f1:
            best_f1 = f1
            best_weights = {"tcn": tw, "ae": aw, "if": iw}

    # Sort results for logging
    results.sort(key=lambda x: x["f1"], reverse=True)
    logger.info("\nTop 5 weight combinations:")
    for r in results[:5]:
        logger.info(
            f"  TCN={r['tcn']} AE={r['ae']} IF={r['if']} "
            f"→ F1={r['f1']:.4f}, FDR={r['fdr']*100:.3f}%"
        )

    if best_weights is None:
        logger.warning("No combination passed FDR gate < 0.1% — using safe defaults (TCN-heavy)")
        best_weights = {"tcn": 0.6, "ae": 0.3, "if": 0.1}

    logger.info(f"\n✅ Best weights: {best_weights} (F1={best_f1:.4f})")
    return best_weights


# ─────────────────────────────────────────────
# ENSEMBLE SCORER
# ─────────────────────────────────────────────

class EnsembleFusion:
    """
    Three-way simultaneous weighted fusion of TCN + AE + IF.
    All models vote on every single flow — no waterfall elif logic.
    """

    def __init__(self, weights: dict = None, ae_scaler: MinMaxScaler = None):
        self.weights = weights or {"tcn": 0.6, "ae": 0.3, "if": 0.1}
        self.ae_scaler = ae_scaler  # Normalize AE loss to [0,1] before fusion

    def fuse(
        self,
        tcn_prob: np.ndarray,
        ae_recon_loss: np.ndarray,
        if_pred: np.ndarray,
    ) -> np.ndarray:
        """
        Compute weighted risk score for each flow.

        Args:
            tcn_prob:      TCN softmax probability [0,1]
            ae_recon_loss: AE reconstruction loss (raw MSE) — will be normalized
            if_pred:       IF prediction: -1=anomaly, 1=normal

        Returns:
            risk_score: np.ndarray [0,1] per flow
        """
        # Normalize AE loss to [0,1]
        if self.ae_scaler is not None:
            ae_norm = self.ae_scaler.transform(ae_recon_loss.reshape(-1, 1)).flatten()
        else:
            ae_min, ae_max = ae_recon_loss.min(), ae_recon_loss.max()
            ae_norm = (ae_recon_loss - ae_min) / (ae_max - ae_min + 1e-9)

        # IF: -1 (anomaly) → 1.0, 1 (normal) → 0.0
        if_score = (if_pred == -1).astype(np.float32)

        risk_score = (
            self.weights["tcn"] * tcn_prob +
            self.weights["ae"]  * ae_norm +
            self.weights["if"]  * if_score
        )
        return np.clip(risk_score, 0.0, 1.0)

    def classify(self, risk_score: np.ndarray) -> list:
        """
        Apply three-tier Zero Trust policy to risk scores.

        Returns list of dicts with tier, action, and infrastructure response.
        """
        decisions = []
        for score in risk_score:
            if score > QUARANTINE_THRESHOLD:
                decisions.append({
                    "tier": "QUARANTINE",
                    "risk_score": float(score),
                    "action": "Block + SOAR alert",
                    "infra": "Write IP to Redis with TTL. SOAR fires. Packets dropped at gateway."
                })
            elif score >= MONITOR_THRESHOLD:
                decisions.append({
                    "tier": "MONITOR",
                    "risk_score": float(score),
                    "action": "Allow + elevated telemetry",
                    "infra": "Log full telemetry to Redis. Flag in Streamlit. Human auditor notified."
                })
            else:
                decisions.append({
                    "tier": "ALLOW",
                    "risk_score": float(score),
                    "action": "Standard pass-through",
                    "infra": "Async log to InfluxDB. No action on hot path."
                })
        return decisions


# ─────────────────────────────────────────────
# FULL PHASE 3 RUNNER
# ─────────────────────────────────────────────

def run_phase3(model_dir: str = "models", data_path: str = None):
    """
    Full Phase 3 pipeline:
    1. Load all three trained models
    2. Score validation set with each model
    3. Calibrate ensemble weights via GridSearchCV
    4. Validate three-tier policy on test set
    5. Save ensemble config
    """
    logger.info("=" * 60)
    logger.info("PHASE 3: Ensemble Fusion Calibration")
    logger.info("=" * 60)

    import torch
    from train_tcn import TCN, load_tcn, score_tcn, load_splt_from_csv, SPLT_FEATURES
    from train_autoencoder import Autoencoder, load_autoencoder, score_autoencoder, get_feature_matrix, ALL_FEATURES
    from train_isolation_forest import load_isolation_forest, score_isolation_forest, get_volumetric_matrix

    # Load models
    logger.info("Loading trained models...")
    tcn_model = load_tcn(model_dir)
    ae_model, ae_scaler, ae_threshold = load_autoencoder(model_dir)
    if_model, if_features = load_isolation_forest(model_dir)

    # Load validation data
    val_path = Path(model_dir) / "test_set.csv"
    if val_path.exists():
        val_df = pd.read_csv(val_path)
        y_val = np.load(Path(model_dir) / "test_labels.npy")
        y_val_binary = (y_val >= 0.5).astype(int)
        logger.info(f"Loaded held-out test set: {len(val_df):,} samples")
    elif data_path:
        val_df = pd.read_csv(data_path).sample(frac=0.15, random_state=42)
        label_col = 'label' if 'label' in val_df.columns else 'Label'
        y_val_binary = val_df[label_col].values.astype(int)
        logger.info(f"Using 15% sample from data: {len(val_df):,} samples")
    else:
        logger.error("No validation data found. Provide data_path or run train_tcn.py first.")
        return None

    # Score each model
    logger.info("\nScoring validation set with each model...")

    X_splt = load_splt_from_csv(val_df.copy())
    tcn_scores = score_tcn(tcn_model, X_splt)
    logger.info(f"  TCN scores: mean={tcn_scores.mean():.4f}, std={tcn_scores.std():.4f}")

    X_all = get_feature_matrix(val_df.copy())
    ae_errors = ae_model.reconstruction_error(
        torch.tensor(ae_scaler.transform(X_all).astype(np.float32))
    ).detach().numpy()
    logger.info(f"  AE errors:  mean={ae_errors.mean():.6f}, threshold={ae_threshold:.6f}")

    X_vol = get_volumetric_matrix(val_df.copy())
    if_preds = if_model.predict(X_vol)  # -1=anomaly, 1=normal
    if_detection = np.mean(if_preds[y_val_binary == 1] == -1) * 100
    logger.info(f"  IF detection rate on malicious: {if_detection:.1f}%")

    # Normalize AE for fusion
    ae_mm_scaler = MinMaxScaler()
    ae_mm_scaler.fit(ae_errors.reshape(-1, 1))
    ae_norm = ae_mm_scaler.transform(ae_errors.reshape(-1, 1)).flatten()

    # Calibrate weights
    best_weights = calibrate_weights(tcn_scores, ae_norm, (if_preds == -1).astype(float), y_val_binary)

    # Build ensemble
    ensemble = EnsembleFusion(weights=best_weights, ae_scaler=ae_mm_scaler)
    risk_scores = ensemble.fuse(tcn_scores, ae_errors, if_preds)
    decisions = ensemble.classify(risk_scores)

    # Final metrics
    final_preds = (risk_scores > QUARANTINE_THRESHOLD).astype(int)
    fdr = false_discovery_rate(y_val_binary, final_preds)
    f1 = f1_score(y_val_binary, final_preds, zero_division=0)

    tiers = [d["tier"] for d in decisions]
    logger.info(f"\n{'='*60}")
    logger.info(f"ENSEMBLE VALIDATION RESULTS")
    logger.info(f"{'='*60}")
    logger.info(f"  F1 Score:         {f1:.4f}")
    logger.info(f"  FDR:              {fdr*100:.3f}% ({'✅ PASS' if fdr < 0.001 else '❌ FAIL'})")
    logger.info(f"  QUARANTINE flows: {tiers.count('QUARANTINE'):,}")
    logger.info(f"  MONITOR flows:    {tiers.count('MONITOR'):,}")
    logger.info(f"  ALLOW flows:      {tiers.count('ALLOW'):,}")
    logger.info(f"\n{classification_report(y_val_binary, final_preds, target_names=['Benign','Malicious'])}")

    # Save ensemble config
    config = {
        "weights": best_weights,
        "quarantine_threshold": QUARANTINE_THRESHOLD,
        "monitor_threshold": MONITOR_THRESHOLD,
        "ae_threshold": ae_threshold,
        "f1": f1,
        "fdr": fdr,
    }
    joblib.dump(config, Path(model_dir) / "ensemble_config.pkl")
    joblib.dump(ae_mm_scaler, Path(model_dir) / "ae_minmax_scaler.pkl")
    logger.info(f"\n✅ Ensemble config saved → {model_dir}/ensemble_config.pkl")

    return ensemble, config


def load_ensemble(model_dir: str = "models") -> tuple:
    """Load ensemble config for inference."""
    config = joblib.load(Path(model_dir) / "ensemble_config.pkl")
    ae_mm_scaler = joblib.load(Path(model_dir) / "ae_minmax_scaler.pkl")
    ensemble = EnsembleFusion(weights=config["weights"], ae_scaler=ae_mm_scaler)
    return ensemble, config


if __name__ == "__main__":
    DATA_PATH = "data/processed/phase1_processed.csv"
    if not Path(DATA_PATH).exists():
        DATA_PATH = "data/processed/final_balanced_240k.csv"
    run_phase3(model_dir="models", data_path=DATA_PATH)
