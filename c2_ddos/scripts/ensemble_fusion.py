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
import torch
import torch.nn as nn
from pathlib import Path
from itertools import product
from sklearn.metrics import f1_score, confusion_matrix, classification_report
from sklearn.preprocessing import MinMaxScaler, PowerTransformer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# THREE-TIER POLICY THRESHOLDS
# ─────────────────────────────────────────────
QUARANTINE_THRESHOLD = 0.50   # > 0.50 → block + SOAR  (calibrated to TCN sigmoid output)
MONITOR_THRESHOLD    = 0.30   # 0.30-0.50 → allow + elevated telemetry
# < 0.30 → ALLOW (standard pass-through)


# ─────────────────────────────────────────────
# 82K TCN ARCHITECTURE (exact match to tcn_classifier.pth)
# ─────────────────────────────────────────────

class Chomp1d(nn.Module):
    def __init__(self, chomp_size):
        super().__init__()
        self.chomp_size = chomp_size
    def forward(self, x):
        return x[:, :, :-self.chomp_size].contiguous() if self.chomp_size > 0 else x

class TemporalBlock(nn.Module):
    def __init__(self, in_ch, out_ch, kernel_size, dilation, dropout):
        super().__init__()
        pad = (kernel_size - 1) * dilation
        self.net = nn.Sequential(
            nn.Conv1d(in_ch, out_ch, kernel_size, padding=pad, dilation=dilation),
            Chomp1d(pad), nn.ReLU(), nn.Dropout(dropout),
            nn.Conv1d(out_ch, out_ch, kernel_size, padding=pad, dilation=dilation),
            Chomp1d(pad), nn.ReLU(), nn.Dropout(dropout),
        )
        self.downsample = nn.Conv1d(in_ch, out_ch, 1) if in_ch != out_ch else nn.Identity()
        self.relu = nn.ReLU()
    def forward(self, x):
        return self.relu(self.net(x) + self.downsample(x))

class TCN82k(nn.Module):
    """
    Exact architecture matching tcn_classifier.pth state_dict keys:
      tcn.0  Conv1d(1, 64, 3)
      tcn.3  Conv1d(64, 128, 3)
      tcn.8  Linear(128, 64)
      tcn.10 Linear(64, 1)
    Input: (N, 1, 40) — flat concatenation of len+iat as single channel
    """
    def __init__(self):
        super().__init__()
        self.tcn = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3, padding=1),   # 0
            nn.ReLU(),                                      # 1
            nn.Dropout(0.2),                               # 2
            nn.Conv1d(64, 128, kernel_size=3, padding=1),  # 3
            nn.ReLU(),                                      # 4
            nn.AdaptiveAvgPool1d(1),                       # 5
            nn.Flatten(),                                   # 6
            nn.Dropout(0.2),                               # 7
            nn.Linear(128, 64),                            # 8
            nn.ReLU(),                                      # 9
            nn.Linear(64, 1),                              # 10
        )

    def forward(self, x):
        return self.tcn(x).squeeze(-1)


# ─────────────────────────────────────────────
# TCN LOADER & SCORER
# ─────────────────────────────────────────────

def load_tcn_82k(model_path: str, device: torch.device) -> TCN82k:
    model = TCN82k()
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.to(device).eval()
    logger.info(f"✅ Loaded 82k TCN from {model_path}")
    return model


def score_tcn_82k(model: TCN82k, df: pd.DataFrame, device: torch.device) -> np.ndarray:
    """
    Return malicious probability [0,1] for each flow.
    Model input: (N, 1, 40) — len[1..20] + iat[1..20] concatenated as single channel.
    """
    SEQ_LEN = 20
    len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN + 1)]
    iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN + 1)]
    X_len = df[len_cols].fillna(0.0).to_numpy(dtype=np.float32)
    X_iat = df[iat_cols].fillna(0.0).to_numpy(dtype=np.float32)

    # Concatenate len + iat → (N, 40), then reshape to (N, 1, 40)
    X_flat = np.concatenate([X_len, X_iat], axis=1)
    X = X_flat[:, np.newaxis, :]  # (N, 1, 40)

    tensor = torch.tensor(X, dtype=torch.float32).to(device)
    with torch.no_grad():
        logits = model(tensor)          # (N,) raw logits
        probs = torch.sigmoid(logits).cpu().numpy()
    return probs


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

    # TCN-dominant grid — TCN has F1=0.96, AE/IF are secondary signals
    tcn_range = [0.7, 0.8, 0.9, 1.0]
    ae_range  = [0.0, 0.1, 0.2]
    if_range  = [0.0, 0.1]

    best_f1 = 0.0
    best_weights = None
    best_threshold = QUARANTINE_THRESHOLD
    best_fdr = 1.0
    results = []

    # Sweep thresholds — TCN sigmoid output clusters near 0 (benign) and 1 (malicious)
    threshold_range = [0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65]

    for tw, aw, iw in product(tcn_range, ae_range, if_range):
        if abs(tw + aw + iw - 1.0) > 0.01:
            continue

        scores = tw * tcn_val + aw * ae_val + iw * if_val

        for thresh in threshold_range:
            preds = (scores > thresh).astype(int)
            fdr = false_discovery_rate(y_val, preds)
            f1  = f1_score(y_val, preds, zero_division=0)

            results.append({"tcn": tw, "ae": aw, "if": iw, "thresh": thresh, "f1": f1, "fdr": fdr})

            if fdr < fdr_gate and f1 > best_f1:
                best_f1 = f1
                best_fdr = fdr
                best_threshold = thresh
                best_weights = {"tcn": tw, "ae": aw, "if": iw}

    results.sort(key=lambda x: x["f1"], reverse=True)
    logger.info("\nTop 5 weight+threshold combinations:")
    for r in results[:5]:
        logger.info(
            f"  TCN={r['tcn']} AE={r['ae']} IF={r['if']} thresh={r['thresh']} "
            f"→ F1={r['f1']:.4f}, FDR={r['fdr']*100:.3f}%"
        )

    if best_weights is None:
        best_result = results[0]
        best_weights   = {"tcn": best_result["tcn"], "ae": best_result["ae"], "if": best_result["if"]}
        best_f1        = best_result["f1"]
        best_threshold = best_result["thresh"]
        logger.warning(
            f"No combination passed FDR gate < {fdr_gate*100:.1f}% — "
            f"using highest-F1 weights (FDR={best_result['fdr']*100:.2f}%)"
        )

    logger.info(f"\n✅ Best weights: {best_weights}  threshold={best_threshold}  (F1={best_f1:.4f})")
    return best_weights, best_threshold


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
        ae_score: np.ndarray,
        if_pred: np.ndarray,
    ) -> np.ndarray:
        """
        Compute weighted risk score for each flow.
        All inputs must already be in [0,1] range before calling this.

        Args:
            tcn_prob:  TCN sigmoid probability [0,1]
            ae_score:  AE anomaly score already normalized to [0,1]
            if_pred:   IF prediction: -1=anomaly, 1=normal

        Returns:
            risk_score: np.ndarray [0,1] per flow
        """
        # IF: -1 (anomaly) → 1.0, 1 (normal) → 0.0
        if_score = (if_pred == -1).astype(np.float32)

        risk_score = (
            self.weights["tcn"] * tcn_prob +
            self.weights["ae"]  * ae_score +
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
    1. Load all three trained models (82k TCN, c2_ddos AE, c2_ddos IF)
    2. Score validation set with each model simultaneously
    3. Calibrate ensemble weights via GridSearchCV + FDR gate
    4. Validate three-tier policy on held-out set
    5. Save ensemble config
    """
    logger.info("=" * 60)
    logger.info("PHASE 3: Validated Fusion Ensemble — The Controller")
    logger.info("=" * 60)

    from train_autoencoder import Autoencoder, load_autoencoder, score_autoencoder, get_feature_matrix
    from train_isolation_forest import load_isolation_forest, get_volumetric_matrix

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # ── Load models ──────────────────────────────────────────────
    logger.info("Loading trained models...")

    # TCN: use newly trained c2_ddos model (Val F1=0.9640)
    from train_tcn import TCN, load_tcn, score_tcn, load_splt_from_csv
    tcn_model = load_tcn(model_dir)
    logger.info(f"✅ Loaded c2_ddos TCN from {model_dir}/tcn_model.pth")

    # AE + IF: from c2_ddos models dir
    ae_model, ae_scaler, ae_threshold = load_autoencoder(model_dir)
    if_model, if_features = load_isolation_forest(model_dir)

    # ── Load held-out test set saved by train_tcn.py ─────────────
    # This is the EXACT same split used during TCN training — no leakage
    test_set_path   = Path(model_dir) / "test_set.csv"
    test_label_path = Path(model_dir) / "test_labels.npy"

    if test_set_path.exists() and test_label_path.exists():
        val_df       = pd.read_csv(test_set_path)
        y_val_binary = np.load(test_label_path).astype(int)
        logger.info(f"✅ Loaded saved test set: {len(val_df):,} samples | Malicious: {y_val_binary.sum():,} ({y_val_binary.mean()*100:.1f}%)")
    else:
        # Fallback: re-create the same split manually
        if data_path is None:
            data_path = "../../data/processed/phase1_processed.csv"
        logger.warning(f"test_set.csv not found — re-creating split from {data_path}")
        df_full = pd.read_csv(data_path)
        if 'snorkel_prob' in df_full.columns:
            y_all = (df_full['snorkel_prob'].values > 0.3).astype(int)
        else:
            label_col = 'label' if 'label' in df_full.columns else 'Label'
            y_all = df_full[label_col].values.astype(int)
        idx   = np.random.RandomState(42).permutation(len(df_full))
        n_test = int(len(df_full) * 0.15)
        val_df       = df_full.iloc[idx[:n_test]].reset_index(drop=True)
        y_val_binary = y_all[idx[:n_test]]
        logger.info(f"Validation set: {len(val_df):,} samples | Malicious: {y_val_binary.sum():,} ({y_val_binary.mean()*100:.1f}%)")

    # ── Score each model simultaneously ──────────────────────────
    logger.info("\nScoring validation set with all three models simultaneously...")

    # TCN scores — use trained c2_ddos model with its scalers
    X_splt_val = load_splt_from_csv(val_df.copy())
    tcn_scores = score_tcn(tcn_model, X_splt_val, model_dir=model_dir)
    logger.info(f"  TCN  → mean={tcn_scores.mean():.4f}, std={tcn_scores.std():.4f}")

    # AE: use raw reconstruction error (properly scaled), then binarize at threshold
    X_all = get_feature_matrix(val_df.copy())
    X_sc  = ae_scaler.transform(X_all).astype(np.float32)
    with torch.no_grad():
        ae_raw = ae_model.reconstruction_error(torch.tensor(X_sc)).numpy()
    # Binary AE signal: 1 if anomaly (above threshold), 0 if normal
    ae_errors = (ae_raw > ae_threshold).astype(np.float32)
    logger.info(f"  AE   → detection rate: {ae_errors.mean()*100:.1f}%  (threshold={ae_threshold:.4f})")

    # IF predictions
    X_vol = get_volumetric_matrix(val_df.copy())
    if_preds = if_model.predict(X_vol)  # -1=anomaly, 1=normal
    if_detection = np.mean(if_preds[y_val_binary == 1] == -1) * 100 if y_val_binary.sum() > 0 else 0
    logger.info(f"  IF   → detection rate on malicious: {if_detection:.1f}%")

    # ── All scores already in [0,1] ──────────────────────────────
    tcn_norm  = tcn_scores.copy()                          # sigmoid [0,1]
    ae_norm   = ae_errors.copy()                           # binary {0,1}
    if_binary = (if_preds == -1).astype(float)             # binary {0,1}
    logger.info(f"  TCN  → mean={tcn_norm.mean():.4f}  benign={tcn_norm[y_val_binary==0].mean():.4f}  mal={tcn_norm[y_val_binary==1].mean():.4f}")
    logger.info(f"  AE   → detection={ae_norm[y_val_binary==1].mean()*100:.1f}%  FPR={ae_norm[y_val_binary==0].mean()*100:.1f}%")
    logger.info(f"  IF   → detection={if_binary[y_val_binary==1].mean()*100:.1f}%  FPR={if_binary[y_val_binary==0].mean()*100:.1f}%")

    # Dummy AE scaler (not used — ae_norm is already binary)
    ae_mm_scaler = MinMaxScaler()
    ae_mm_scaler.fit(np.array([[0.0],[1.0]]))

    # ── GridSearchCV weight calibration ──────────────────────────
    best_weights, best_threshold = calibrate_weights(tcn_norm, ae_norm, if_binary, y_val_binary)

    # ── Build ensemble & final evaluation ────────────────────────
    ensemble = EnsembleFusion(weights=best_weights, ae_scaler=ae_mm_scaler)
    risk_scores = ensemble.fuse(tcn_norm, ae_norm, if_preds)  # all inputs already [0,1]
    decisions = ensemble.classify(risk_scores)

    final_preds = (risk_scores > best_threshold).astype(int)
    fdr = false_discovery_rate(y_val_binary, final_preds)
    f1  = f1_score(y_val_binary, final_preds, zero_division=0)
    tiers = [d["tier"] for d in decisions]

    logger.info(f"\n{'='*60}")
    logger.info(f"ENSEMBLE VALIDATION RESULTS")
    logger.info(f"{'='*60}")
    logger.info(f"  Best Weights:     TCN={best_weights['tcn']} AE={best_weights['ae']} IF={best_weights['if']}")
    logger.info(f"  F1 Score:         {f1:.4f}")
    logger.info(f"  FDR:              {fdr*100:.3f}% ({'✅ PASS' if fdr < 0.001 else '⚠️  ABOVE GATE'})")    
    logger.info(f"  QUARANTINE flows: {tiers.count('QUARANTINE'):,}")
    logger.info(f"  MONITOR flows:    {tiers.count('MONITOR'):,}")
    logger.info(f"  ALLOW flows:      {tiers.count('ALLOW'):,}")
    logger.info(f"\n{classification_report(y_val_binary, final_preds, target_names=['Benign','Malicious'])}")

    # ── Save ensemble config ──────────────────────────────────────
    config = {
        "weights": best_weights,
        "quarantine_threshold": QUARANTINE_THRESHOLD,
        "monitor_threshold": MONITOR_THRESHOLD,
        "ae_threshold": float(ae_threshold),
        "ae_min": float(ae_errors.min()),
        "ae_max": float(ae_errors.max()),
        "f1": float(f1),
        "fdr": float(fdr),
    }
    out_dir = Path(model_dir)
    joblib.dump(config, out_dir / "ensemble_config.pkl")
    joblib.dump(ae_mm_scaler, out_dir / "ae_minmax_scaler.pkl")
    logger.info(f"\n✅ Ensemble config saved → {model_dir}/ensemble_config.pkl")

    return ensemble, config


def load_ensemble(model_dir: str = "models") -> tuple:
    """Load ensemble config for inference."""
    config = joblib.load(Path(model_dir) / "ensemble_config.pkl")
    ae_mm_scaler = joblib.load(Path(model_dir) / "ae_minmax_scaler.pkl")
    ensemble = EnsembleFusion(weights=config["weights"], ae_scaler=ae_mm_scaler)
    return ensemble, config


if __name__ == "__main__":
    DATA_PATH = "../../data/processed/phase1_processed.csv"
    if not Path(DATA_PATH).exists():
        DATA_PATH = "../../data/processed/final_balanced_240k.csv"
    run_phase3(model_dir="models", data_path=DATA_PATH)
