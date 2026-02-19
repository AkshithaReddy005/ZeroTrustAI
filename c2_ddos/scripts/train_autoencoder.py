#!/usr/bin/env python3
"""
Phase 2 - Model A: Autoencoder (Anomaly Lens)
Train on 80K benign samples ONLY.
KneeLocator threshold — NOT flat 99th percentile.
MSE reconstruction loss.
"""

import numpy as np
import pandas as pd
import joblib
import logging
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import RobustScaler
from kneed import KneeLocator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# AUTOENCODER ARCHITECTURE
# ─────────────────────────────────────────────

class Autoencoder(nn.Module):
    """
    Symmetric encoder-decoder on 47 features (40 SPLT + 7 volumetric).
    Learns the exact shape of BENIGN traffic — anything else = anomaly.
    """
    def __init__(self, input_dim: int = 47):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Per-sample MSE reconstruction error."""
        recon = self.forward(x)
        return torch.mean((x - recon) ** 2, dim=1)


# ─────────────────────────────────────────────
# FEATURE SELECTION
# ─────────────────────────────────────────────

SPLT_FEATURES = (
    [f'splt_len_{i}' for i in range(1, 21)] +
    [f'splt_iat_{i}' for i in range(1, 21)]
)

VOLUMETRIC_FEATURES = [
    'pps', 'bps', 'mean_packet_size', 'mean_iat',
    'burstiness', 'pseudo_upload_bytes', 'pseudo_download_bytes'
]

ALL_FEATURES = SPLT_FEATURES + VOLUMETRIC_FEATURES  # 47 total


def get_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    available = [f for f in ALL_FEATURES if f in df.columns]
    missing = [f for f in ALL_FEATURES if f not in df.columns]
    if missing:
        logger.warning(f"Missing features (padding with 0): {missing}")
        for col in missing:
            df[col] = 0.0
    return df[ALL_FEATURES].fillna(0).replace([np.inf, -np.inf], 0).values.astype(np.float32)


def _derive_missing_volumetric_features(df: pd.DataFrame, eps: float = 1e-6) -> pd.DataFrame:
    df = df.copy()
    needed = [c for c in VOLUMETRIC_FEATURES if c not in df.columns]
    if not needed:
        return df

    duration = pd.to_numeric(df.get("duration", 0.0), errors="coerce").fillna(0.0).astype(float)
    total_packets = pd.to_numeric(df.get("total_packets", 0.0), errors="coerce").fillna(0.0).astype(float)
    total_bytes = pd.to_numeric(df.get("total_bytes", 0.0), errors="coerce").fillna(0.0).astype(float)

    if "pps" in needed:
        df["pps"] = total_packets / (duration + eps)
    if "bps" in needed:
        df["bps"] = total_bytes / (duration + eps)
    if "mean_packet_size" in needed:
        df["mean_packet_size"] = total_bytes / (np.maximum(total_packets, 1.0))
    if "mean_iat" in needed:
        df["mean_iat"] = duration / (np.maximum(total_packets - 1.0, 1.0))

    if "burstiness" in needed:
        iat_cols_20 = [f"splt_iat_{i}" for i in range(1, 21)]
        present_iats = [c for c in iat_cols_20 if c in df.columns]
        if present_iats:
            df["burstiness"] = df[present_iats].std(axis=1).fillna(0.0)
        else:
            df["burstiness"] = 0.0

    if "pseudo_upload_bytes" in needed or "pseudo_download_bytes" in needed:
        len_cols_20 = [f"splt_len_{i}" for i in range(1, 21)]
        present_lens = [c for c in len_cols_20 if c in df.columns]
        if present_lens:
            odd_len_cols = [f"splt_len_{i}" for i in range(1, 21, 2) if f"splt_len_{i}" in df.columns]
            even_len_cols = [f"splt_len_{i}" for i in range(2, 21, 2) if f"splt_len_{i}" in df.columns]
            if "pseudo_upload_bytes" in needed:
                df["pseudo_upload_bytes"] = df[odd_len_cols].sum(axis=1) if odd_len_cols else 0.0
            if "pseudo_download_bytes" in needed:
                df["pseudo_download_bytes"] = df[even_len_cols].sum(axis=1) if even_len_cols else 0.0
        else:
            if "pseudo_upload_bytes" in needed:
                df["pseudo_upload_bytes"] = 0.0
            if "pseudo_download_bytes" in needed:
                df["pseudo_download_bytes"] = 0.0

    return df


# ─────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────

def train_autoencoder(
    data_path: str,
    model_dir: str = "models",
    epochs: int = 50,
    batch_size: int = 256,
    lr: float = 1e-4,
    benign_limit: int = 80_000,
) -> tuple:
    """
    Train Autoencoder on benign-only samples.
    Returns (model, anomaly_threshold).
    """
    logger.info("=" * 60)
    logger.info("PHASE 2 - Model A: Autoencoder Training")
    logger.info("=" * 60)

    # Load data — benign ONLY
    df = pd.read_csv(data_path)
    df = _derive_missing_volumetric_features(df)
    label_col = 'label' if 'label' in df.columns else 'Label'
    benign_df = df[df[label_col] == 0].head(benign_limit).copy()
    logger.info(f"Benign samples for AE training: {len(benign_df):,}")

    # 80/20 train/val split within benign
    split = int(len(benign_df) * 0.8)
    train_df = benign_df.iloc[:split]
    val_df = benign_df.iloc[split:]

    X_train = get_feature_matrix(train_df)
    X_val = get_feature_matrix(val_df)

    # Scale with RobustScaler
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train).astype(np.float32)
    X_val_scaled = scaler.transform(X_val).astype(np.float32)

    # Clamp extreme values to avoid exploding loss due to pathological outliers
    X_train_scaled = np.clip(X_train_scaled, -10.0, 10.0)
    X_val_scaled = np.clip(X_val_scaled, -10.0, 10.0)

    logger.info(
        "Scaled feature stats (train): "
        f"min={float(np.min(X_train_scaled)):.3f}, "
        f"max={float(np.max(X_train_scaled)):.3f}, "
        f"mean={float(np.mean(X_train_scaled)):.3f}, "
        f"std={float(np.std(X_train_scaled)):.3f}"
    )

    Path(model_dir).mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, Path(model_dir) / "ae_scaler.pkl")

    # DataLoader
    train_tensor = torch.tensor(X_train_scaled)
    train_ds = TensorDataset(train_tensor, train_tensor)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)

    # Model
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = Autoencoder(input_dim=X_train_scaled.shape[1]).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    # Training loop
    model.train()
    for epoch in range(epochs):
        total_loss = 0.0
        for batch_x, batch_y in train_loader:
            batch_x = batch_x.to(device)
            optimizer.zero_grad()
            recon = model(batch_x)
            loss = criterion(recon, batch_x)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            total_loss += loss.item()
        avg_loss = total_loss / len(train_loader)
        if (epoch + 1) % 10 == 0:
            logger.info(f"  Epoch [{epoch+1}/{epochs}] Loss: {avg_loss:.6f}")

    # ─────────────────────────────────────────────
    # KNEELOCATOR THRESHOLD (not flat 99th percentile)
    # ─────────────────────────────────────────────
    model.eval()
    with torch.no_grad():
        val_tensor = torch.tensor(X_val_scaled).to(device)
        errors = model.reconstruction_error(val_tensor).cpu().numpy()

    errors_sorted = np.sort(errors)
    knee = KneeLocator(
        range(len(errors_sorted)),
        errors_sorted,
        curve="convex",
        direction="increasing"
    )
    if knee.knee is not None:
        threshold = errors_sorted[knee.knee]
        logger.info(f"✅ KneeLocator threshold: {threshold:.6f} (at index {knee.knee})")
    else:
        threshold = np.percentile(errors_sorted, 95)
        logger.warning(f"KneeLocator failed — fallback to 95th percentile: {threshold:.6f}")

    # Save model and threshold
    torch.save(model.state_dict(), Path(model_dir) / "autoencoder.pt")
    joblib.dump({"threshold": threshold, "input_dim": X_train_scaled.shape[1]},
                Path(model_dir) / "ae_config.pkl")

    logger.info(f"✅ Autoencoder saved → {model_dir}/autoencoder.pt")
    logger.info(f"✅ AE config saved   → {model_dir}/ae_config.pkl")

    # Validation summary
    val_anomalies = np.sum(errors > threshold)
    logger.info(f"\nValidation (benign-only):")
    logger.info(f"  Mean recon error: {np.mean(errors):.6f}")
    logger.info(f"  Threshold:        {threshold:.6f}")
    logger.info(f"  False positives:  {val_anomalies}/{len(errors)} ({val_anomalies/len(errors)*100:.1f}%)")

    return model, threshold


# ─────────────────────────────────────────────
# INFERENCE
# ─────────────────────────────────────────────

def load_autoencoder(model_dir: str = "models") -> tuple:
    """Load trained AE + config for inference."""
    config = joblib.load(Path(model_dir) / "ae_config.pkl")
    model = Autoencoder(input_dim=config["input_dim"])
    model.load_state_dict(torch.load(Path(model_dir) / "autoencoder.pt", map_location="cpu"))
    model.eval()
    scaler = joblib.load(Path(model_dir) / "ae_scaler.pkl")
    return model, scaler, config["threshold"]


def score_autoencoder(model: Autoencoder, scaler: RobustScaler, X: np.ndarray, threshold: float) -> np.ndarray:
    """
    Returns normalized AE anomaly score in [0, 1].
    Score > threshold → anomaly (malicious).
    """
    X_scaled = scaler.transform(X).astype(np.float32)
    with torch.no_grad():
        tensor = torch.tensor(X_scaled)
        errors = model.reconstruction_error(tensor).numpy()
    # Normalize to [0, 1] using threshold as reference
    normalized = np.clip(errors / (threshold * 2 + 1e-9), 0, 1)
    return normalized


if __name__ == "__main__":
    DATA_PATH = "../../data/processed/phase1_processed.csv"
    if not Path(DATA_PATH).exists():
        DATA_PATH = "../../data/processed/final_balanced_240k.csv"
    train_autoencoder(DATA_PATH)
