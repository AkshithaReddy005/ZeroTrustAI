#!/usr/bin/env python3
"""
Phase 2 - Model C: TCN (Temporal Lens)
Train on full 238K dataset using Snorkel probabilistic soft labels.
Input: 40-packet SPLT sequences (20 lengths + 20 IATs).
Reads SPLT sequences from Redis Feature Store during training.
"""

import numpy as np
import pandas as pd
import joblib
import logging
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import f1_score, classification_report

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 40 SPLT features — the temporal sequence input
SPLT_FEATURES = (
    [f'splt_len_{i}' for i in range(1, 21)] +
    [f'splt_iat_{i}' for i in range(1, 21)]
)


# ─────────────────────────────────────────────
# TCN ARCHITECTURE
# ─────────────────────────────────────────────

class CausalConv1d(nn.Module):
    """Causal dilated convolution — no future leakage."""
    def __init__(self, in_channels, out_channels, kernel_size, dilation):
        super().__init__()
        self.padding = (kernel_size - 1) * dilation
        self.conv = nn.Conv1d(
            in_channels, out_channels, kernel_size,
            padding=self.padding, dilation=dilation
        )

    def forward(self, x):
        out = self.conv(x)
        return out[:, :, :-self.padding] if self.padding > 0 else out


class TCNBlock(nn.Module):
    """Single TCN residual block with causal dilated convolutions."""
    def __init__(self, in_channels, out_channels, kernel_size, dilation, dropout=0.2):
        super().__init__()
        self.conv1 = CausalConv1d(in_channels, out_channels, kernel_size, dilation)
        self.conv2 = CausalConv1d(out_channels, out_channels, kernel_size, dilation)
        self.norm1 = nn.BatchNorm1d(out_channels)
        self.norm2 = nn.BatchNorm1d(out_channels)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(dropout)
        self.downsample = nn.Conv1d(in_channels, out_channels, 1) if in_channels != out_channels else None

    def forward(self, x):
        residual = x
        out = self.relu(self.norm1(self.conv1(x)))
        out = self.dropout(out)
        out = self.relu(self.norm2(self.conv2(out)))
        out = self.dropout(out)
        if self.downsample:
            residual = self.downsample(x)
        return self.relu(out + residual)


class TCN(nn.Module):
    """
    Temporal Convolutional Network for SPLT sequence classification.
    Input: (batch, 2, 20) — 2 channels (lengths, IATs), 20 time steps.
    Output: Softmax probability [0, 1] for malicious class.
    """
    def __init__(self, input_channels=2, sequence_len=20, num_classes=1,
                 channels=[32, 64, 128], kernel_size=3, dropout=0.2):
        super().__init__()
        layers = []
        in_ch = input_channels
        for i, out_ch in enumerate(channels):
            dilation = 2 ** i
            layers.append(TCNBlock(in_ch, out_ch, kernel_size, dilation, dropout))
            in_ch = out_ch
        self.tcn = nn.Sequential(*layers)
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        self.classifier = nn.Sequential(
            nn.Linear(channels[-1], 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, num_classes),
            nn.Sigmoid()
        )

    def forward(self, x):
        # x: (batch, channels, seq_len)
        out = self.tcn(x)
        out = self.global_pool(out).squeeze(-1)
        return self.classifier(out).squeeze(-1)


# ─────────────────────────────────────────────
# DATA LOADING
# ─────────────────────────────────────────────

def load_splt_from_redis(flow_ids: list, redis_store) -> np.ndarray:
    """Read SPLT sequences from Redis Feature Store."""
    if redis_store and redis_store.is_available():
        return redis_store.read_splt_batch(flow_ids)
    return None


def load_splt_from_csv(df: pd.DataFrame) -> np.ndarray:
    """Fallback: load SPLT from CSV when Redis unavailable."""
    for col in SPLT_FEATURES:
        if col not in df.columns:
            df[col] = 0.0
    return df[SPLT_FEATURES].fillna(0).replace([np.inf, -np.inf], 0).values.astype(np.float32)


def prepare_tcn_input(X_splt: np.ndarray) -> torch.Tensor:
    """
    Reshape SPLT features for TCN input.
    (N, 40) → (N, 2, 20): 2 channels (lengths, IATs), 20 time steps.
    """
    lengths = X_splt[:, :20]   # splt_len_1 to splt_len_20
    iats = X_splt[:, 20:]      # splt_iat_1 to splt_iat_20
    # Stack as 2 channels
    X_tcn = np.stack([lengths, iats], axis=1)  # (N, 2, 20)
    return torch.tensor(X_tcn, dtype=torch.float32)


# ─────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────

def train_tcn(
    data_path: str,
    model_dir: str = "models",
    epochs: int = 30,
    batch_size: int = 512,
    lr: float = 1e-3,
    val_split: float = 0.15,
    test_split: float = 0.15,
    random_state: int = 42,
    redis_store=None,
) -> TCN:
    """
    Train TCN on full 238K dataset with Snorkel soft labels.
    70/15/15 train/val/test split — test set touched ONCE at the end.
    """
    logger.info("=" * 60)
    logger.info("PHASE 2 - Model C: TCN Training")
    logger.info("=" * 60)

    df = pd.read_csv(data_path)
    logger.info(f"Loaded {len(df):,} samples")

    # Use Snorkel soft labels if available, else fall back to hard labels
    if 'snorkel_prob' in df.columns:
        y = df['snorkel_prob'].values.astype(np.float32)
        logger.info("Using Snorkel probabilistic soft labels")
    else:
        label_col = 'label' if 'label' in df.columns else 'Label'
        y = df[label_col].values.astype(np.float32)
        logger.warning("Snorkel labels not found — using hard labels. Run snorkel_labeling.py first.")

    # 70/15/15 split
    df_shuffled = df.sample(frac=1, random_state=random_state).reset_index(drop=True)
    y_shuffled = y[df_shuffled.index]
    df_shuffled = df_shuffled.reset_index(drop=True)

    n = len(df_shuffled)
    n_test = int(n * test_split)
    n_val = int(n * val_split)

    test_df = df_shuffled.iloc[:n_test]
    val_df = df_shuffled.iloc[n_test:n_test + n_val]
    train_df = df_shuffled.iloc[n_test + n_val:]

    y_test = y_shuffled[:n_test]
    y_val = y_shuffled[n_test:n_test + n_val]
    y_train = y_shuffled[n_test + n_val:]

    logger.info(f"Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,} (held out)")

    # Load SPLT features from Redis or CSV
    flow_ids_train = train_df.get('flow_id', pd.Series(range(len(train_df)))).tolist()
    X_train_redis = load_splt_from_redis(flow_ids_train, redis_store)
    if X_train_redis is not None:
        X_train = X_train_redis
        logger.info("SPLT sequences loaded from Redis Feature Store ✅")
    else:
        X_train = load_splt_from_csv(train_df)
        logger.info("SPLT sequences loaded from CSV (Redis unavailable)")

    X_val = load_splt_from_csv(val_df)
    X_test = load_splt_from_csv(test_df)

    # Prepare TCN input tensors
    X_train_tcn = prepare_tcn_input(X_train)
    X_val_tcn = prepare_tcn_input(X_val)
    X_test_tcn = prepare_tcn_input(X_test)

    y_train_t = torch.tensor(y_train, dtype=torch.float32)
    y_val_t = torch.tensor(y_val, dtype=torch.float32)

    train_ds = TensorDataset(X_train_tcn, y_train_t)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=0)

    # Model
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Training on: {device}")
    model = TCN(input_channels=2, sequence_len=20).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)

    # Cross-entropy on soft labels (BCELoss)
    criterion = nn.BCELoss()

    best_val_f1 = 0.0
    best_state = None

    for epoch in range(epochs):
        # Train
        model.train()
        total_loss = 0.0
        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            optimizer.zero_grad()
            preds = model(batch_x)
            loss = criterion(preds, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        avg_loss = total_loss / len(train_loader)

        # Validate
        model.eval()
        with torch.no_grad():
            val_preds = model(X_val_tcn.to(device)).cpu().numpy()
        val_labels = (y_val >= 0.5).astype(int)
        val_pred_labels = (val_preds >= 0.5).astype(int)
        val_f1 = f1_score(val_labels, val_pred_labels, zero_division=0)
        scheduler.step(1 - val_f1)

        if (epoch + 1) % 5 == 0:
            logger.info(f"  Epoch [{epoch+1}/{epochs}] Loss: {avg_loss:.4f} | Val F1: {val_f1:.4f}")

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

    # Restore best checkpoint
    if best_state:
        model.load_state_dict(best_state)
    logger.info(f"\nBest Val F1: {best_val_f1:.4f}")

    # Save model
    Path(model_dir).mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), Path(model_dir) / "tcn.pt")
    joblib.dump({"input_channels": 2, "sequence_len": 20}, Path(model_dir) / "tcn_config.pkl")
    logger.info(f"✅ TCN saved → {model_dir}/tcn.pt")

    # Save test set for final evaluation (touch ONCE)
    test_df.to_csv(Path(model_dir) / "test_set.csv", index=False)
    np.save(Path(model_dir) / "test_labels.npy", y_test)
    logger.info(f"✅ Test set saved (DO NOT TOUCH until final evaluation)")

    return model


def load_tcn(model_dir: str = "models") -> TCN:
    """Load trained TCN for inference."""
    config = joblib.load(Path(model_dir) / "tcn_config.pkl")
    model = TCN(input_channels=config["input_channels"], sequence_len=config["sequence_len"])
    model.load_state_dict(torch.load(Path(model_dir) / "tcn.pt", map_location="cpu"))
    model.eval()
    return model


def score_tcn(model: TCN, X_splt: np.ndarray) -> np.ndarray:
    """Returns TCN probability score in [0, 1] for malicious class."""
    X_tcn = prepare_tcn_input(X_splt)
    with torch.no_grad():
        scores = model(X_tcn).numpy()
    return scores.astype(np.float32)


if __name__ == "__main__":
    DATA_PATH = "data/processed/phase1_processed.csv"
    if not Path(DATA_PATH).exists():
        DATA_PATH = "data/processed/snorkel_labeled.csv"
    if not Path(DATA_PATH).exists():
        DATA_PATH = "data/processed/final_balanced_240k.csv"

    # Try to connect Redis
    try:
        from redis_feature_store import RedisFeatureStore
        store = RedisFeatureStore()
    except Exception:
        store = None

    train_tcn(DATA_PATH, redis_store=store)
