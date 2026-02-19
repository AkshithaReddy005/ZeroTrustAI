#!/usr/bin/env python3
"""
Phase 2 - Model C: TCN (Temporal Lens)
Train on full 238K dataset using Snorkel probabilistic soft labels.
Input: 40-packet SPLT sequences (20 lengths + 20 IATs).
Reads SPLT sequences from Redis Feature Store during training.
"""

import logging
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import f1_score, classification_report
from sklearn.preprocessing import PowerTransformer
import joblib

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
        self.relu = nn.LeakyReLU(0.1)
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
    Output: Logit (unnormalized score). Use sigmoid outside the model.
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
        )

    def forward(self, x):
        # x: (batch, channels, seq_len)
        out = self.tcn(x)
        out = self.global_pool(out).squeeze(-1)
        return self.classifier(out).squeeze(-1)


# ─────────────────────────────────────────────
# DATA LOADING
# ─────────────────────────────────────────────

def load_data_from_redis(store, flow_ids: list, batch_size: int = 1000) -> list:
    """Optimized batch loading from Redis to reduce TCP overhead"""
    import redis
    r = redis.Redis(host='localhost', port=6379, decode_responses=False)
    pipe = r.pipeline()
    
    all_features = []
    logger.info(f"Loading {len(flow_ids)} flows in batches of {batch_size}...")
    
    for i in range(0, len(flow_ids), batch_size):
        batch_ids = flow_ids[i:i + batch_size]
        for fid in batch_ids:
            pipe.hgetall(f"flow:{fid}")
        
        # Execute batch request
        results = pipe.execute()
        all_features.extend(results)
        
        if (i // batch_size + 1) % 10 == 0:
            logger.info(f"  Loaded {i + batch_size:,}/{len(flow_ids):,} flows...")
    
    return all_features


def load_splt_from_redis(flow_ids: list, redis_store) -> np.ndarray:
    """Read SPLT sequences from Redis Feature Store with batch optimization."""
    if redis_store and redis_store.is_available():
        logger.info("Loading SPLT sequences from Redis (optimized batch loading)...")
        features = load_data_from_redis(redis_store, flow_ids, batch_size=1000)
        
        # Convert Redis hash results to SPLT array
        X_splt = np.zeros((len(flow_ids), 40), dtype=np.float32)
        for i, data in enumerate(features):
            if data:
                for j, feat in enumerate(SPLT_FEATURES):
                    if feat.encode() in data:
                        X_splt[i, j] = float(data[feat.encode()])
        # If Redis keys expired (TTL) or missing, we may get all-zeros.
        if np.count_nonzero(X_splt) == 0:
            logger.warning(
                "Redis returned empty/all-zero SPLT sequences (possible TTL expiry). "
                "Falling back to CSV for training."
            )
            return None
        return X_splt
    else:
        logger.info("Redis unavailable — using CSV fallback for SPLT...")
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


def _scale_and_stack_len_iat(X_splt: np.ndarray, len_scaler: PowerTransformer, iat_scaler: PowerTransformer, *, fit: bool) -> np.ndarray:
    """Scale SPLT lengths and IATs independently with PowerTransformer for aggressive normalization."""
    splt_len = X_splt[:, :20].astype(np.float32, copy=False)
    splt_iat = X_splt[:, 20:].astype(np.float32, copy=False)

    # Handle IATs with log1p to squash outliers (time-based features often have extreme values)
    # Only apply log to non-zero values to preserve zeros
    iats_log = np.where(splt_iat > 0, np.log1p(splt_iat), 0.0)

    if fit:
        # Flatten -> Scale -> Reshape for PowerTransformer
        len_flat = splt_len.reshape(-1, 1)
        iat_flat = iats_log.reshape(-1, 1)
        
        len_scaled = len_scaler.fit_transform(len_flat).reshape(splt_len.shape)
        iat_scaled = iat_scaler.fit_transform(iat_flat).reshape(splt_len.shape)
    else:
        len_scaled = len_scaler.transform(splt_len.reshape(-1, 1)).reshape(splt_len.shape)
        iat_scaled = iat_scaler.transform(iats_log.reshape(-1, 1)).reshape(splt_len.shape)

    return np.stack([len_scaled, iat_scaled], axis=1).astype(np.float32)


# ─────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────

def train_tcn(
    data_path: str,
    model_dir: str = "models",
    epochs: int = 15,
    batch_size: int = 256,
    val_split: float = 0.15,
    test_split: float = 0.15,
    random_state: int = 42,
    redis_store=None,
) -> TCN:
    logger.info("=" * 60)
    logger.info("PHASE 2 - Model C: TCN Training (Clean)")
    logger.info("=" * 60)

    # ── Load data ────────────────────────────────────────────────
    df = pd.read_csv(data_path)
    logger.info(f"Loaded {len(df):,} samples")

    # Hard binary labels — threshold snorkel_prob at 0.3
    if 'snorkel_prob' in df.columns:
        y = (df['snorkel_prob'].values > 0.3).astype(np.float32)
        logger.info("Labels: snorkel_prob > 0.3 → binary")
    else:
        label_col = 'label' if 'label' in df.columns else 'Label'
        y = df[label_col].values.astype(np.float32)

    # ── 70/15/15 split ───────────────────────────────────────────
    idx = np.random.RandomState(random_state).permutation(len(df))
    n_test = int(len(df) * test_split)
    n_val  = int(len(df) * val_split)
    test_idx  = idx[:n_test]
    val_idx   = idx[n_test:n_test + n_val]
    train_idx = idx[n_test + n_val:]

    train_df = df.iloc[train_idx].reset_index(drop=True)
    val_df   = df.iloc[val_idx].reset_index(drop=True)
    test_df  = df.iloc[test_idx].reset_index(drop=True)
    y_train, y_val, y_test = y[train_idx], y[val_idx], y[test_idx]

    logger.info(f"Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,}")
    logger.info(f"Train malicious: {y_train.mean()*100:.1f}%  Val: {y_val.mean()*100:.1f}%")

    # ── Load SPLT features ───────────────────────────────────────
    flow_ids_train = train_df.get('flow_id', pd.Series(range(len(train_df)))).tolist()
    X_train_redis = load_splt_from_redis(flow_ids_train, redis_store)
    X_train = X_train_redis if X_train_redis is not None else load_splt_from_csv(train_df)
    X_val   = load_splt_from_csv(val_df)
    X_test  = load_splt_from_csv(test_df)
    logger.info(f"SPLT loaded: train={X_train.shape}, val={X_val.shape}")

    # ── Scale: PowerTransformer per-feature-group ────────────────
    len_scaler = PowerTransformer(method='yeo-johnson', standardize=True)
    iat_scaler = PowerTransformer(method='yeo-johnson', standardize=True)
    X_train_tcn_np = _scale_and_stack_len_iat(X_train, len_scaler, iat_scaler, fit=True)
    X_val_tcn_np   = _scale_and_stack_len_iat(X_val,   len_scaler, iat_scaler, fit=False)
    X_test_tcn_np  = _scale_and_stack_len_iat(X_test,  len_scaler, iat_scaler, fit=False)

    # Clamp to [-5, 5] — tighter than before to prevent any gradient issues
    X_train_tcn = torch.tensor(np.clip(X_train_tcn_np, -5, 5), dtype=torch.float32)
    X_val_tcn   = torch.tensor(np.clip(X_val_tcn_np,   -5, 5), dtype=torch.float32)
    X_test_tcn  = torch.tensor(np.clip(X_test_tcn_np,  -5, 5), dtype=torch.float32)
    logger.info(f"Scaled: max={X_train_tcn.abs().max():.3f}  var={X_train_tcn.var():.3f}")

    # ── Tensors & DataLoader ─────────────────────────────────────
    y_train_t = torch.tensor(y_train, dtype=torch.float32)
    y_val_t   = torch.tensor(y_val,   dtype=torch.float32)

    train_ds     = TensorDataset(X_train_tcn, y_train_t)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True,
                              num_workers=0, pin_memory=False)

    # ── Model ────────────────────────────────────────────────────
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device: {device}")
    # Simple 2-layer TCN, kernel=3, no over-engineering
    model = TCN(input_channels=2, sequence_len=20,
                channels=[32, 64], kernel_size=3, dropout=0.1).to(device)

    # ── Optimizer & Loss ─────────────────────────────────────────
    # LR=1e-3 is the sweet spot: not too slow, not exploding
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='max', factor=0.5, patience=3, min_lr=1e-5
    )
    # pos_weight = malicious_ratio correction
    n_neg = (y_train == 0).sum()
    n_pos = (y_train == 1).sum()
    pw = torch.tensor([n_neg / (n_pos + 1e-9)], device=device)
    logger.info(f"pos_weight={pw.item():.2f}  (neg={n_neg:,}  pos={n_pos:,})")
    criterion = nn.BCEWithLogitsLoss(pos_weight=pw)

    # ── Training loop ────────────────────────────────────────────
    best_val_f1 = 0.0
    best_state  = None

    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            optimizer.zero_grad()
            loss = criterion(model(batch_x), batch_y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            total_loss += loss.item()

        avg_loss = total_loss / len(train_loader)

        # Validate
        model.eval()
        with torch.no_grad():
            val_probs = torch.sigmoid(model(X_val_tcn.to(device))).cpu().numpy()
        val_preds = (val_probs >= 0.5).astype(int)
        val_f1    = f1_score(y_val.astype(int), val_preds, average='binary', zero_division=0)
        scheduler.step(val_f1)

        lr_now = optimizer.param_groups[0]['lr']
        logger.info(f"Epoch [{epoch+1:2d}/{epochs}] loss={avg_loss:.4f}  val_f1={val_f1:.4f}  lr={lr_now:.2e}")

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_state  = {k: v.clone() for k, v in model.state_dict().items()}

    # ── Restore best & final test eval ───────────────────────────
    if best_state:
        model.load_state_dict(best_state)
    logger.info(f"\nBest Val F1: {best_val_f1:.4f}")

    model.eval()
    with torch.no_grad():
        test_probs = torch.sigmoid(model(X_test_tcn.to(device))).cpu().numpy()
    test_preds = (test_probs >= 0.5).astype(int)
    test_f1 = f1_score(y_test.astype(int), test_preds, average='binary', zero_division=0)
    logger.info(f"Test F1: {test_f1:.4f}")
    logger.info(f"\n{classification_report(y_test.astype(int), test_preds, target_names=['Benign','Malicious'])}")

    # ── Save ─────────────────────────────────────────────────────
    Path(model_dir).mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), Path(model_dir) / "tcn_model.pth")
    joblib.dump(len_scaler, Path(model_dir) / "tcn_len_scaler.pkl")
    joblib.dump(iat_scaler, Path(model_dir) / "tcn_iat_scaler.pkl")
    test_df.to_csv(Path(model_dir) / "test_set.csv", index=False)
    np.save(Path(model_dir) / "test_labels.npy", y_test)
    logger.info(f"✅ Saved → {model_dir}/tcn_model.pth")

    return model


def load_tcn(model_dir: str = "models") -> TCN:
    """Load trained TCN for inference — matches train_tcn channels=[32,64]."""
    model = TCN(input_channels=2, sequence_len=20, channels=[32, 64], kernel_size=3, dropout=0.1)
    model.load_state_dict(torch.load(Path(model_dir) / "tcn_model.pth", map_location="cpu"))
    model.eval()
    return model


def load_tcn_bundle(model_dir: str = "models") -> tuple[TCN, PowerTransformer, PowerTransformer]:
    """Load trained TCN + SPLT scalers for correct inference preprocessing."""
    model = load_tcn(model_dir)
    len_scaler = joblib.load(Path(model_dir) / "tcn_len_scaler.pkl")
    iat_scaler = joblib.load(Path(model_dir) / "tcn_iat_scaler.pkl")
    return model, len_scaler, iat_scaler


def score_tcn(
    model: TCN,
    X_splt: np.ndarray,
    *,
    model_dir: str = "models",
    len_scaler: PowerTransformer | None = None,
    iat_scaler: PowerTransformer | None = None,
) -> np.ndarray:
    """Returns TCN probability score in [0, 1] for malicious class."""
    if len_scaler is None or iat_scaler is None:
        p_len = Path(model_dir) / "tcn_len_scaler.pkl"
        p_iat = Path(model_dir) / "tcn_iat_scaler.pkl"
        if p_len.exists() and p_iat.exists():
            len_scaler = joblib.load(p_len)
            iat_scaler = joblib.load(p_iat)
        else:
            # Fallback: fit on the provided batch (not ideal, but avoids crashing)
            len_scaler = PowerTransformer(method='yeo-johnson', standardize=True)
            iat_scaler = PowerTransformer(method='yeo-johnson', standardize=True)
            X_tcn_np = _scale_and_stack_len_iat(X_splt, len_scaler, iat_scaler, fit=True)
            X_tcn = torch.tensor(X_tcn_np, dtype=torch.float32)
            with torch.no_grad():
                logits = model(X_tcn)
                scores = torch.sigmoid(logits).cpu().numpy()
            return scores.astype(np.float32)

    X_tcn_np = _scale_and_stack_len_iat(X_splt, len_scaler, iat_scaler, fit=False)
    X_tcn = torch.tensor(X_tcn_np, dtype=torch.float32)
    with torch.no_grad():
        logits = model(X_tcn)
        scores = torch.sigmoid(logits).cpu().numpy()
    return scores.astype(np.float32)


if __name__ == "__main__":
    DATA_PATH = "../../data/processed/phase1_processed.csv"
    if not Path(DATA_PATH).exists():
        DATA_PATH = "../../data/processed/snorkel_labeled.csv"
    if not Path(DATA_PATH).exists():
        DATA_PATH = "../../data/processed/final_balanced_240k.csv"

    # Try to connect Redis
    try:
        from redis_feature_store import RedisFeatureStore
        store = RedisFeatureStore()
    except Exception:
        store = None

    train_tcn(DATA_PATH, redis_store=store)
