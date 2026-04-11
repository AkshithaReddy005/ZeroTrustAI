#!/usr/bin/env python3
"""
Fast-train GAN (Discriminator Lens) for anomaly detection.

Goal (review-ready):
- Train only on BENIGN flows.
- Use the Discriminator as the "GAN score" (probability a flow looks like real benign).
- Save artifact for inference.

This is a simple vanilla GAN (MLP Generator/Discriminator) optimized for speed and stability.
It is NOT a full AnoGAN inversion loop; for tomorrow's demo, the discriminator score is enough.
"""

import argparse
import logging
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


logger = logging.getLogger(__name__)


def _setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _feature_columns(df: pd.DataFrame) -> List[str]:
    cols: List[str] = []
    for i in range(1, 21):
        cols.append(f"splt_len_{i}")
        cols.append(f"splt_iat_{i}")

    extra = [
        "pps",
        "bps",
        "mean_packet_size",
        "mean_iat",
        "burstiness",
        "pseudo_upload_bytes",
        "pseudo_download_bytes",
        "total_packets",
        "total_bytes",
        "duration",
        "std_packet_size",
    ]

    for c in extra:
        if c in df.columns:
            cols.append(c)

    for c in cols:
        if c not in df.columns:
            df[c] = 0.0

    return cols


class Generator(nn.Module):
    def __init__(self, z_dim: int, out_dim: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(z_dim, 128),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(128, 256),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(256, out_dim),
        )

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        return self.net(z)


class Discriminator(nn.Module):
    def __init__(self, in_dim: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 256),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.1),
            nn.Linear(256, 128),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.1),
            nn.Linear(128, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)  # logits


def _batch_iter(X: np.ndarray, batch_size: int, rng: np.random.RandomState):
    idx = rng.permutation(len(X))
    for i in range(0, len(idx), batch_size):
        yield X[idx[i : i + batch_size]]


def train_gan_discriminator(
    data_path: str,
    model_dir: str,
    benign_limit: int,
    epochs: int,
    batch_size: int,
    z_dim: int,
    lr: float,
    seed: int,
) -> Path:
    _setup_logging()

    data_path_p = Path(data_path)
    out_dir = Path(model_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 70)
    logger.info("FAST-TRAIN GAN (DISCRIMINATOR LENS)")
    logger.info("=" * 70)
    logger.info(f"Dataset: {data_path_p}")

    df = pd.read_csv(data_path_p)
    label_col = "label" if "label" in df.columns else ("Label" if "Label" in df.columns else None)
    if label_col is None:
        raise RuntimeError("No label column found (expected 'label' or 'Label')")

    benign_df = df[df[label_col].astype(int) == 0].copy()
    if benign_limit and len(benign_df) > benign_limit:
        benign_df = benign_df.sample(n=benign_limit, random_state=seed)

    logger.info(f"Benign samples used: {len(benign_df):,}")

    cols = _feature_columns(benign_df)
    X = (
        benign_df[cols]
        .fillna(0)
        .replace([np.inf, -np.inf], 0)
        .astype(np.float32)
        .values
    )

    X_train, X_val = train_test_split(X, test_size=0.2, random_state=seed)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train).astype(np.float32)
    X_val_s = scaler.transform(X_val).astype(np.float32)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device: {device}")

    G = Generator(z_dim=z_dim, out_dim=X_train_s.shape[1]).to(device)
    D = Discriminator(in_dim=X_train_s.shape[1]).to(device)

    opt_g = optim.Adam(G.parameters(), lr=lr, betas=(0.5, 0.999))
    opt_d = optim.Adam(D.parameters(), lr=lr, betas=(0.5, 0.999))

    bce = nn.BCEWithLogitsLoss()

    rng = np.random.RandomState(seed)
    torch.manual_seed(seed)

    def disc_prob(x_np: np.ndarray) -> np.ndarray:
        D.eval()
        with torch.no_grad():
            x = torch.from_numpy(x_np).to(device)
            p = torch.sigmoid(D(x)).squeeze(1).detach().cpu().numpy()
        return p

    for epoch in range(1, epochs + 1):
        G.train()
        D.train()

        d_loss_acc = 0.0
        g_loss_acc = 0.0
        steps = 0

        for xb in _batch_iter(X_train_s, batch_size=batch_size, rng=rng):
            steps += 1
            x_real = torch.from_numpy(xb).to(device)
            bsz = x_real.size(0)

            # --- Train D ---
            z = torch.randn(bsz, z_dim, device=device)
            x_fake = G(z).detach()

            y_real = torch.ones(bsz, 1, device=device)
            y_fake = torch.zeros(bsz, 1, device=device)

            opt_d.zero_grad(set_to_none=True)
            d_real = D(x_real)
            d_fake = D(x_fake)
            d_loss = bce(d_real, y_real) + bce(d_fake, y_fake)
            d_loss.backward()
            opt_d.step()

            # --- Train G ---
            z = torch.randn(bsz, z_dim, device=device)
            opt_g.zero_grad(set_to_none=True)
            x_fake2 = G(z)
            d_fake2 = D(x_fake2)
            g_loss = bce(d_fake2, y_real)  # want D to predict real
            g_loss.backward()
            opt_g.step()

            d_loss_acc += float(d_loss.detach().cpu().item())
            g_loss_acc += float(g_loss.detach().cpu().item())

        if epoch % max(1, (epochs // 10)) == 0 or epoch == 1:
            # Quick sanity metrics on benign val: D should output high prob
            p_val = disc_prob(X_val_s)
            benign_mean = float(np.mean(p_val))
            benign_p10 = float(np.quantile(p_val, 0.10))

            # For a demo-friendly number: treat low prob as anomaly, compute pseudo-AUC
            # (labels are all benign so AUC is not meaningful; we'll just log distribution)
            logger.info(
                f"Epoch {epoch:3d}/{epochs} | D_loss={d_loss_acc/steps:.4f} | G_loss={g_loss_acc/steps:.4f} | "
                f"D(benign) mean={benign_mean:.3f} p10={benign_p10:.3f}"
            )

    artifact = {
        "type": "gan_discriminator_lens",
        "feature_names": cols,
        "scaler": scaler,
        "z_dim": z_dim,
        "discriminator_state_dict": D.state_dict(),
        "generator_state_dict": G.state_dict(),
        # threshold heuristic: 10th percentile benign score
        "threshold": float(np.quantile(disc_prob(X_val_s), 0.10)),
    }

    out_path = out_dir / "gan_discriminator_lens.pth"
    torch.save(artifact, out_path)
    logger.info(f"✅ Saved -> {out_path}")
    logger.info(f"Suggested threshold (benign p10): {artifact['threshold']:.3f}")

    return out_path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data_path", default="../../data/processed/final_balanced_240k_fixed.csv")
    ap.add_argument("--model_dir", default="models")
    ap.add_argument("--benign_limit", type=int, default=60000)
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--batch_size", type=int, default=512)
    ap.add_argument("--z_dim", type=int, default=32)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    train_gan_discriminator(
        data_path=args.data_path,
        model_dir=args.model_dir,
        benign_limit=args.benign_limit,
        epochs=args.epochs,
        batch_size=args.batch_size,
        z_dim=args.z_dim,
        lr=args.lr,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
