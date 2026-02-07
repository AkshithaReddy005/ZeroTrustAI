#!/usr/bin/env python3
"""
Train a simple 1D convolutional Autoencoder on SPLT features for anomaly scoring.
- Input: data/processed/splt_features.csv
- Output: models/autoencoder.pth
- Also writes models/ae_threshold.txt with a simple percentile-based threshold.
"""
import os
import pathlib
import numpy as np
import pandas as pd

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader

CSV_PATH = pathlib.Path("../data/processed/splt_features.csv")
LABELED_CSV_PATH = pathlib.Path("../data/processed/splt_features_labeled.csv")
MODEL_DIR = pathlib.Path("../models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)
AE_PATH = MODEL_DIR / "autoencoder.pth"
THR_PATH = MODEL_DIR / "ae_threshold.txt"

SEQ_LEN = 20
BATCH = 64
EPOCHS = 5
LR = 1e-3


class SPLTAEDataset(Dataset):
    def __init__(self, df: pd.DataFrame):
        len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN + 1)]
        iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN + 1)]
        X_len = df[len_cols].fillna(0.0).to_numpy(dtype=np.float32)
        X_iat = df[iat_cols].fillna(0.0).to_numpy(dtype=np.float32)
        X = np.stack([X_len, X_iat], axis=1)  # [N, 2, 20]
        self.X = torch.from_numpy(X)

    def __len__(self):
        return self.X.shape[0]

    def __getitem__(self, idx):
        return self.X[idx]


class AE(nn.Module):
    def __init__(self, in_ch=2, latent=32):
        super().__init__()
        # encoder
        self.enc = nn.Sequential(
            nn.Conv1d(in_ch, 32, 3, padding=1), nn.ReLU(),
            nn.Conv1d(32, 64, 3, padding=1), nn.ReLU(),
            nn.Conv1d(64, latent, 3, padding=1), nn.ReLU(),
        )
        # decoder
        self.dec = nn.Sequential(
            nn.Conv1d(latent, 64, 3, padding=1), nn.ReLU(),
            nn.Conv1d(64, 32, 3, padding=1), nn.ReLU(),
            nn.Conv1d(32, in_ch, 3, padding=1),
        )

    def forward(self, x):
        z = self.enc(x)
        xhat = self.dec(z)
        return xhat


def train():
    if LABELED_CSV_PATH.exists():
        df = pd.read_csv(LABELED_CSV_PATH)
        if "label" in df.columns:
            df = df[df["label"].fillna(0).astype(int) == 0]
    else:
        if not CSV_PATH.exists():
            raise FileNotFoundError(f"CSV not found: {CSV_PATH}")
        df = pd.read_csv(CSV_PATH)

    if len(df) < 100:
        raise RuntimeError("Not enough benign samples to train AE. Add benign PCAP(s) or regenerate labeled dataset.")
    ds = SPLTAEDataset(df)
    dl = DataLoader(ds, batch_size=BATCH, shuffle=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = AE().to(device)
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    crit = nn.MSELoss()

    for epoch in range(1, EPOCHS + 1):
        model.train()
        loss_sum = 0.0
        for xb in dl:
            xb = xb.to(device)
            opt.zero_grad()
            xhat = model(xb)
            loss = crit(xhat, xb)
            loss.backward()
            opt.step()
            loss_sum += loss.item() * xb.size(0)
        loss_avg = loss_sum / max(1, len(dl.dataset))
        print(f"Epoch {epoch}: recon_loss={loss_avg:.6f}")

    # Compute reconstruction errors for threshold
    model.eval()
    errs = []
    with torch.no_grad():
        for xb in dl:
            xb = xb.to(device)
            xhat = model(xb)
            mse = ((xb - xhat) ** 2).mean(dim=(1, 2))
            errs.append(mse.cpu().numpy())
    errs = np.concatenate(errs, axis=0)
    thr = float(np.percentile(errs, 95))  # simple high-percentile threshold

    torch.save(model.state_dict(), AE_PATH)
    THR_PATH.write_text(str(thr))
    print(f"Saved Autoencoder to {AE_PATH}, threshold={thr:.6f} -> {THR_PATH}")


if __name__ == "__main__":
    train()
