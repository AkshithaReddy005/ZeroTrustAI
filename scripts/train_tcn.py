#!/usr/bin/env python3
"""
Train a simple Temporal Convolutional Network (TCN) classifier on SPLT features.
- Input: data/processed/splt_features.csv
- Output: models/tcn_classifier.pth

Notes:
- This demo derives weak labels heuristically since ground-truth labels may not exist in SPLT CSV.
  You should replace the heuristic with your dataset's true labels when available.

Heuristic label (y):
- y = 1 (malicious) if any of:
  - ech_detected == 1, or
  - tls_version contains 'TLS1.3', or
  - total_packets > 200 and total_bytes > 50_000, or
  - duration > 5 and pps > 200
- else y = 0 (benign)
"""
import os
import pathlib
import numpy as np
import pandas as pd
from typing import Tuple

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split

CSV_PATH = pathlib.Path("data/processed/splt_features.csv")
LABELED_CSV_PATH = pathlib.Path("data/processed/splt_features_labeled.csv")
MODEL_DIR = pathlib.Path("models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)
OUT_PATH = MODEL_DIR / "tcn_classifier.pth"

SEQ_LEN = 20  # SPLT length
BATCH = 64
EPOCHS = 5
LR = 1e-3


class SPLTDataset(Dataset):
    def __init__(self, df: pd.DataFrame):
        # Build sequences: concatenate len and iat as 2 channels
        len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN + 1)]
        iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN + 1)]
        X_len = df[len_cols].fillna(0.0).to_numpy(dtype=np.float32)
        X_iat = df[iat_cols].fillna(0.0).to_numpy(dtype=np.float32)
        X = np.stack([X_len, X_iat], axis=1)  # [N, C=2, T=20]

        # Prefer real labels if available; otherwise fallback to heuristic labels
        if "label" in df.columns:
            y = df["label"].fillna(0).astype(np.int64).to_numpy()
        else:
            tls = df.get("tls_version", pd.Series([""] * len(df))).astype(str).str.upper()
            ech = df.get("ech_detected", pd.Series([0] * len(df))).astype(int)
            total_packets = df.get("total_packets", pd.Series([0] * len(df))).astype(float)
            total_bytes = df.get("total_bytes", pd.Series([0] * len(df))).astype(float)
            duration = df.get("duration", pd.Series([0] * len(df))).astype(float)
            pps = df.get("total_packets", pd.Series([0] * len(df))).astype(float) / (duration.replace(0, 1e-3))

            y = (
                (ech == 1)
                | tls.str.contains("TLS1.3")
                | ((total_packets > 200) & (total_bytes > 50_000))
                | ((duration > 5.0) & (pps > 200))
            ).astype(np.int64).to_numpy()

        self.X = torch.from_numpy(X)
        self.y = torch.from_numpy(y)

    def __len__(self):
        return self.X.shape[0]

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


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
            Chomp1d(pad),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Conv1d(out_ch, out_ch, kernel_size, padding=pad, dilation=dilation),
            Chomp1d(pad),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        self.downsample = nn.Conv1d(in_ch, out_ch, 1) if in_ch != out_ch else nn.Identity()
        self.relu = nn.ReLU()

    def forward(self, x):
        out = self.net(x)
        res = self.downsample(x)
        return self.relu(out + res)


class TCN(nn.Module):
    def __init__(self, in_ch=2, n_classes=2, channels=(32, 64, 64), kernel_size=3, dropout=0.2):
        super().__init__()
        layers = []
        ch_in = in_ch
        for i, ch_out in enumerate(channels):
            layers.append(TemporalBlock(ch_in, ch_out, kernel_size, dilation=2 ** i, dropout=dropout))
            ch_in = ch_out
        self.tcn = nn.Sequential(*layers)
        self.head = nn.Sequential(
            nn.AdaptiveAvgPool1d(1),
            nn.Flatten(),
            nn.Linear(ch_out, n_classes),
        )

    def forward(self, x):  # x: [B, C=2, T]
        z = self.tcn(x)
        return self.head(z)


def train():
    if LABELED_CSV_PATH.exists():
        df = pd.read_csv(LABELED_CSV_PATH)
    else:
        if not CSV_PATH.exists():
            raise FileNotFoundError(f"CSV not found: {CSV_PATH}")
        df = pd.read_csv(CSV_PATH)
    ds = SPLTDataset(df)

    n_total = len(ds)
    n_train = int(0.8 * n_total)
    n_val = n_total - n_train
    train_ds, val_ds = random_split(ds, [n_train, n_val], generator=torch.Generator().manual_seed(42))

    train_loader = DataLoader(train_ds, batch_size=BATCH, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = TCN().to(device)
    crit = nn.CrossEntropyLoss()
    opt = torch.optim.Adam(model.parameters(), lr=LR)

    for epoch in range(1, EPOCHS + 1):
        model.train()
        tr_loss = 0.0
        for xb, yb in train_loader:
            xb = xb.to(device)
            yb = yb.to(device)
            opt.zero_grad()
            logits = model(xb)
            loss = crit(logits, yb)
            loss.backward()
            opt.step()
            tr_loss += loss.item() * xb.size(0)
        tr_loss /= max(1, len(train_loader.dataset))

        model.eval()
        val_loss = 0.0
        correct = 0
        with torch.no_grad():
            for xb, yb in val_loader:
                xb = xb.to(device)
                yb = yb.to(device)
                logits = model(xb)
                val_loss += crit(logits, yb).item() * xb.size(0)
                pred = logits.argmax(dim=1)
                correct += (pred == yb).sum().item()
        val_loss /= max(1, len(val_loader.dataset))
        val_acc = correct / max(1, len(val_loader.dataset))
        print(f"Epoch {epoch}: train_loss={tr_loss:.4f} val_loss={val_loss:.4f} val_acc={val_acc:.3f}")

    torch.save(model.state_dict(), OUT_PATH)
    print(f"Saved TCN classifier to {OUT_PATH}")


if __name__ == "__main__":
    train()
