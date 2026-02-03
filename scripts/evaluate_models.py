#!/usr/bin/env python3
"""Evaluate TCN, Autoencoder, IsolationForest and their ensemble on SPLT CSV.

This prints classification metrics on a holdout split.

Important note about labels:
- Unless your SPLT CSV contains real ground-truth labels, this evaluation uses a heuristic label.
- Replace `make_labels()` to use your true labels once you have them.

Outputs:
- Prints accuracy/precision/recall/f1 for TCN, AE-threshold, IsoForest, and ensemble.
"""
import pathlib
import numpy as np
import pandas as pd
import joblib

import torch
import torch.nn as nn

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

CSV_PATH = pathlib.Path("data/processed/splt_features.csv")
LABELED_CSV_PATH = pathlib.Path("data/processed/splt_features_labeled.csv")
MODEL_DIR = pathlib.Path("models")

TCN_PATH = MODEL_DIR / "tcn_classifier.pth"
AE_PATH = MODEL_DIR / "autoencoder.pth"
AE_THR_PATH = MODEL_DIR / "ae_threshold.txt"
ISO_SCALER_PATH = MODEL_DIR / "splt_scaler.joblib"
ISO_PATH = MODEL_DIR / "splt_isoforest.joblib"

SEQ_LEN = 20


class Chomp1d(nn.Module):
    def __init__(self, chomp_size: int):
        super().__init__()
        self.chomp_size = int(chomp_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.chomp_size <= 0:
            return x
        return x[:, :, :-self.chomp_size].contiguous()


class TemporalBlock(nn.Module):
    def __init__(self, in_ch: int, out_ch: int, kernel_size: int, dilation: int, dropout: float):
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

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out = self.net(x)
        res = self.downsample(x)
        return self.relu(out + res)


class TCN(nn.Module):
    def __init__(self, in_ch: int = 2, n_classes: int = 2, channels=(32, 64, 64), kernel_size: int = 3, dropout: float = 0.2):
        super().__init__()
        layers = []
        ch_in = in_ch
        ch_out = channels[-1]
        for i, c in enumerate(channels):
            layers.append(TemporalBlock(ch_in, c, kernel_size, dilation=2 ** i, dropout=dropout))
            ch_in = c
            ch_out = c
        self.tcn = nn.Sequential(*layers)
        self.head = nn.Sequential(
            nn.AdaptiveAvgPool1d(1),
            nn.Flatten(),
            nn.Linear(ch_out, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.tcn(x)
        return self.head(z)


class AE(nn.Module):
    def __init__(self, in_ch: int = 2, latent: int = 32):
        super().__init__()
        self.enc = nn.Sequential(
            nn.Conv1d(in_ch, 32, 3, padding=1), nn.ReLU(),
            nn.Conv1d(32, 64, 3, padding=1), nn.ReLU(),
            nn.Conv1d(64, latent, 3, padding=1), nn.ReLU(),
        )
        self.dec = nn.Sequential(
            nn.Conv1d(latent, 64, 3, padding=1), nn.ReLU(),
            nn.Conv1d(64, 32, 3, padding=1), nn.ReLU(),
            nn.Conv1d(32, in_ch, 3, padding=1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.enc(x)
        return self.dec(z)


def make_labels(df: pd.DataFrame) -> np.ndarray:
    if "label" in df.columns:
        return df["label"].fillna(0).astype(int).to_numpy()
    # Heuristic labels (replace with real labels when available)
    tls = df.get("tls_version", pd.Series([""] * len(df))).astype(str).str.upper()
    ech = df.get("ech_detected", pd.Series([0] * len(df))).astype(int)
    total_packets = df.get("total_packets", pd.Series([0] * len(df))).astype(float)
    total_bytes = df.get("total_bytes", pd.Series([0] * len(df))).astype(float)
    duration = df.get("duration", pd.Series([0] * len(df))).astype(float).replace(0, 1e-3)
    pps = df.get("total_packets", pd.Series([0] * len(df))).astype(float) / duration

    y = (
        (ech == 1)
        | tls.str.contains("TLS1.3")
        | ((total_packets > 200) & (total_bytes > 50_000))
        | ((duration > 5.0) & (pps > 200))
    ).astype(np.int64).to_numpy()
    return y


def load_X(df: pd.DataFrame) -> np.ndarray:
    len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN + 1)]
    iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN + 1)]
    X_len = df[len_cols].fillna(0.0).to_numpy(dtype=np.float32)
    X_iat = df[iat_cols].fillna(0.0).to_numpy(dtype=np.float32)
    X = np.stack([X_len, X_iat], axis=1)  # [N,2,20]
    return X


def metrics(y_true, y_pred) -> dict:
    acc = accuracy_score(y_true, y_pred)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    return {"acc": acc, "precision": p, "recall": r, "f1": f1}


def main():
    if LABELED_CSV_PATH.exists():
        df = pd.read_csv(LABELED_CSV_PATH)
    else:
        if not CSV_PATH.exists():
            raise FileNotFoundError(CSV_PATH)
        df = pd.read_csv(CSV_PATH)
    y = make_labels(df)
    X = load_X(df)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y if y.sum() > 10 else None)

    device = torch.device("cpu")

    # Load TCN
    tcn = TCN().to(device)
    tcn.load_state_dict(torch.load(TCN_PATH, map_location=device))
    tcn.eval()

    # Load AE + threshold
    ae = AE().to(device)
    ae.load_state_dict(torch.load(AE_PATH, map_location=device))
    ae.eval()
    ae_thr = float(AE_THR_PATH.read_text().strip())

    # Load IsoForest
    scaler = joblib.load(ISO_SCALER_PATH)
    iso = joblib.load(ISO_PATH)

    Xt = torch.from_numpy(X_test).float().to(device)

    # TCN predictions
    with torch.no_grad():
        probs = torch.softmax(tcn(Xt), dim=1)[:, 1].cpu().numpy()
    y_tcn = (probs >= 0.6).astype(np.int64)

    # AE anomaly predictions
    with torch.no_grad():
        xhat = ae(Xt)
        err = ((Xt - xhat) ** 2).mean(dim=(1, 2)).cpu().numpy()
    ae_score = np.clip(err / max(ae_thr, 1e-6), 0.0, 1.0)
    y_ae = (ae_score >= 0.7).astype(np.int64)

    # Iso anomaly predictions
    v = X_test.reshape(X_test.shape[0], -1)
    vs = scaler.transform(v)
    df_score = iso.decision_function(vs)
    iso_score = 1.0 / (1.0 + np.exp(3.0 * df_score))
    iso_score = np.clip(iso_score, 0.0, 1.0)
    y_iso = (iso_score >= 0.6).astype(np.int64)

    # Ensemble
    ens = np.clip(0.50 * probs + 0.25 * ae_score + 0.25 * iso_score, 0.0, 1.0)
    y_ens = (ens >= 0.6).astype(np.int64)

    print("Metrics (holdout test split)")
    print("- TCN:", metrics(y_test, y_tcn))
    print("- Autoencoder:", metrics(y_test, y_ae))
    print("- IsoForest:", metrics(y_test, y_iso))
    print("- Ensemble:", metrics(y_test, y_ens))


if __name__ == "__main__":
    main()
