#!/usr/bin/env python3

import numpy as np
import torch
import torch.nn as nn
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class GanDiscriminator(nn.Module):
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


def _ensure_cols(df, cols: List[str]):
    for c in cols:
        if c not in df.columns:
            df[c] = 0.0
    return df


def load_gan_discriminator(model_dir: Path) -> Optional[Dict]:
    path = model_dir / "gan_discriminator_lens.pth"
    if not path.exists():
        return None

    artifact = torch.load(path, map_location="cpu", weights_only=False)
    feat = artifact["feature_names"]
    D = GanDiscriminator(in_dim=len(feat))
    D.load_state_dict(artifact["discriminator_state_dict"])
    D.eval()

    return {
        "path": path,
        "feature_names": feat,
        "scaler": artifact["scaler"],
        "threshold": float(artifact.get("threshold", 0.5)),
        "model": D,
    }


def gan_scores_from_rows(rows_df, gan_bundle: Dict) -> Tuple[np.ndarray, np.ndarray]:
    cols = gan_bundle["feature_names"]
    df = _ensure_cols(rows_df.copy(), cols)
    X = (
        df[cols]
        .fillna(0)
        .replace([np.inf, -np.inf], 0)
        .astype(np.float32)
        .values
    )
    Xs = gan_bundle["scaler"].transform(X).astype(np.float32)

    with torch.no_grad():
        logits = gan_bundle["model"](torch.from_numpy(Xs))
        p_real = torch.sigmoid(logits).squeeze(1).numpy()  # probability looks like real benign

    attack_like = 1.0 - p_real
    return p_real.astype(np.float32), attack_like.astype(np.float32)
