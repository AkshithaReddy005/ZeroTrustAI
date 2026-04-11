#!/usr/bin/env python3
"""Generate fusion dataset with TCN + AE + GAN (adversarial lens) scores.

Outputs CSV with columns:
- tcn_score
- ae_score
- gan_attack (1 - gan_real)
- label

This is intended to be used as input for meta-fuser / hierarchical meta-fuser training.
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


REPO_ROOT = Path(__file__).resolve().parent
MODEL_DIR = REPO_ROOT / "c2_ddos" / "scripts" / "models"

SEQ_LEN = 20


def _row_to_matrices(row: pd.Series):
    len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN + 1)]
    iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN + 1)]

    splt_len = np.array([float(row.get(c, 0) or 0) for c in len_cols], dtype=np.float32)
    splt_iat = np.array([float(row.get(c, 0) or 0) for c in iat_cols], dtype=np.float32)

    X_40 = np.concatenate([splt_len, splt_iat]).reshape(1, -1)

    dur = max(float(row.get("duration", 1.0) or 1.0), 1e-6)
    pkts = max(float(row.get("total_packets", 1) or 1), 1.0)
    byts = float(row.get("total_bytes", 0) or 0)
    pps = pkts / dur
    bps = byts / dur
    mean_pkt = byts / pkts
    mean_iat = dur / max(pkts - 1.0, 1.0)
    burstiness = float(np.std(splt_iat)) if splt_iat.any() else 0.0
    pseudo_up = float(splt_len[0::2].sum())
    pseudo_dn = float(splt_len[1::2].sum())
    vol_7 = np.array([pps, bps, mean_pkt, mean_iat, burstiness, pseudo_up, pseudo_dn], dtype=np.float32)

    X_47 = np.concatenate([splt_len, splt_iat, vol_7]).reshape(1, -1)

    return X_40, X_47


def generate_fusion_csv(input_csv: Path, out_csv: Path, max_rows: int = 50000):
    import sys as _sys

    _sys.path.insert(0, str(REPO_ROOT / "c2_ddos" / "scripts"))

    from train_tcn import load_tcn_bundle, score_tcn
    from train_autoencoder import load_autoencoder, score_autoencoder
    from gan_discriminator_inference import load_gan_discriminator, gan_scores_from_rows

    df = pd.read_csv(input_csv, low_memory=False)
    if "label" not in df.columns:
        raise ValueError("Input CSV must include 'label' column")

    if max_rows and len(df) > max_rows:
        df = df.sample(n=int(max_rows), random_state=42).reset_index(drop=True)

    y = df["label"].fillna(0).astype(int).to_numpy()

    tcn, len_sc, iat_sc = load_tcn_bundle(str(MODEL_DIR))
    ae, ae_sc, ae_thr = load_autoencoder(str(MODEL_DIR))

    gan_bundle = load_gan_discriminator(MODEL_DIR)
    if gan_bundle is None:
        raise FileNotFoundError(f"GAN lens artifact not found in {MODEL_DIR} (expected gan_discriminator_lens.pth)")

    tcn_scores = np.zeros(len(df), dtype=np.float32)
    ae_scores = np.zeros(len(df), dtype=np.float32)
    gan_attack = np.zeros(len(df), dtype=np.float32)

    for i, row in enumerate(df.itertuples(index=False)):
        s = pd.Series(row._asdict())
        X_40, X_47 = _row_to_matrices(s)

        try:
            tcn_scores[i] = float(score_tcn(tcn, X_40, len_scaler=len_sc, iat_scaler=iat_sc)[0])
        except Exception:
            tcn_scores[i] = 0.5

        try:
            ae_scores[i] = float(score_autoencoder(ae, ae_sc, X_47, ae_thr)[0])
        except Exception:
            ae_scores[i] = 0.5

        try:
            gdf = pd.DataFrame([s.to_dict()])
            _, attack_like = gan_scores_from_rows(gdf, gan_bundle)
            gan_attack[i] = float(attack_like[0])
        except Exception:
            gan_attack[i] = 0.5

        if (i + 1) % 2000 == 0 or i == len(df) - 1:
            print(f"  ... {i+1}/{len(df)} scored")

    out_df = pd.DataFrame(
        {
            "tcn_score": tcn_scores,
            "ae_score": ae_scores,
            "gan_attack": gan_attack,
            "label": y,
        }
    )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out_csv, index=False)
    print(f"✅ Saved fusion CSV -> {out_csv}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input_csv", default=str(REPO_ROOT / "data" / "processed" / "meta_fusion_training_50k_unseen.csv"))
    ap.add_argument("--out_csv", default=str(REPO_ROOT / "data" / "processed" / "gan_fusion_training_50k_unseen.csv"))
    ap.add_argument("--max_rows", type=int, default=50000)
    args = ap.parse_args()

    generate_fusion_csv(Path(args.input_csv), Path(args.out_csv), max_rows=int(args.max_rows))


if __name__ == "__main__":
    main()
