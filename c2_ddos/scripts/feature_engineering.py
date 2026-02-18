#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
import joblib


def _sorted_splt_cols(df: pd.DataFrame, prefix: str) -> list[str]:
    cols = [c for c in df.columns if c.startswith(prefix)]

    def _idx(c: str) -> int:
        try:
            return int(c.split("_")[-1])
        except Exception:
            return 10**9

    return sorted(cols, key=_idx)


def _ensure_splt_padding(df: pd.DataFrame, prefix: str, target_len: int) -> pd.DataFrame:
    out = df.copy()
    existing = _sorted_splt_cols(out, prefix)

    existing_idx = set()
    for c in existing:
        try:
            existing_idx.add(int(c.split("_")[-1]))
        except Exception:
            pass

    for i in range(1, target_len + 1):
        col = f"{prefix}{i}"
        if i not in existing_idx:
            out[col] = 0.0

    padded_cols = [f"{prefix}{i}" for i in range(1, target_len + 1)]
    out[padded_cols] = out[padded_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    return out


def engineer_features(
    input_csv: str,
    output_csv: str,
    output_summary_json: str | None,
    target_splt_len: int = 40,
    eps: float = 1e-6,
    save_scaler_path: str | None = None,
) -> dict:
    df = pd.read_csv(input_csv)

    if "Attack_Type" in df.columns and "attack_type" not in df.columns:
        df = df.rename(columns={"Attack_Type": "attack_type"})
    if "Label" in df.columns and "label" not in df.columns:
        df = df.rename(columns={"Label": "label"})

    df = _ensure_splt_padding(df, prefix="splt_len_", target_len=target_splt_len)
    df = _ensure_splt_padding(df, prefix="splt_iat_", target_len=target_splt_len)

    duration = pd.to_numeric(df.get("duration", 0.0), errors="coerce").fillna(0.0).astype(float)
    total_packets = pd.to_numeric(df.get("total_packets", 0.0), errors="coerce").fillna(0.0).astype(float)
    total_bytes = pd.to_numeric(df.get("total_bytes", 0.0), errors="coerce").fillna(0.0).astype(float)

    df["pps"] = total_packets / (duration + eps)
    df["bps"] = total_bytes / (duration + eps)
    df["mean_packet_size"] = total_bytes / (np.maximum(total_packets, 1.0))
    df["mean_iat"] = duration / (np.maximum(total_packets - 1.0, 1.0))

    len_cols_20 = [f"splt_len_{i}" for i in range(1, 21)]
    iat_cols_20 = [f"splt_iat_{i}" for i in range(1, 21)]

    df["pkt_size_mean_20"] = df[len_cols_20].mean(axis=1)
    df["pkt_size_std_20"] = df[len_cols_20].std(axis=1)
    df["iat_mean_20"] = df[iat_cols_20].mean(axis=1)
    df["iat_std_20"] = df[iat_cols_20].std(axis=1)
    df["burstiness"] = df["iat_std_20"]

    odd_len_cols = [f"splt_len_{i}" for i in range(1, 21, 2)]
    even_len_cols = [f"splt_len_{i}" for i in range(2, 21, 2)]
    df["pseudo_upload_bytes"] = df[odd_len_cols].sum(axis=1)
    df["pseudo_download_bytes"] = df[even_len_cols].sum(axis=1)
    df["byte_symmetry_ratio"] = df["pseudo_upload_bytes"] / (df["pseudo_download_bytes"] + eps)

    if save_scaler_path:
        volumetric_cols = [
            "pps",
            "bps",
            "duration",
            "total_packets",
            "total_bytes",
            "mean_packet_size",
            "mean_iat",
            "burstiness",
            "pkt_size_mean_20",
            "pkt_size_std_20",
            "iat_mean_20",
            "iat_std_20",
            "byte_symmetry_ratio",
        ]
        present = [c for c in volumetric_cols if c in df.columns]
        scaler = RobustScaler()
        scaler.fit(df[present].replace([np.inf, -np.inf], np.nan).fillna(0.0))
        Path(save_scaler_path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"scaler": scaler, "columns": present}, save_scaler_path)

    Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)

    summary = {
        "input_csv": str(input_csv),
        "output_csv": str(output_csv),
        "rows": int(len(df)),
        "cols": int(len(df.columns)),
        "splt_target_len": int(target_splt_len),
        "derived_features": [
            "pps",
            "bps",
            "mean_packet_size",
            "mean_iat",
            "pkt_size_mean_20",
            "pkt_size_std_20",
            "iat_mean_20",
            "iat_std_20",
            "burstiness",
            "pseudo_upload_bytes",
            "pseudo_download_bytes",
            "byte_symmetry_ratio",
        ],
        "attack_type_counts": df["attack_type"].value_counts().to_dict() if "attack_type" in df.columns else None,
        "label_counts": df["label"].value_counts().to_dict() if "label" in df.columns else None,
        "scaler_saved": str(save_scaler_path) if save_scaler_path else None,
    }

    if output_summary_json:
        Path(output_summary_json).parent.mkdir(parents=True, exist_ok=True)
        with open(output_summary_json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="data/processed/final_balanced_240k.csv",
    )
    parser.add_argument(
        "--output",
        default="data/processed/final_balanced_240k_blueprint.csv",
    )
    parser.add_argument(
        "--summary",
        default="data/processed/final_balanced_240k_blueprint.json",
    )
    parser.add_argument(
        "--target-splt-len",
        type=int,
        default=40,
    )
    parser.add_argument(
        "--save-scaler",
        default="models/robust_scaler_volumetric.joblib",
    )

    args = parser.parse_args()

    engineer_features(
        input_csv=args.input,
        output_csv=args.output,
        output_summary_json=args.summary,
        target_splt_len=args.target_splt_len,
        save_scaler_path=args.save_scaler,
    )


if __name__ == "__main__":
    main()
