#!/usr/bin/env python3
"""
Run this FIRST to inspect your saved model architectures.
    python inspect_models.py
"""
import torch, joblib, numpy as np

MODEL_DIR = "models"

print("=" * 60)
print("  INSPECTING SAVED MODEL KEYS")
print("=" * 60)

# ── TCN ──
print("\n── TCN (tcn_classifier.pth) ──")
state = torch.load(f"{MODEL_DIR}/tcn_classifier.pth", map_location="cpu")
if isinstance(state, dict):
    for k, v in state.items():
        print(f"  {k:<40} {tuple(v.shape)}")

# ── AE ──
print("\n── Autoencoder (autoencoder.pth) ──")
state = torch.load(f"{MODEL_DIR}/autoencoder.pth", map_location="cpu")
if isinstance(state, dict):
    for k, v in state.items():
        print(f"  {k:<40} {tuple(v.shape)}")

# ── joblib files ──
for fname in ["isoforest.joblib", "scaler.joblib",
              "splt_isoforest.joblib", "splt_scaler.joblib",
              "robust_scaler_volumetric.joblib"]:
    import os
    path = f"{MODEL_DIR}/{fname}"
    if os.path.exists(path):
        obj = joblib.load(path)
        print(f"\n── {fname} → {type(obj).__name__}")
        if hasattr(obj, "mean_"):
            print(f"   Scaler expects: {obj.mean_.shape[0]} features")
        if hasattr(obj, "estimators_"):
            print(f"   IsoForest n_estimators: {len(obj.estimators_)}")
            # figure out n_features
            try:
                print(f"   IsoForest n_features: {obj.n_features_in_}")
            except: pass

# ── AE threshold ──
with open(f"{MODEL_DIR}/ae_threshold.txt") as f:
    print(f"\n── ae_threshold.txt → {f.read().strip()}")