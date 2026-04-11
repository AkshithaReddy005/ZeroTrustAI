#!/usr/bin/env python3
"""
Hierarchical Meta-Fusion Inference for GAN-based Zero Trust PDP (MLP version)
Loads hierarchical_meta_fuser_gan.joblib and provides predict() API.
"""

import joblib
import numpy as np
from pathlib import Path

class HierarchicalMetaFuserGAN:
    def __init__(self, model_bundle):
        self.stage1 = model_bundle["stage1"]
        self.stage2 = model_bundle["stage2"]
        self.stage2_scaler = model_bundle.get("stage2_scaler")
        self.threshold = model_bundle.get("threshold", 0.40)
        self.stage1_features = model_bundle.get("stage1_features", ["ae_score", "gan_attack"])
        self.stage2_features = model_bundle.get("stage2_features", ["tcn_score", "anomaly_expert_score"])

    def predict(self, tcn_score, ae_score, gan_attack):
        """
        Predict using hierarchical MLP meta-fuser.
        Args:
            tcn_score: float
            ae_score: float
            gan_attack: float
        Returns:
            final_confidence: float (probability of malicious)
            stage_outputs: dict with intermediate scores
        """
        # Stage 1: Anomaly Expert (AE + GAN)
        X_stage1 = np.array([[ae_score, gan_attack]], dtype=np.float32)
        anomaly_expert_prob = float(self.stage1.predict_proba(X_stage1)[0, 1])

        # Stage 2: Zero Trust PDP (TCN + Anomaly Expert) with MLP
        X_stage2_raw = np.array([[tcn_score, anomaly_expert_prob]], dtype=np.float32)
        if self.stage2_scaler:
            X_stage2 = self.stage2_scaler.transform(X_stage2_raw)
        else:
            X_stage2 = X_stage2_raw

        final_confidence = float(self.stage2.predict_proba(X_stage2)[0, 1])

        stage_outputs = {
            "stage1_input": {"ae_score": ae_score, "gan_attack": gan_attack},
            "stage1_output": anomaly_expert_prob,
            "stage2_input": {"tcn_score": tcn_score, "anomaly_expert_score": anomaly_expert_prob},
            "stage2_output": final_confidence,
            "threshold": self.threshold,
        }

        return final_confidence, stage_outputs

def load_hierarchical_meta_fuser(model_dir: Path):
    """
    Load hierarchical GAN meta-fuser from joblib bundle.
    """
    bundle_path = model_dir / "hierarchical_meta_fuser_gan.joblib"
    if not bundle_path.exists():
        return None
    try:
        bundle = joblib.load(bundle_path)
        return HierarchicalMetaFuserGAN(bundle)
    except Exception as e:
        print(f"Failed to load hierarchical meta-fuser GAN: {e}")
        return None
