#!/usr/bin/env python3
"""
FINAL SOLUTION: Simple & Effective Production Model

Based on analysis, the best approach is:
1. Use TCN with threshold 0.40 (not 0.50)
2. Add simple ensemble backup
3. Achieve Goldilocks Zone: 85%+ benign, 80%+ attack
"""

import pathlib
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Paths
DATA_DIR = pathlib.Path("data")
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = pathlib.Path("models")
BALANCED_CSV = PROCESSED_DIR / "balanced_train_400k.csv"

# Model paths
TCN_EMERGENCY_PATH = MODELS_DIR / "tcn_emergency.pth"
AE_FIXED_PATH = MODELS_DIR / "autoencoder_fixed.pth"
SCALER_EMERGENCY_PATH = MODELS_DIR / "scaler_emergency.joblib"
SCALER_BENIGN_PATH = MODELS_DIR / "scaler_benign.joblib"

class EmergencyTCN(nn.Module):
    def __init__(self, input_size):
        super().__init__()
        self.tcn = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.AdaptiveAvgPool1d(1),
            nn.Flatten(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        x = x.unsqueeze(1)
        return self.tcn(x).squeeze()

class FixedAutoencoder(nn.Module):
    def __init__(self, input_size):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32)
        )
        
        self.decoder = nn.Sequential(
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, input_size)
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def final_production_model():
    """Create final production-ready model."""
    print("🏆 FINAL PRODUCTION MODEL")
    print("=" * 40)
    print("Strategy: TCN(0.40) + Simple AE Backup")
    
    # Load test data
    df = pd.read_csv(BALANCED_CSV)
    
    # Prepare features
    splt_cols = [f"splt_len_{i}" for i in range(1, 21)] + [f"splt_iat_{i}" for i in range(1, 21)]
    available_cols = [col for col in splt_cols if col in df.columns]
    
    feature_cols = available_cols + ['total_packets', 'total_bytes', 'avg_packet_size', 
                                 'std_packet_size', 'duration', 'pps', 'avg_entropy']
    
    X = df[feature_cols].fillna(0).values
    y = df['label'].values
    
    # Split test data
    from sklearn.model_selection import train_test_split
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Test set: {len(X_test):,} samples")
    
    # Load models
    print("Loading models...")
    
    # Load TCN
    tcn_model = EmergencyTCN(X_test.shape[1])
    tcn_model.load_state_dict(torch.load(TCN_EMERGENCY_PATH))
    tcn_model.eval()
    
    # Load FIXED Autoencoder
    ae_model = FixedAutoencoder(X_test.shape[1])
    ae_model.load_state_dict(torch.load(AE_FIXED_PATH))
    ae_model.eval()
    
    # Load scalers
    scaler_tcn = joblib.load(SCALER_EMERGENCY_PATH)
    scaler_ae = joblib.load(SCALER_BENIGN_PATH)
    
    # Get predictions
    with torch.no_grad():
        # TCN predictions
        X_tcn = torch.FloatTensor(scaler_tcn.transform(X_test))
        tcn_probs = tcn_model(X_tcn).numpy().flatten()
        
        # Autoencoder predictions
        X_ae = torch.FloatTensor(scaler_ae.transform(X_test))
        reconstructed = ae_model(X_ae)
        reconstruction_errors = torch.mean((X_ae - reconstructed) ** 2, dim=1).numpy()
    
    # Normalize reconstruction errors (0-1 scale)
    ae_errors_normalized = (reconstruction_errors - reconstruction_errors.min()) / \
                        (reconstruction_errors.max() - reconstruction_errors.min())
    
    print("✅ Models loaded and predictions generated")
    
    # FINAL PRODUCTION LOGIC
    print(f"\n🎯 FINAL PRODUCTION CONFIGURATION:")
    
    # Optimal thresholds based on our analysis
    TCN_THRESHOLD = 0.40  # Lowered from 0.50
    AE_THRESHOLD = 0.95  # High threshold for AE (only very anomalous)
    
    print(f"TCN Threshold: {TCN_THRESHOLD}")
    print(f"AE Threshold: {AE_THRESHOLD}")
    
    # Apply final logic
    tcn_pred = (tcn_probs >= TCN_THRESHOLD).astype(int)
    ae_pred = (ae_errors_normalized >= AE_THRESHOLD).astype(int)
    
    # ENSEMBLE: TCN OR AE (but AE is very conservative)
    final_pred = np.maximum(tcn_pred, ae_pred)
    
    # Calculate final metrics
    accuracy = accuracy_score(y_test, final_pred)
    precision = precision_score(y_test, final_pred)
    recall = recall_score(y_test, final_pred)
    f1 = f1_score(y_test, final_pred)
    
    # Per-class accuracy
    benign_mask = y_test == 0
    attack_mask = y_test == 1
    
    benign_acc = accuracy_score(y_test[benign_mask], final_pred[benign_mask])
    attack_acc = accuracy_score(y_test[attack_mask], final_pred[attack_mask])
    
    print(f"\n📊 FINAL PRODUCTION RESULTS:")
    print(f"  Overall Accuracy: {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall: {recall:.4f}")
    print(f"  F1-Score: {f1:.4f}")
    print(f"  Benign Accuracy: {benign_acc:.4f}")
    print(f"  Attack Detection: {attack_acc:.4f}")
    
    # Check if we achieved Goldilocks zone
    if benign_acc >= 0.85 and attack_acc >= 0.80:
        print(f"\n🏆 GOLDILOCKS ZONE ACHIEVED!")
        print(f"✅ False Positive Crisis: SOLVED!")
        status = "SUCCESS"
    else:
        print(f"\n⚠️ Close to Goldilocks Zone")
        status = "CLOSE"
    
    # Generate confusion matrix
    cm = confusion_matrix(y_test, final_pred)
    
    print(f"\n📈 Confusion Matrix:")
    print(f"              Predicted")
    print(f"              Benign    Attack")
    print(f"Actual Benign   {cm[0,0]:6d}      {cm[0,1]:6d}")
    print(f"Actual Attack   {cm[1,0]:6d}      {cm[1,1]:6d}")
    
    # False Positive Rate
    fp_rate = cm[0,1] / (cm[0,0] + cm[0,1]) if (cm[0,0] + cm[0,1]) > 0 else 0
    print(f"\n📊 False Positive Rate: {fp_rate:.4f} ({fp_rate*100:.1f}%)")
    
    # Save production configuration
    config = {
        'tcn_threshold': TCN_THRESHOLD,
        'ae_threshold': AE_THRESHOLD,
        'benign_accuracy': benign_acc,
        'attack_detection': attack_acc,
        'f1_score': f1,
        'status': status
    }
    
    with open(MODELS_DIR / "production_config.txt", "w") as f:
        for key, value in config.items():
            f.write(f"{key}={value}\n")
    
    print(f"\n✅ Production configuration saved to models/production_config.txt")
    
    # Generate production deployment code
    deployment_code = f'''
# PRODUCTION DEPLOYMENT CODE
def detect_attack(flow_features):
    """
    Production-ready attack detection function
    """
    # Load models (in production, load once at startup)
    tcn_model = load_tcn_model()
    ae_model = load_ae_model()
    scaler_tcn = load_tcn_scaler()
    scaler_ae = load_ae_scaler()
    
    # Preprocess features
    X_tcn = scaler_tcn.transform(flow_features)
    X_ae = scaler_ae.transform(flow_features)
    
    # Get predictions
    with torch.no_grad():
        tcn_prob = tcn_model(torch.FloatTensor(X_tcn)).item()
        
        reconstructed = ae_model(torch.FloatTensor(X_ae))
        reconstruction_error = torch.mean((X_ae - reconstructed) ** 2).item()
    
    # Normalize reconstruction error
    # (In production, precompute min/max from training)
    ae_error_normalized = (reconstruction_error - AE_MIN) / (AE_MAX - AE_MIN)
    
    # FINAL PRODUCTION LOGIC
    TCN_THRESHOLD = {TCN_THRESHOLD}
    AE_THRESHOLD = {AE_THRESHOLD}
    
    tcn_prediction = tcn_prob >= TCN_THRESHOLD
    ae_prediction = ae_error_normalized >= AE_THRESHOLD
    
    # Ensemble decision
    is_attack = tcn_prediction or ae_prediction
    
    return {{
        'is_attack': is_attack,
        'tcn_confidence': tcn_prob,
        'ae_anomaly_score': ae_error_normalized,
        'final_decision': is_attack
    }}

# Usage:
# result = detect_attack(flow_features)
# if result['is_attack']:
#     block_traffic()
# else:
#     allow_traffic()
'''
    
    with open(MODELS_DIR / "production_deployment.py", "w") as f:
        f.write(deployment_code)
    
    print(f"✅ Production deployment code saved to models/production_deployment.py")
    
    return config

if __name__ == "__main__":
    config = final_production_model()
    
    print(f"\n🎉 PRODUCTION MODEL SUMMARY:")
    print(f"🏆 Status: {config['status']}")
    print(f"📊 Benign Accuracy: {config['benign_accuracy']:.1%}")
    print(f"📊 Attack Detection: {config['attack_detection']:.1%}")
    print(f"📊 F1-Score: {config['f1_score']:.3f}")
    print(f"🚀 Production Ready: {config['status'] == 'SUCCESS'}")
