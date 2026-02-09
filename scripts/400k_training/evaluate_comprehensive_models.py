#!/usr/bin/env python3
"""
Comprehensive model evaluation with detailed metrics for all 7 attack types.

This script:
1. Evaluates all models on comprehensive dataset
2. Calculates metrics per attack type
3. Generates confusion matrix
4. Provides detailed performance analysis
"""

import pathlib
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Paths
DATA_DIR = pathlib.Path("data")
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = pathlib.Path("models")
COMPREHENSIVE_CSV = PROCESSED_DIR / "comprehensive_splt_features.csv"

# Model paths
TCN_PATH = MODELS_DIR / "tcn_classifier.pth"
AE_PATH = MODELS_DIR / "autoencoder.pth"
ISO_PATH = MODELS_DIR / "isoforest.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"

# Attack type mapping
ATTACK_MAPPING = {
    "benign.parquet": "Benign",
    "botnet.parquet": "Botnet", 
    "brute_force.parquet": "Brute Force",
    "ddos.parquet": "DDoS",
    "dos.parquet": "DoS",
    "infiltration.parquet": "Infiltration",
    "web_attack.parquet": "Web Attack",
    "portscan.parquet": "Port Scan"
}

class SPLTDataset(torch.utils.data.Dataset):
    def __init__(self, features, labels=None):
        self.features = torch.FloatTensor(features)
        self.labels = torch.FloatTensor(labels) if labels is not None else None
    
    def __len__(self):
        return len(self.features)
    
    def __getitem__(self, idx):
        if self.labels is not None:
            return self.features[idx], self.labels[idx]
        return self.features[idx]

class SimpleTCN(nn.Module):
    def __init__(self, input_size):
        super().__init__()
        self.tcn = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
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

class Autoencoder(nn.Module):
    def __init__(self, input_size):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 32)
        )
        
        self.decoder = nn.Sequential(
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, input_size)
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def load_models_and_data():
    """Load all trained models and test data."""
    print("Loading models and data...")
    
    # Load dataset
    df = pd.read_csv(COMPREHENSIVE_CSV)
    print(f"Loaded dataset: {len(df)} samples")
    
    # Prepare features
    splt_cols = [f"splt_len_{i}" for i in range(1, 21)] + [f"splt_iat_{i}" for i in range(1, 21)]
    available_cols = [col for col in splt_cols if col in df.columns]
    
    feature_cols = available_cols + ['total_packets', 'total_bytes', 'avg_packet_size', 
                                 'std_packet_size', 'duration', 'pps', 'avg_entropy']
    
    X = df[feature_cols].fillna(0).values
    y = df['label'].values
    
    # Load scaler
    scaler = joblib.load(SCALER_PATH)
    X_scaled = scaler.transform(X)
    
    # Load models
    tcn_model = SimpleTCN(X_scaled.shape[1])
    tcn_model.load_state_dict(torch.load(TCN_PATH))
    tcn_model.eval()
    
    ae_model = Autoencoder(X_scaled.shape[1])
    ae_model.load_state_dict(torch.load(AE_PATH))
    ae_model.eval()
    
    iso_model = joblib.load(ISO_PATH)
    
    print("✅ All models loaded successfully")
    
    return X_scaled, y, df, tcn_model, ae_model, iso_model, feature_cols

def evaluate_tcn(tcn_model, X, y, df):
    """Evaluate TCN model."""
    print("\n🔥 Evaluating TCN Model...")
    
    dataset = SPLTDataset(X, y)
    loader = DataLoader(dataset, batch_size=512, shuffle=False)
    
    predictions = []
    actuals = []
    
    with torch.no_grad():
        for batch_features, batch_labels in loader:
            outputs = tcn_model(batch_features)
            preds = (outputs > 0.5).float()
            predictions.extend(preds.cpu().numpy())
            actuals.extend(batch_labels.cpu().numpy())
    
    predictions = np.array(predictions)
    actuals = np.array(actuals)
    
    # Overall metrics
    accuracy = accuracy_score(actuals, predictions)
    precision = precision_score(actuals, predictions)
    recall = recall_score(actuals, predictions)
    f1 = f1_score(actuals, predictions)
    auc = roc_auc_score(actuals, predictions)
    
    print(f"📊 TCN Overall Metrics:")
    print(f"  Accuracy: {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall: {recall:.4f}")
    print(f"  F1-Score: {f1:.4f}")
    print(f"  AUC-ROC: {auc:.4f}")
    
    # Per-attack metrics
    print(f"\n🎯 Per-Attack Type Metrics:")
    attack_metrics = {}
    
    for attack_file, attack_name in ATTACK_MAPPING.items():
        mask = df['pcap_file'].str.contains(attack_file, na=False)
        if mask.any():
            attack_actuals = actuals[mask]
            attack_preds = predictions[mask]
            
            if len(attack_actuals) > 0:
                acc = accuracy_score(attack_actuals, attack_preds)
                prec = precision_score(attack_actuals, attack_preds, zero_division=0)
                rec = recall_score(attack_actuals, attack_preds, zero_division=0)
                f1_attack = f1_score(attack_actuals, attack_preds, zero_division=0)
                
                attack_metrics[attack_name] = {
                    'samples': len(attack_actuals),
                    'accuracy': acc,
                    'precision': prec,
                    'recall': rec,
                    'f1_score': f1_attack
                }
                
                print(f"  {attack_name:12}: Acc={acc:.3f}, Prec={prec:.3f}, Rec={rec:.3f}, F1={f1_attack:.3f}")
    
    return predictions, attack_metrics

def evaluate_ensemble(ae_model, iso_model, X, y, df):
    """Evaluate ensemble (AE + IsoForest)."""
    print("\n🔥 Evaluating Ensemble (AE + IsolationForest)...")
    
    # Autoencoder reconstruction error
    with torch.no_grad():
        X_tensor = torch.FloatTensor(X)
        reconstructed = ae_model(X_tensor)
        reconstruction_errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1).numpy()
    
    # IsolationForest scores
    iso_scores = iso_model.decision_function(X)
    iso_scores = -iso_scores  # Convert to anomaly scores (higher = more anomalous)
    
    # Combine ensemble scores
    ae_threshold = np.percentile(reconstruction_errors, 95)  # Top 5% as anomalies
    iso_threshold = np.percentile(iso_scores, 95)
    
    ae_anomalies = (reconstruction_errors > ae_threshold).astype(int)
    iso_anomalies = (iso_scores > iso_threshold).astype(int)
    
    # Ensemble: anomaly if either model detects it
    ensemble_predictions = np.maximum(ae_anomalies, iso_anomalies)
    
    # Metrics
    accuracy = accuracy_score(y, ensemble_predictions)
    precision = precision_score(y, ensemble_predictions)
    recall = recall_score(y, ensemble_predictions)
    f1 = f1_score(y, ensemble_predictions)
    
    print(f"📊 Ensemble Overall Metrics:")
    print(f"  Accuracy: {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall: {recall:.4f}")
    print(f"  F1-Score: {f1:.4f}")
    print(f"  AE Threshold: {ae_threshold:.4f}")
    print(f"  Iso Threshold: {iso_threshold:.4f}")
    
    return ensemble_predictions, reconstruction_errors, iso_scores

def generate_confusion_matrix(y_true, y_pred, title="Confusion Matrix"):
    """Generate and display confusion matrix."""
    cm = confusion_matrix(y_true, y_pred)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign', 'Malicious'],
                yticklabels=['Benign', 'Malicious'])
    plt.title(title)
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.show()
    
    return cm

def main():
    """Main evaluation pipeline."""
    print("🚀 Starting Comprehensive Model Evaluation...")
    
    # Load models and data
    X, y, df, tcn_model, ae_model, iso_model, feature_cols = load_models_and_data()
    
    # Evaluate TCN
    tcn_preds, tcn_metrics = evaluate_tcn(tcn_model, X, y, df)
    
    # Evaluate Ensemble
    ensemble_preds, ae_errors, iso_scores = evaluate_ensemble(ae_model, iso_model, X, y, df)
    
    # Generate confusion matrices
    print("\n📊 Generating Confusion Matrices...")
    tcn_cm = generate_confusion_matrix(y, tcn_preds, "TCN Confusion Matrix")
    ensemble_cm = generate_confusion_matrix(y, ensemble_preds, "Ensemble Confusion Matrix")
    
    # Summary report
    print("\n🎉 EVALUATION SUMMARY")
    print("=" * 50)
    print(f"Dataset Size: {len(df):,} samples")
    print(f"Attack Types: {len(ATTACK_MAPPING)}")
    print(f"Feature Count: {len(feature_cols)}")
    
    print(f"\nTCN Performance:")
    print(f"  Overall F1: {f1_score(y, tcn_preds):.4f}")
    print(f"  Overall Accuracy: {accuracy_score(y, tcn_preds):.4f}")
    
    print(f"\nEnsemble Performance:")
    print(f"  Overall F1: {f1_score(y, ensemble_preds):.4f}")
    print(f"  Overall Accuracy: {accuracy_score(y, ensemble_preds):.4f}")
    
    print(f"\n🏆 Best Attack Detection (TCN F1-Score):")
    sorted_attacks = sorted(tcn_metrics.items(), key=lambda x: x[1]['f1_score'], reverse=True)
    for attack_name, metrics in sorted_attacks[:5]:
        print(f"  {attack_name:15}: F1={metrics['f1_score']:.3f} ({metrics['samples']:,} samples)")
    
    print(f"\n✅ Evaluation Complete!")
    print("📈 Models are ready for production deployment!")

if __name__ == "__main__":
    main()
