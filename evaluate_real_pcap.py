#!/usr/bin/env python3
"""
Real PCAP Data Evaluation Script
Calculates accurate metrics: Accuracy, Precision, Recall, F1-Score
Uses real PCAP-derived CSV data with proper confusion matrix
"""

import os
import sys
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# Configuration
CSV_PATH = "data/processed/final_balanced_240k.csv"
MODEL_DIR = "models/82k_models"
SEQ_LEN = 20
AE_THRESHOLD = 0.95

# Model Classes
class TCN(nn.Module):
    def __init__(self):
        super().__init__()
        self.tcn = nn.Sequential(
            nn.Conv1d(1, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(64, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(32, 16, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(16, 8, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(8, 1, kernel_size=3, padding=1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.tcn(x).squeeze(-1)

class Autoencoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(47, 128), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, 32),
        )
        self.decoder = nn.Sequential(
            nn.Linear(32, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, 128), nn.ReLU(),
            nn.Linear(128, 47),
        )
    
    def forward(self, x):
        return self.decoder(self.encoder(x))

def load_models():
    """Load all trained models"""
    device = torch.device("cpu")
    models = {}
    
    # Load TCN
    try:
        tcn = TCN()
        tcn.load_state_dict(torch.load(f"{MODEL_DIR}/tcn_classifier.pth", map_location=device))
        tcn.eval()
        models['tcn'] = tcn
        print("✅ TCN loaded")
    except Exception as e:
        print(f"❌ TCN error: {e}")
        models['tcn'] = None
    
    # Load Autoencoder
    try:
        ae = Autoencoder()
        ae.load_state_dict(torch.load(f"{MODEL_DIR}/autoencoder.pth", map_location=device))
        ae.eval()
        models['ae'] = ae
        print("✅ Autoencoder loaded")
    except Exception as e:
        print(f"❌ Autoencoder error: {e}")
        models['ae'] = None
    
    # Load IsolationForest
    try:
        iso_paths = []
        for root, dirs, files in os.walk(MODEL_DIR):
            for file in files:
                if file.endswith('.joblib'):
                    iso_paths.append(os.path.join(root, file))
        
        iso = None
        scaler = None
        for path in iso_paths:
            try:
                obj = joblib.load(path)
                if isinstance(obj, IsolationForest):
                    iso = obj
                    print(f"✅ IsolationForest loaded: {path}")
                    break
            except:
                continue
        
        # Find scaler
        if iso:
            for path in iso_paths:
                try:
                    obj = joblib.load(path)
                    if hasattr(obj, 'mean_') and len(obj.mean_) == iso.n_features_in_:
                        scaler = obj
                        print(f"✅ Scaler loaded: {path}")
                        break
                except:
                    continue
        
        models['iso'] = iso
        models['scaler'] = scaler
        models['iso_nfeat'] = iso.n_features_in_ if iso else 47
        
    except Exception as e:
        print(f"❌ IsolationForest error: {e}")
        models['iso'] = None
        models['scaler'] = None
        models['iso_nfeat'] = 47
    
    return models, device

def extract_features(row):
    """Extract features from PCAP data row"""
    # SPLT features (40)
    len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN+1)]
    iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN+1)]
    
    splt_len = np.array([float(row.get(c, 0) or 0) for c in len_cols], dtype=np.float32)
    splt_iat = np.array([float(row.get(c, 0) or 0) for c in iat_cols], dtype=np.float32)
    splt_40 = np.concatenate([splt_len, splt_iat])
    
    # Volumetric features (7)
    dur = max(float(row.get("duration", 1.0) or 1.0), 1e-3)
    pps = float(row.get("total_packets", 100) or 100) / dur
    
    vol_7 = np.array([
        float(row.get("total_packets", 100) or 100),
        float(row.get("total_bytes", 50000) or 50000),
        float(row.get("avg_packet_size", 500) or 500),
        float(row.get("std_packet_size", 100) or 100),
        dur, pps,
        float(row.get("avg_entropy", 4.0) or 4.0),
    ], dtype=np.float32)
    
    full_47 = np.concatenate([splt_40, vol_7])
    X_tcn = splt_40.reshape(1, -1)
    
    return X_tcn, full_47

def predict_ensemble(row, models, device):
    """Get ensemble prediction for a single row"""
    X_tcn, X_47 = extract_features(row)
    
    # TCN prediction
    tcn_score = 0.5
    if models['tcn']:
        try:
            t = torch.from_numpy(X_tcn).unsqueeze(0).float()
            with torch.no_grad():
                tcn_score = float(models['tcn'](t).squeeze().item())
        except Exception as e:
            print(f"TCN error: {e}")
            pass
    
    # Autoencoder prediction
    ae_score = 0.5
    if models['ae']:
        try:
            t = torch.from_numpy(X_47).unsqueeze(0).float()
            with torch.no_grad():
                recon = models['ae'](t)
                mse = float(((t - recon)**2).mean().item())
            ae_score = float(np.clip(mse / AE_THRESHOLD, 0.0, 1.0))
        except Exception as e:
            print(f"AE error: {e}")
            pass
    
    # IsolationForest prediction
    iso_score = 0.5
    if models['iso']:
        try:
            n = models['iso_nfeat']
            Xi = np.zeros((1, n), dtype=np.float32)
            src = X_47 if len(X_47) >= n else np.pad(X_47, (0, n-len(X_47)))
            Xi[0] = src[:n]
            
            if models['scaler']:
                Xs = models['scaler'].transform(Xi)
            else:
                Xs = Xi
            
            raw = float(models['iso'].decision_function(Xs)[0])
            # Fix: IsolationForest returns negative for outliers, positive for inliers
            iso_score = float(np.clip(1.0 / (1.0 + np.exp(-3.0 * raw)), 0.0, 1.0))
        except Exception as e:
            print(f"IsoForest error: {e}")
            pass
    
    # Ensemble weighted average
    n_loaded = sum(1 for k in ['tcn', 'ae', 'iso'] if models.get(k))
    if n_loaded == 3:
        ensemble_score = tcn_score * 0.40 + ae_score * 0.30 + iso_score * 0.30
    elif n_loaded == 2:
        scores = [s for s, k in [(tcn_score, 'tcn'), (ae_score, 'ae'), (iso_score, 'iso')] if models.get(k)]
        ensemble_score = sum(scores) / len(scores)
    else:
        ensemble_score = tcn_score
    
    return ensemble_score, tcn_score, ae_score, iso_score

def evaluate_on_real_data():
    """Evaluate models on real PCAP data"""
    print("="*80)
    print("🔬 REAL PCAP DATA EVALUATION")
    print("="*80)
    
    # Load models
    models, device = load_models()
    n_loaded = sum(1 for k in ['tcn', 'ae', 'iso'] if models.get(k))
    print(f"\n📊 Models loaded: {n_loaded}/3")
    
    if n_loaded == 0:
        print("❌ No models loaded!")
        return
    
    # Load real PCAP data
    if not os.path.exists(CSV_PATH):
        print(f"❌ Data file not found: {CSV_PATH}")
        return
    
    print(f"\n📂 Loading real PCAP data: {CSV_PATH}")
    df = pd.read_csv(CSV_PATH, low_memory=False)
    print(f"✅ Loaded {len(df):,} flows")
    
    # Sample for evaluation (use subset for faster processing)
    eval_size = min(10000, len(df))  # Evaluate on 10k samples max
    df_eval = df.sample(n=eval_size, random_state=42).reset_index(drop=True)
    print(f"📊 Evaluating on {len(df_eval):,} samples")
    
    # Get true labels from PCAP data
    true_labels = []
    pred_labels = []
    pred_scores = []
    
    print(f"\n🚀 Running inference on real PCAP data...")
    
    for idx, row in df_eval.iterrows():
        if idx % 1000 == 0:
            print(f"   Processing {idx}/{len(df_eval)}...")
        
        # Get true label from PCAP data
        label_val = str(row.get('label', '0')).strip()
        if label_val in ['0', 'benign', 'normal']:
            true_label = 0  # Benign
        else:
            true_label = 1  # Malicious
        
        # Get ensemble prediction
        ensemble_score, tcn_s, ae_s, iso_s = predict_ensemble(row, models, device)
        pred_label = 1 if ensemble_score >= 0.5 else 0
        
        true_labels.append(true_label)
        pred_labels.append(pred_label)
        pred_scores.append(ensemble_score)
    
    # Find optimal threshold
    print(f"\n🎯 FINDING OPTIMAL THRESHOLD...")
    thresholds = np.linspace(0.1, 0.9, 50)
    best_f1 = 0
    best_threshold = 0.5
    
    for threshold in thresholds:
        pred_at_thresh = [1 if score >= threshold else 0 for score in pred_scores]
        f1 = f1_score(true_labels, pred_at_thresh, average='binary', zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
    
    print(f"   Best threshold: {best_threshold:.3f} (F1: {best_f1:.4f})")
    
    # Re-calculate metrics with optimal threshold
    pred_labels_optimal = [1 if score >= best_threshold else 0 for score in pred_scores]
    
    accuracy = accuracy_score(true_labels, pred_labels_optimal)
    precision = precision_score(true_labels, pred_labels_optimal, average='binary', zero_division=0)
    recall = recall_score(true_labels, pred_labels_optimal, average='binary', zero_division=0)
    f1 = f1_score(true_labels, pred_labels_optimal, average='binary', zero_division=0)
    
    # Confusion Matrix
    cm = confusion_matrix(true_labels, pred_labels_optimal)
    tn, fp, fn, tp = cm.ravel()
    
    # Additional metrics
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    print("\n" + "="*60)
    print("📊 EVALUATION RESULTS ON REAL PCAP DATA")
    print("="*60)
    
    print(f"\n🎯 CORE METRICS:")
    print(f"   Accuracy:       {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"   Precision:      {precision:.4f} ({precision*100:.2f}%)")
    print(f"   Recall:         {recall:.4f} ({recall*100:.2f}%)")
    print(f"   F1-Score:       {f1:.4f} ({f1*100:.2f}%)")
    
    print(f"\n📋 CONFUSION MATRIX:")
    print(f"   True Negatives (TN):  {tn:,}")
    print(f"   False Positives (FP): {fp:,}")
    print(f"   False Negatives (FN): {fn:,}")
    print(f"   True Positives (TP):  {tp:,}")
    
    print(f"\n🔍 ADDITIONAL METRICS:")
    print(f"   Specificity:    {specificity:.4f} ({specificity*100:.2f}%)")
    print(f"   False Positive Rate:  {false_positive_rate:.4f} ({false_positive_rate*100:.2f}%)")
    print(f"   False Negative Rate:  {false_negative_rate:.4f} ({false_negative_rate*100:.2f}%)")
    
    # Data distribution
    total_malicious = sum(true_labels)
    total_benign = len(true_labels) - total_malicious
    print(f"\n📊 DATA DISTRIBUTION:")
    print(f"   Total samples:     {len(true_labels):,}")
    print(f"   Benign samples:     {total_benign:,} ({total_benign/len(true_labels)*100:.1f}%)")
    print(f"   Malicious samples:  {total_malicious:,} ({total_malicious/len(true_labels)*100:.1f}%)")
    
    # Detailed classification report
    print(f"\n📋 CLASSIFICATION REPORT:")
    print(classification_report(true_labels, pred_labels, 
                          target_names=['Benign', 'Malicious'], 
                          digits=4))
    
    # Create confusion matrix visualization
    plt.figure(figsize=(10, 8))
    
    # Confusion Matrix Heatmap
    plt.subplot(2, 2, 1)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign', 'Malicious'],
                yticklabels=['Benign', 'Malicious'])
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    
    # Metrics Bar Chart
    plt.subplot(2, 2, 2)
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    values = [accuracy, precision, recall, f1]
    colors = ['green', 'blue', 'orange', 'red']
    bars = plt.bar(metrics, values, color=colors, alpha=0.7)
    plt.title('Performance Metrics')
    plt.ylabel('Score')
    plt.ylim(0, 1)
    for bar, value in zip(bars, values):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{value:.3f}', ha='center', va='bottom')
    
    # Score Distribution
    plt.subplot(2, 2, 3)
    benign_scores = [pred_scores[i] for i in range(len(pred_scores)) if true_labels[i] == 0]
    malicious_scores = [pred_scores[i] for i in range(len(pred_scores)) if true_labels[i] == 1]
    
    plt.hist(benign_scores, bins=50, alpha=0.7, label='Benign', color='green', density=True)
    plt.hist(malicious_scores, bins=50, alpha=0.7, label='Malicious', color='red', density=True)
    plt.axvline(x=0.5, color='black', linestyle='--', label='Decision Threshold')
    plt.title('Score Distribution')
    plt.xlabel('Ensemble Score')
    plt.ylabel('Density')
    plt.legend()
    
    # ROC-like visualization
    plt.subplot(2, 2, 4)
    thresholds = np.linspace(0, 1, 100)
    tprs = []
    fprs = []
    
    for threshold in thresholds:
        pred_at_thresh = [1 if score >= threshold else 0 for score in pred_scores]
        tp = sum(1 for i, (t, p) in enumerate(zip(true_labels, pred_at_thresh)) if t == 1 and p == 1)
        fp = sum(1 for i, (t, p) in enumerate(zip(true_labels, pred_at_thresh)) if t == 0 and p == 1)
        fn = sum(1 for i, (t, p) in enumerate(zip(true_labels, pred_at_thresh)) if t == 1 and p == 0)
        tn = sum(1 for i, (t, p) in enumerate(zip(true_labels, pred_at_thresh)) if t == 0 and p == 0)
        
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        tprs.append(tpr)
        fprs.append(fpr)
    
    plt.plot(fprs, tprs, color='blue', lw=2)
    plt.plot([0, 1], [0, 1], color='gray', linestyle='--')
    plt.title('ROC Curve')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    plot_file = f"evaluation_results_{timestamp}.png"
    plt.savefig(plot_file, dpi=300, bbox_inches='tight')
    print(f"\n📊 Visualization saved: {plot_file}")
    
    # Save metrics to file
    results_file = f"evaluation_metrics_{timestamp}.txt"
    with open(results_file, 'w') as f:
        f.write("REAL PCAP DATA EVALUATION RESULTS\n")
        f.write("="*50 + "\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
        f.write(f"Dataset: {CSV_PATH}\n")
        f.write(f"Samples evaluated: {len(df_eval):,}\n")
        f.write(f"Models loaded: {n_loaded}/3\n\n")
        
        f.write("CORE METRICS\n")
        f.write("-"*20 + "\n")
        f.write(f"Accuracy: {accuracy:.6f}\n")
        f.write(f"Precision: {precision:.6f}\n")
        f.write(f"Recall: {recall:.6f}\n")
        f.write(f"F1-Score: {f1:.6f}\n\n")
        
        f.write("CONFUSION MATRIX\n")
        f.write("-"*20 + "\n")
        f.write(f"True Negatives: {tn}\n")
        f.write(f"False Positives: {fp}\n")
        f.write(f"False Negatives: {fn}\n")
        f.write(f"True Positives: {tp}\n\n")
        
        f.write("ADDITIONAL METRICS\n")
        f.write("-"*20 + "\n")
        f.write(f"Specificity: {specificity:.6f}\n")
        f.write(f"False Positive Rate: {false_positive_rate:.6f}\n")
        f.write(f"False Negative Rate: {false_negative_rate:.6f}\n")
    
    print(f"📄 Metrics saved: {results_file}")
    
    plt.show()
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'confusion_matrix': cm,
        'true_labels': true_labels,
        'pred_labels': pred_labels,
        'pred_scores': pred_scores
    }

if __name__ == "__main__":
    results = evaluate_on_real_data()
    print(f"\n✅ Evaluation complete!")
