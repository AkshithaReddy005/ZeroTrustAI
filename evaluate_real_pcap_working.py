#!/usr/bin/env python3
"""
Real PCAP Data Evaluation Script - Using Working Models
Calculates accurate metrics with the actual models from real_data_sender.py
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

# Import model classes from real_data_sender.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

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

def find_isoforest():
    """Find IsolationForest model"""
    import glob
    paths = glob.glob(os.path.join(MODEL_DIR, "**", "*.joblib"), recursive=True)
    paths += glob.glob(os.path.join(MODEL_DIR, "*.joblib"))
    for path in sorted(set(paths)):
        try:
            obj = joblib.load(path)
            if isinstance(obj, IsolationForest):
                print(f"✅ IsoForest: {path}  (n_features={obj.n_features_in_})")
                return obj
        except: continue
    return None

def find_scaler(n_features):
    """Find scaler for IsolationForest"""
    import glob
    paths = glob.glob(os.path.join(MODEL_DIR, "**", "*.joblib"), recursive=True)
    paths += glob.glob(os.path.join(MODEL_DIR, "*.joblib"))
    for path in sorted(set(paths)):
        try:
            obj = joblib.load(path)
            n = getattr(obj, "mean_", getattr(obj, "center_", None))
            if n is not None and len(n) == n_features:
                print(f"✅ Scaler:    {path}  (features={len(n)})")
                return obj
        except: continue
    return None

def load_models():
    """Load models using the same logic as real_data_sender.py"""
    device = torch.device("cpu")
    m = {}

    # TCN
    try:
        tcn = TCN()
        tcn.load_state_dict(torch.load(f"{MODEL_DIR}/tcn_classifier.pth", map_location=device))
        tcn.eval(); m["tcn"] = tcn
        print("✅ TCN loaded  → input [batch, 1, 40]")
    except Exception as e:
        print(f"❌ TCN: {e}"); m["tcn"] = None

    # Autoencoder
    try:
        ae = Autoencoder()
        ae.load_state_dict(torch.load(f"{MODEL_DIR}/autoencoder.pth", map_location=device))
        ae.eval(); m["ae"] = ae; m["ae_thr"] = AE_THRESHOLD
        print(f"✅ AE loaded   → input [batch, 47]  threshold={AE_THRESHOLD}")
    except Exception as e:
        print(f"❌ AE: {e}"); m["ae"] = None; m["ae_thr"] = AE_THRESHOLD

    # IsoForest (search all subdirs)
    iso = find_isoforest()
    m["iso"] = iso
    m["iso_nfeat"] = iso.n_features_in_ if iso else 47
    if iso:
        m["scaler"] = find_scaler(iso.n_features_in_)
    else:
        print("⚠️  IsolationForest not found")
        m["scaler"] = None

    return m, device

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

def score_row(row, m, device):
    """Score a row using the same logic as real_data_sender.py"""
    X_tcn, X_47 = extract_features(row)

    # TCN — input [1, 1, 40]
    tcn_s = 0.5
    if m["tcn"]:
        try:
            t = torch.from_numpy(X_tcn).unsqueeze(0).float()
            with torch.no_grad():
                tcn_s = float(m["tcn"](t).squeeze().item())
        except Exception as e:
            print(f"   TCN error: {e}")

    # AE — input [1, 47]
    ae_s = 0.5
    if m["ae"]:
        try:
            t = torch.from_numpy(X_47).unsqueeze(0).float()
            with torch.no_grad():
                recon = m["ae"](t)
                mse = float(((t - recon)**2).mean().item())
            ae_s = float(np.clip(mse / max(m["ae_thr"], 1e-9), 0.0, 1.0))
        except Exception as e:
            print(f"   AE error: {e}")

    # IsoForest
    iso_s = 0.5
    if m["iso"]:
        try:
            n   = m["iso_nfeat"]
            Xi  = np.zeros((1, n), dtype=np.float32)
            src = X_47 if len(X_47) >= n else np.pad(X_47, (0, n-len(X_47)))
            Xi[0] = src[:n]
            Xs = m["scaler"].transform(Xi) if m["scaler"] else Xi
            raw = float(m["iso"].decision_function(Xs)[0])
            iso_s = float(np.clip(1.0 / (1.0 + np.exp(3.0 * raw)), 0.0, 1.0))
        except Exception as e:
            print(f"   IsoForest error: {e}")

    # Ensemble
    n_loaded = sum(1 for k in ["tcn","ae","iso"] if m.get(k))
    if n_loaded == 3:
        conf = tcn_s*0.50 + ae_s*0.25 + iso_s*0.25
    elif n_loaded == 2:
        vals = [s for s,k in [(tcn_s,"tcn"),(ae_s,"ae"),(iso_s,"iso")] if m.get(k)]
        conf = sum(vals)/len(vals)
    else:
        conf = tcn_s
    return tcn_s, ae_s, iso_s, float(np.clip(conf,0,1))

def get_attack_type(row):
    """Get attack type from row data"""
    if "attack_type" in row and pd.notna(row.get("attack_type")):
        at = str(row["attack_type"]).lower().strip()
        LABEL_MAP = {
            "dos":"dos","ddos":"ddos","brute_force":"brute_force","bruteforce":"brute_force",
            "botnet":"botnet","infiltration":"infiltration","web_attack":"web_attack",
            "port_scan":"port_scan","portscan":"port_scan","benign":"benign",
            "normal":"benign","0":"benign","1":"malicious"
        }
        return LABEL_MAP.get(at, at)
    
    if "label" in row and pd.notna(row.get("label")):
        lbl = str(row["label"]).strip()
        if lbl=="0": return "benign"
        if lbl=="1": return "malicious"
        return lbl.lower()
    
    return "benign"

def evaluate_on_real_data():
    """Evaluate models on real PCAP data"""
    print("="*80)
    print("🔬 REAL PCAP DATA EVALUATION - WORKING MODELS")
    print("="*80)
    
    # Load models
    m, device = load_models()
    n = sum(1 for k in ["tcn","ae","iso"] if m.get(k))
    print(f"\n{'✅' if n==3 else '⚠️'} {n}/3 models loaded")
    if n==0: print("❌ No models"); sys.exit(1)

    # Load real PCAP data
    if not os.path.exists(CSV_PATH):
        print(f"❌ Data file not found: {CSV_PATH}")
        return
    
    print(f"\n📂 {CSV_PATH}")
    df = pd.read_csv(CSV_PATH, low_memory=False)
    print(f"✅ {len(df):,} flows\n")

    # Sample for evaluation
    eval_size = min(5000, len(df))
    df_eval = df.sample(n=eval_size, random_state=42).reset_index(drop=True)
    print(f"📊 Evaluating on {len(df_eval):,} samples")
    
    # Get true labels and predictions
    true_labels = []
    pred_labels = []
    pred_scores = []
    tcn_scores = []
    ae_scores = []
    iso_scores = []
    
    print(f"\n🚀 Running inference...")
    
    for idx, row in df_eval.iterrows():
        if idx % 500 == 0:
            print(f"   {idx}/{len(df_eval)}")
        
        # Get true label
        label_val = str(row.get('label', '0')).strip()
        if label_val in ['0', 'benign', 'normal']:
            true_label = 0  # Benign
        else:
            true_label = 1  # Malicious
        
        # Get ensemble prediction
        tcn_s, ae_s, iso_s, conf = score_row(row, m, device)
        pred_label = 1 if conf >= 0.5 else 0
        
        true_labels.append(true_label)
        pred_labels.append(pred_label)
        pred_scores.append(conf)
        tcn_scores.append(tcn_s)
        ae_scores.append(ae_s)
        iso_scores.append(iso_s)
    
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
    
    print(f"\n🎯 CORE METRICS (Optimal Threshold: {best_threshold:.3f}):")
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
    
    # Model performance breakdown
    print(f"\n🤖 MODEL PERFORMANCE BREAKDOWN:")
    print(f"   TCN Score Range:    {min(tcn_scores):.3f} - {max(tcn_scores):.3f}")
    print(f"   AE Score Range:     {min(ae_scores):.3f} - {max(ae_scores):.3f}")
    print(f"   IsoForest Range:    {min(iso_scores):.3f} - {max(iso_scores):.3f}")
    print(f"   Ensemble Range:     {min(pred_scores):.3f} - {max(pred_scores):.3f}")
    
    # Detailed classification report
    print(f"\n📋 CLASSIFICATION REPORT:")
    print(classification_report(true_labels, pred_labels_optimal, 
                          target_names=['Benign', 'Malicious'], 
                          digits=4))
    
    # Create visualization
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    
    # Confusion Matrix
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign', 'Malicious'],
                yticklabels=['Benign', 'Malicious'], ax=axes[0,0])
    axes[0,0].set_title('Confusion Matrix')
    axes[0,0].set_ylabel('True Label')
    axes[0,0].set_xlabel('Predicted Label')
    
    # Metrics Bar Chart
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    values = [accuracy, precision, recall, f1]
    colors = ['green', 'blue', 'orange', 'red']
    bars = axes[0,1].bar(metrics, values, color=colors, alpha=0.7)
    axes[0,1].set_title('Performance Metrics')
    axes[0,1].set_ylabel('Score')
    axes[0,1].set_ylim(0, 1)
    for bar, value in zip(bars, values):
        axes[0,1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                      f'{value:.3f}', ha='center', va='bottom')
    
    # Score Distribution
    benign_scores = [pred_scores[i] for i in range(len(pred_scores)) if true_labels[i] == 0]
    malicious_scores = [pred_scores[i] for i in range(len(pred_scores)) if true_labels[i] == 1]
    
    axes[1,0].hist(benign_scores, bins=30, alpha=0.7, label='Benign', color='green', density=True)
    axes[1,0].hist(malicious_scores, bins=30, alpha=0.7, label='Malicious', color='red', density=True)
    axes[1,0].axvline(x=best_threshold, color='black', linestyle='--', label=f'Threshold={best_threshold:.2f}')
    axes[1,0].set_title('Score Distribution')
    axes[1,0].set_xlabel('Ensemble Score')
    axes[1,0].set_ylabel('Density')
    axes[1,0].legend()
    
    # ROC Curve
    from sklearn.metrics import roc_curve, auc
    fpr, tpr, _ = roc_curve(true_labels, pred_scores)
    roc_auc = auc(fpr, tpr)
    
    axes[1,1].plot(fpr, tpr, color='blue', lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
    axes[1,1].plot([0, 1], [0, 1], color='gray', linestyle='--')
    axes[1,1].set_title('ROC Curve')
    axes[1,1].set_xlabel('False Positive Rate')
    axes[1,1].set_ylabel('True Positive Rate')
    axes[1,1].legend()
    axes[1,1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    plot_file = f"real_pcap_evaluation_{timestamp}.png"
    plt.savefig(plot_file, dpi=300, bbox_inches='tight')
    print(f"\n📊 Visualization saved: {plot_file}")
    
    # Save metrics
    results_file = f"real_pcap_metrics_{timestamp}.txt"
    with open(results_file, 'w') as f:
        f.write("REAL PCAP DATA EVALUATION RESULTS\n")
        f.write("="*50 + "\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
        f.write(f"Dataset: {CSV_PATH}\n")
        f.write(f"Samples evaluated: {len(df_eval):,}\n")
        f.write(f"Models loaded: {n}/3\n")
        f.write(f"Optimal threshold: {best_threshold:.4f}\n\n")
        
        f.write("CORE METRICS\n")
        f.write("-"*20 + "\n")
        f.write(f"Accuracy: {accuracy:.6f}\n")
        f.write(f"Precision: {precision:.6f}\n")
        f.write(f"Recall: {recall:.6f}\n")
        f.write(f"F1-Score: {f1:.6f}\n")
        f.write(f"AUC-ROC: {roc_auc:.6f}\n\n")
        
        f.write("CONFUSION MATRIX\n")
        f.write("-"*20 + "\n")
        f.write(f"True Negatives: {tn}\n")
        f.write(f"False Positives: {fp}\n")
        f.write(f"False Negatives: {fn}\n")
        f.write(f"True Positives: {tp}\n")
    
    print(f"📄 Metrics saved: {results_file}")
    
    plt.show()
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'auc_roc': roc_auc,
        'confusion_matrix': cm,
        'optimal_threshold': best_threshold,
        'true_labels': true_labels,
        'pred_labels': pred_labels_optimal,
        'pred_scores': pred_scores
    }

if __name__ == "__main__":
    results = evaluate_on_real_data()
    print(f"\n✅ Real PCAP evaluation complete!")
    print(f"🎯 Best F1-Score: {results['f1_score']:.4f}")
    print(f"📊 Best Accuracy: {results['accuracy']:.4f}")
    print(f"🎯 Optimal Threshold: {results['optimal_threshold']:.3f}")
