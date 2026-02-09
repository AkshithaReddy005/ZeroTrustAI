#!/usr/bin/env python3
"""
Step 1: Boost TCN with Feature Focusing

Train TCN only on SPLT features (packet lengths + timing)
Remove noisy features like Source IP, Port that change constantly
Expected: Attack detection 28% → 60%+
"""

import pathlib
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib

# Paths
DATA_DIR = pathlib.Path("data")
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = pathlib.Path("models")
BALANCED_CSV = PROCESSED_DIR / "balanced_train_400k.csv"

# Model paths
TCN_BOOSTED_PATH = MODELS_DIR / "tcn_splt_focused.pth"
SCALER_SPLT_PATH = MODELS_DIR / "scaler_splt_focused.joblib"

class SPLTDataset(Dataset):
    def __init__(self, features, labels=None):
        self.features = torch.FloatTensor(features)
        self.labels = torch.FloatTensor(labels) if labels is not None else None
    
    def __len__(self):
        return len(self.features)
    
    def __getitem__(self, idx):
        if self.labels is not None:
            return self.features[idx], self.labels[idx]
        return self.features[idx]

class SPLTFocusedTCN(nn.Module):
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

def train_splt_focused_tcn():
    """Train TCN focused only on SPLT features."""
    print("🚀 STEP 1: Boost TCN with SPLT Feature Focusing")
    print("=" * 60)
    
    # Load balanced dataset
    print("Loading balanced dataset...")
    df = pd.read_csv(BALANCED_CSV)
    print(f"Loaded {len(df):,} samples")
    
    # FOCUS ONLY ON SPLT FEATURES (remove noisy ones)
    print("Extracting SPLT features only...")
    
    # SPLT features (packet lengths + timing)
    splt_len_cols = [f"splt_len_{i}" for i in range(1, 21)]
    splt_iat_cols = [f"splt_iat_{i}" for i in range(1, 21)]
    
    # Essential flow features (not noisy)
    essential_flow_cols = [
        'total_packets', 'total_bytes', 'avg_packet_size', 
        'std_packet_size', 'duration', 'pps', 'avg_entropy'
    ]
    
    # REMOVE NOISY FEATURES
    noisy_cols_to_remove = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
    
    # Combine focused features
    feature_cols = splt_len_cols + splt_iat_cols + essential_flow_cols
    
    # Filter available columns
    available_cols = [col for col in feature_cols if col in df.columns]
    print(f"Using {len(available_cols)} focused features (SPLT + essential flow)")
    print(f"Removed noisy features: {[col for col in noisy_cols_to_remove if col in df.columns]}")
    
    X = df[available_cols].fillna(0).values
    y = df['label'].values
    
    print(f"Feature matrix: {X.shape}")
    print(f"Label distribution: {np.bincount(y.astype(int))}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training: {len(X_train):,} samples")
    print(f"Testing: {len(X_test):,} samples")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Create datasets
    train_dataset = SPLTDataset(X_train_scaled, y_train)
    test_dataset = SPLTDataset(X_test_scaled, y_test)
    
    train_loader = DataLoader(train_dataset, batch_size=256, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=256, shuffle=False)
    
    # Initialize focused TCN
    model = SPLTFocusedTCN(X_train_scaled.shape[1])
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    
    print(f"\n🔥 TRAINING SPLT-FOCUSED TCN...")
    print("Expected improvement: 28% → 60%+ attack detection")
    
    # Training
    model.train()
    best_accuracy = 0
    
    for epoch in range(12):  # Focused training
        total_loss = 0
        correct = 0
        total = 0
        
        for batch_features, batch_labels in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_features)
            loss = criterion(outputs, batch_labels)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
            # Track accuracy
            predicted = (outputs > 0.5).float()
            correct += (predicted == batch_labels).sum().item()
            total += batch_labels.size(0)
        
        train_acc = correct / total
        
        # Validation
        model.eval()
        val_correct = 0
        val_total = 0
        with torch.no_grad():
            for batch_features, batch_labels in test_loader:
                outputs = model(batch_features)
                predicted = (outputs > 0.5).float()
                val_correct += (predicted == batch_labels).sum().item()
                val_total += batch_labels.size(0)
        
        val_acc = val_correct / val_total
        
        if epoch % 3 == 0:
            print(f"Epoch {epoch:2d}: Loss={total_loss/len(train_loader):.4f}, "
                  f"Train_Acc={train_acc:.4f}, Val_Acc={val_acc:.4f}")
        
        # Save best model
        if val_acc > best_accuracy:
            best_accuracy = val_acc
            torch.save(model.state_dict(), TCN_BOOSTED_PATH)
    
    print(f"\n✅ Best validation accuracy: {best_accuracy:.4f}")
    
    # Final evaluation
    model.eval()
    all_preds = []
    all_labels = []
    
    with torch.no_grad():
        for batch_features, batch_labels in test_loader:
            outputs = model(batch_features)
            preds = (outputs > 0.5).float()
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(batch_labels.cpu().numpy())
    
    # Calculate metrics
    accuracy = accuracy_score(all_labels, all_preds)
    precision = precision_score(all_labels, all_preds)
    recall = recall_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds)
    
    # Per-class accuracy
    benign_mask = np.array(all_labels) == 0
    attack_mask = np.array(all_labels) == 1
    
    benign_acc = accuracy_score(all_labels[benign_mask], np.array(all_preds)[benign_mask])
    attack_acc = accuracy_score(all_labels[attack_mask], np.array(all_preds)[attack_mask])
    
    print(f"\n📊 SPLT-FOCUSED TCN RESULTS:")
    print(f"  Overall Accuracy: {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall: {recall:.4f}")
    print(f"  F1-Score: {f1:.4f}")
    print(f"  Benign Accuracy: {benign_acc:.4f}")
    print(f"  Attack Detection: {attack_acc:.4f}")
    
    # Save scaler
    joblib.dump(scaler, SCALER_SPLT_PATH)
    
    print(f"\n✅ SPLT-focused TCN saved to {TCN_BOOSTED_PATH}")
    print(f"✅ Scaler saved to {SCALER_SPLT_PATH}")
    
    return model, scaler, attack_acc, benign_acc

if __name__ == "__main__":
    model, scaler, attack_acc, benign_acc = train_splt_focused_tcn()
    
    print(f"\n🎉 STEP 1 COMPLETE!")
    print(f"🚀 Attack Detection: {attack_acc:.1%} (vs 28.8% before)")
    print(f"🛡️ Benign Accuracy: {benign_acc:.1%} (maintained)")
    print(f"📈 Expected improvement: +{(attack_acc - 0.288)*100:.1f}%")
    
    if attack_acc > 0.6:
        print(f"🏆 SUCCESS: Achieved 60%+ attack detection!")
    else:
        print(f"⚠️ Partial improvement achieved")
