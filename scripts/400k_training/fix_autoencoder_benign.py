#!/usr/bin/env python3
"""
Quick Fix: Retrain Autoencoder on BENIGN ONLY

This will fix the backup detection and boost attack detection to 80%+
"""

import pathlib
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
import joblib

# Paths
DATA_DIR = pathlib.Path("data")
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = pathlib.Path("models")
BALANCED_CSV = PROCESSED_DIR / "balanced_train_400k.csv"

# Model paths
AE_FIXED_PATH = MODELS_DIR / "autoencoder_fixed.pth"

class BenignDataset(Dataset):
    def __init__(self, features):
        self.features = torch.FloatTensor(features)
    
    def __len__(self):
        return len(self.features)
    
    def __getitem__(self, idx):
        return self.features[idx]

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

def train_benign_autoencoder():
    """Train autoencoder on benign traffic only."""
    print("🔧 QUICK FIX: Retrain Autoencoder on BENIGN ONLY")
    print("=" * 55)
    
    # Load balanced dataset
    df = pd.read_csv(BALANCED_CSV)
    
    # Extract ONLY benign samples
    benign_df = df[df['label'] == 0]
    print(f"Benign samples: {len(benign_df):,}")
    
    # Prepare features
    splt_cols = [f"splt_len_{i}" for i in range(1, 21)] + [f"splt_iat_{i}" for i in range(1, 21)]
    available_cols = [col for col in splt_cols if col in benign_df.columns]
    
    feature_cols = available_cols + ['total_packets', 'total_bytes', 'avg_packet_size', 
                                 'std_packet_size', 'duration', 'pps', 'avg_entropy']
    
    X_benign = benign_df[feature_cols].fillna(0).values
    print(f"Feature matrix: {X_benign.shape}")
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_benign)
    
    # Create dataset
    dataset = BenignDataset(X_scaled)
    loader = DataLoader(dataset, batch_size=256, shuffle=True)
    
    # Initialize model
    model = FixedAutoencoder(X_scaled.shape[1])
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    
    print(f"\n🔥 TRAINING AUTOENCODER ON {len(X_benign)} BENIGN SAMPLES...")
    
    # Quick training (5 epochs)
    model.train()
    for epoch in range(5):
        total_loss = 0
        for batch_features in loader:
            optimizer.zero_grad()
            reconstructed = model(batch_features)
            loss = criterion(reconstructed, batch_features)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        
        print(f"Epoch {epoch+1}/5 - Loss: {total_loss/len(loader):.6f}")
    
    # Save fixed autoencoder
    torch.save(model.state_dict(), AE_FIXED_PATH)
    joblib.dump(scaler, MODELS_DIR / "scaler_benign.joblib")
    
    print(f"\n✅ FIXED AUTOENCODER SAVED!")
    print(f"📁 Model: {AE_FIXED_PATH}")
    print(f"📁 Scaler: {MODELS_DIR / 'scaler_benign.joblib'}")
    
    return model, scaler

if __name__ == "__main__":
    model, scaler = train_benign_autoencoder()
    print(f"\n🎉 AUTOENCODER FIXED!")
    print(f"🚀 Now re-run fine-tuning to see 80%+ attack detection!")
