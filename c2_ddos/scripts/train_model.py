#!/usr/bin/env python3
"""
Training script for C2 vs DDoS detection model
"""

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SPLTDataset(Dataset):
    """Dataset for SPLT features"""
    
    def __init__(self, features, labels):
        self.features = torch.FloatTensor(features)
        self.labels = torch.FloatTensor(labels)
    
    def __len__(self):
        return len(self.features)
    
    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]

class TCN(nn.Module):
    """Temporal Convolutional Network for SPLT analysis"""
    
    def __init__(self, input_dim=53, hidden_dim=128, num_layers=3, dropout=0.3):
        super(TCN, self).__init__()
        
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # Feature extraction layers
        self.feature_layers = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        # Temporal layers
        self.temporal_layers = nn.ModuleList([
            nn.Conv1d(hidden_dim, hidden_dim, kernel_size=3, padding=1)
            for _ in range(num_layers)
        ])
        
        # Classification layer
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        # Feature extraction
        x = self.feature_layers(x)
        
        # Reshape for temporal layers
        x = x.unsqueeze(1)  # Add sequence dimension
        
        # Temporal convolution
        for conv_layer in self.temporal_layers:
            x = torch.relu(conv_layer(x))
            x = torch.nn.functional.max_pool1d(x, kernel_size=2)
        
        # Global pooling
        x = torch.nn.functional.adaptive_avg_pool1d(x, 1).squeeze(-1)
        
        # Classification
        output = self.classifier(x)
        return output

def prepare_data(data_path):
    """Prepare training data"""
    logger.info(f"📂 Loading data from {data_path}")
    
    df = pd.read_csv(data_path)
    logger.info(f"📊 Loaded {len(df)} samples")
    
    # Get SPLT features
    splt_cols = [col for col in df.columns if 'splt_' in col]
    basic_cols = ['duration', 'protocol', 'total_packets', 'total_bytes']
    
    # Filter available columns
    available_splt = [col for col in splt_cols if col in df.columns]
    available_basic = [col for col in basic_cols if col in df.columns]
    
    feature_cols = available_splt + available_basic
    logger.info(f"🔢 Using {len(feature_cols)} features: {len(available_splt)} SPLT + {len(available_basic)} basic")
    
    # Prepare features and labels
    X = df[feature_cols].fillna(0.001).values
    y = df['label'].values
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    logger.info(f"📊 Train: {len(X_train)}, Test: {len(X_test)}")
    logger.info(f"📈 Train distribution: {np.bincount(y_train)}")
    logger.info(f"📈 Test distribution: {np.bincount(y_test)}")
    
    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, feature_cols

def train_model(data_path, models_dir="models"):
    """Train the TCN model"""
    logger.info("🚀 Starting C2DDoS Model Training")
    logger.info("=" * 50)
    
    # Create models directory
    Path(models_dir).mkdir(exist_ok=True)
    
    # Prepare data
    X_train, X_test, y_train, y_test, scaler, feature_cols = prepare_data(data_path)
    
    # Save scaler and feature info
    joblib.dump(scaler, Path(models_dir) / "scaler.joblib")
    joblib.dump(feature_cols, Path(models_dir) / "feature_cols.joblib")
    
    # Create datasets
    train_dataset = SPLTDataset(X_train, y_train)
    test_dataset = SPLTDataset(X_test, y_test)
    
    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)
    
    # Initialize model
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = TCN(input_dim=len(feature_cols)).to(device)
    
    # Training setup
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    num_epochs = 50
    
    logger.info(f"🎯 Training on device: {device}")
    logger.info(f"📊 Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Training loop
    for epoch in range(num_epochs):
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        for batch_features, batch_labels in train_loader:
            batch_features, batch_labels = batch_features.to(device), batch_labels.to(device)
            
            optimizer.zero_grad()
            outputs = model(batch_features)
            loss = criterion(outputs.squeeze(), batch_labels)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            predicted = (outputs.squeeze() > 0.5).float()
            train_correct += (predicted == batch_labels).sum().item()
            train_total += batch_labels.size(0)
        
        # Validation
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            for batch_features, batch_labels in test_loader:
                batch_features, batch_labels = batch_features.to(device), batch_labels.to(device)
                outputs = model(batch_features)
                loss = criterion(outputs.squeeze(), batch_labels)
                
                val_loss += loss.item()
                predicted = (outputs.squeeze() > 0.5).float()
                val_correct += (predicted == batch_labels).sum().item()
                val_total += batch_labels.size(0)
        
        # Calculate metrics
        train_acc = train_correct / train_total
        val_acc = val_correct / val_total
        
        logger.info(f"Epoch {epoch+1}/{num_epochs}: "
                   f"Train Loss: {train_loss/len(train_loader):.4f}, Train Acc: {train_acc:.4f}, "
                   f"Val Loss: {val_loss/len(test_loader):.4f}, Val Acc: {val_acc:.4f}")
    
    # Final evaluation
    model.eval()
    all_predictions = []
    all_labels = []
    
    with torch.no_grad():
        for batch_features, batch_labels in test_loader:
            batch_features = batch_features.to(device)
            outputs = model(batch_features)
            predicted = (outputs.squeeze() > 0.5).float()
            
            all_predictions.extend(predicted.cpu().numpy())
            all_labels.extend(batch_labels.cpu().numpy())
    
    # Print final metrics
    logger.info("\n🎯 FINAL RESULTS")
    logger.info("=" * 50)
    logger.info(f"Test Accuracy: {np.mean(np.array(all_predictions) == np.array(all_labels)):.4f}")
    logger.info("\nClassification Report:")
    logger.info(classification_report(all_labels, all_predictions, target_names=['Normal', 'Malicious']))
    
    # Save model
    torch.save(model.state_dict(), Path(models_dir) / "tcn_model.pth")
    logger.info(f"✅ Model saved to {models_dir}/tcn_model.pth")
    
    return model, scaler, feature_cols

def main():
    """Main function"""
    data_path = "data/processed/final_balanced_240k.csv"
    models_dir = "models"
    
    model, scaler, feature_cols = train_model(data_path, models_dir)
    
    logger.info("🎉 Training completed successfully!")

if __name__ == "__main__":
    main()
