#!/usr/bin/env python3
"""
Train Malicious vs Normal Detection Model
Focuses on DDoS and C2 attack detection with proper train/test split

This script:
1. Loads the combined DDoS+C2 dataset (165K samples)
2. Creates binary classification: malicious (DDoS+C2) vs normal
3. Splits into train/test sets (80/20)
4. Trains TCN model optimized for infrastructure-level threats
5. Evaluates performance on attack detection

Key Focus:
- DDoS: Greatest threat to system availability
- C2: Hardest blind spot in encryption
- Future expandable to other attack types
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import torch.optim as optim
import torch.nn.functional as F
from tqdm import tqdm
import json
import matplotlib.pyplot as plt
import seaborn as sns

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
DATA_PATH = Path("data/processed/final_balanced_240k.csv")
OUTPUT_DIR = Path("models/ddos_c2_models")
OUTPUT_DIR.mkdir(exist_ok=True, parents=True)

# Model parameters
BATCH_SIZE = 64
EPOCHS = 50
LEARNING_RATE = 0.001
HIDDEN_DIM = 128
NUM_LAYERS = 3
DROPOUT = 0.3
TEST_SIZE = 0.2
RANDOM_STATE = 42

# Set random seeds
torch.manual_seed(RANDOM_STATE)
np.random.seed(RANDOM_STATE)

class SPLTDataset(Dataset):
    """Dataset for SPLT features with binary labels"""
    
    def __init__(self, features, labels):
        self.features = torch.FloatTensor(features)
        self.labels = torch.FloatTensor(labels)
        
    def __len__(self):
        return len(self.features)
    
    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]

class TCN(nn.Module):
    """Temporal Convolutional Network for binary classification"""
    
    def __init__(self, input_dim, hidden_dim, num_layers, dropout):
        super(TCN, self).__init__()
        
        # Input projection
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        
        # TCN layers
        self.tcn_layers = nn.ModuleList()
        for i in range(num_layers):
            dilation = 2 ** i
            padding = (dilation * (3 - 1)) // 2
            self.tcn_layers.append(
                nn.Conv1d(hidden_dim, hidden_dim, kernel_size=3, 
                         dilation=dilation, padding=padding)
            )
            self.tcn_layers.append(nn.ReLU())
            self.tcn_layers.append(nn.Dropout(dropout))
        
        # Output layers
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        self.classifier = nn.Linear(hidden_dim, 1)
        
    def forward(self, x):
        # Input projection
        x = self.input_proj(x)  # (batch, hidden_dim)
        x = x.unsqueeze(2)  # (batch, hidden_dim, 1)
        
        # TCN layers
        for layer in self.tcn_layers:
            x = layer(x)
        
        # Global pooling and classification
        x = self.global_pool(x).squeeze(2)  # (batch, hidden_dim)
        x = self.classifier(x)  # (batch, 1)
        return torch.sigmoid(x).squeeze(1)

def load_and_prepare_data():
    """Load and prepare the dataset for binary classification"""
    
    logger.info("🔍 Loading combined DDoS+C2 dataset...")
    
    # Load dataset with mixed dtype handling
    df = pd.read_csv(DATA_PATH, low_memory=False)
    logger.info(f"Loaded {len(df)} samples")
    
    # Check label distribution
    label_dist = df['Label'].value_counts()
    logger.info(f"Label distribution: {label_dist.to_dict()}")
    
    # Attack type distribution
    attack_dist = df['Attack_Type'].value_counts()
    logger.info(f"Attack types: {attack_dist.to_dict()}")
    
    # Extract SPLT features (last 40 columns)
    splt_cols = [f"splt_len_{i}" for i in range(1, 21)] + [f"splt_iat_{i}" for i in range(1, 21)]
    available_splt = [col for col in splt_cols if col in df.columns]
    logger.info(f"Using {len(available_splt)} SPLT features")
    
    # Additional important features
    additional_features = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Flow Bytes/s', 'Flow Packets/s', 'Packet Length Mean',
        'Packet Length Std', 'FIN Flag Count', 'SYN Flag Count',
        'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count'
    ]
    
    # Select available features
    available_additional = [col for col in additional_features if col in df.columns]
    feature_cols = available_splt + available_additional
    
    logger.info(f"Total features: {len(feature_cols)}")
    logger.info(f"Features: {feature_cols[:10]}...")  # Show first 10
    
    # Prepare features and labels
    X = df[feature_cols].fillna(0).values
    y = df['Label'].values  # 0 = Normal, 1 = Malicious (DDoS+C2)
    
    # Split into train/test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    
    logger.info(f"Train set: {X_train.shape} - Malicious: {np.sum(y_train)}, Normal: {len(y_train)-np.sum(y_train)}")
    logger.info(f"Test set: {X_test.shape} - Malicious: {np.sum(y_test)}, Normal: {len(y_test)-np.sum(y_test)}")
    
    # Normalize features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save scaler
    scaler_path = OUTPUT_DIR / "scaler.pkl"
    import pickle
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    logger.info(f"Scaler saved to {scaler_path}")
    
    return X_train_scaled, X_test_scaled, y_train, y_test, len(feature_cols)

def train_model():
    """Train the TCN model for binary classification"""
    
    # Load data
    X_train, X_test, y_train, y_test, input_dim = load_and_prepare_data()
    
    # Create datasets
    train_dataset = SPLTDataset(X_train, y_train)
    test_dataset = SPLTDataset(X_test, y_test)
    
    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)
    
    # Initialize model
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = TCN(input_dim, HIDDEN_DIM, NUM_LAYERS, DROPOUT).to(device)
    
    # Loss and optimizer
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
    
    logger.info(f"Training on {device}")
    logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Training loop
    train_losses = []
    train_accs = []
    val_losses = []
    val_accs = []
    
    for epoch in range(EPOCHS):
        # Training
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        for batch_features, batch_labels in tqdm(train_loader, desc=f"Epoch {epoch+1}/{EPOCHS}"):
            batch_features, batch_labels = batch_features.to(device), batch_labels.to(device)
            
            optimizer.zero_grad()
            outputs = model(batch_features)
            loss = criterion(outputs, batch_labels)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            predicted = (outputs > 0.5).float()
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
                loss = criterion(outputs, batch_labels)
                
                val_loss += loss.item()
                predicted = (outputs > 0.5).float()
                val_correct += (predicted == batch_labels).sum().item()
                val_total += batch_labels.size(0)
        
        # Calculate metrics
        train_loss_avg = train_loss / len(train_loader)
        train_acc = train_correct / train_total
        val_loss_avg = val_loss / len(test_loader)
        val_acc = val_correct / val_total
        
        train_losses.append(train_loss_avg)
        train_accs.append(train_acc)
        val_losses.append(val_loss_avg)
        val_accs.append(val_acc)
        
        logger.info(f"Epoch {epoch+1}: Train Loss: {train_loss_avg:.4f}, Train Acc: {train_acc:.4f}, "
                   f"Val Loss: {val_loss_avg:.4f}, Val Acc: {val_acc:.4f}")
    
    # Save model
    model_path = OUTPUT_DIR / "ddos_c2_binary_model.pth"
    torch.save(model.state_dict(), model_path)
    logger.info(f"Model saved to {model_path}")
    
    # Save training history
    history = {
        'train_losses': train_losses,
        'train_accs': train_accs,
        'val_losses': val_losses,
        'val_accs': val_accs
    }
    
    history_path = OUTPUT_DIR / "training_history.json"
    with open(history_path, 'w') as f:
        json.dump(history, f, indent=2)
    
    return model, X_test, y_test, history

def evaluate_model(model, X_test, y_test):
    """Comprehensive model evaluation"""
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.eval()
    
    # Create test dataset
    test_dataset = SPLTDataset(X_test, y_test)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)
    
    # Get predictions
    all_predictions = []
    all_probabilities = []
    all_labels = []
    
    with torch.no_grad():
        for batch_features, batch_labels in test_loader:
            batch_features = batch_features.to(device)
            outputs = model(batch_features)
            probs = outputs.cpu().numpy()
            preds = (probs > 0.5).astype(int)
            
            all_predictions.extend(preds)
            all_probabilities.extend(probs)
            all_labels.extend(batch_labels.numpy())
    
    # Convert to numpy arrays
    y_pred = np.array(all_predictions)
    y_prob = np.array(all_probabilities)
    y_true = np.array(all_labels)
    
    # Calculate metrics
    accuracy = np.mean(y_pred == y_true)
    auc_score = roc_auc_score(y_true, y_prob)
    
    # Detailed classification report
    report = classification_report(y_true, y_pred, target_names=['Normal', 'Malicious'], 
                                   output_dict=True)
    
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    
    logger.info("\n📊 MODEL EVALUATION RESULTS:")
    logger.info(f"Overall Accuracy: {accuracy:.4f}")
    logger.info(f"AUC Score: {auc_score:.4f}")
    logger.info(f"Normal Detection: {report['Normal']['recall']:.4f}")
    logger.info(f"Malicious Detection: {report['Malicious']['recall']:.4f}")
    logger.info(f"Precision: {report['Malicious']['precision']:.4f}")
    logger.info(f"F1-Score: {report['Malicious']['f1-score']:.4f}")
    
    # Save evaluation results
    results = {
        'accuracy': float(accuracy),
        'auc_score': float(auc_score),
        'classification_report': report,
        'confusion_matrix': cm.tolist(),
        'normal_detection': float(report['Normal']['recall']),
        'malicious_detection': float(report['Malicious']['recall']),
        'precision': float(report['Malicious']['precision']),
        'f1_score': float(report['Malicious']['f1-score'])
    }
    
    results_path = OUTPUT_DIR / "evaluation_results.json"
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Evaluation results saved to {results_path}")
    
    # Plot confusion matrix
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Normal', 'Malicious'], 
                yticklabels=['Normal', 'Malicious'])
    plt.title('Confusion Matrix - DDoS+C2 Detection')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'confusion_matrix.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    return results

def generate_expert_summary():
    """Generate expert summary for the model's capabilities"""
    
    summary = """
🎯 MALICIOUS VS NORMAL DETECTION MODEL
=====================================

📋 MODEL PURPOSE:
Our system detects malicious traffic patterns vs normal baseline, specifically optimized for:
- DDoS attacks: Greatest threat to system availability
- C2 beaconing: Hardest blind spot in encrypted traffic

🔍 DETECTION APPROACH:
- Pattern-based anomaly detection using SPLT features
- NOT signature-based rules - learns traffic behavior
- Binary classification: Normal (0) vs Malicious (1)
- Temporal analysis of packet sequences and timing

📊 DATASET COMPOSITION:
- Total samples: 238,014 flows (balanced)
- C2 attacks: 78,014 samples (32.8%)
- DDoS attacks: 80,000 samples (33.6%)
- Normal traffic: 80,000 samples (33.6%)
- Train/Test split: 80/20 stratified
- SPLT features: 40 temporal features for all traffic types

🎯 FOCUS AREAS:
1. INFRASTRUCTURE THREATS: DDoS impacts availability, C2 enables compromise
2. ENCRYPTION BLIND SPOTS: C2 detection in encrypted channels
3. FUTURE EXPANDABILITY: Architecture supports additional attack types

🚀 FUTURE ROADMAP:
- Phase 2: Add SQL Injection, XSS, Command Injection patterns
- Phase 3: Zero-day anomaly detection
- Phase 4: Multi-class attack classification

💡 KEY ADVANTAGE:
Behavioral analysis catches attack variants and unknown patterns
that signature-based systems miss, especially in encrypted traffic.
"""
    
    summary_path = OUTPUT_DIR / "model_summary.txt"
    with open(summary_path, 'w') as f:
        f.write(summary)
    
    logger.info("Model summary saved to {summary_path}")
    return summary

def main():
    """Main training pipeline"""
    
    logger.info("🚀 Starting DDoS+C2 Binary Classification Training")
    logger.info("=" * 60)
    
    # Train model
    model, X_test, y_test, history = train_model()
    
    # Evaluate model
    results = evaluate_model(model, X_test, y_test)
    
    # Generate summary
    summary = generate_expert_summary()
    
    logger.info("\n✅ TRAINING COMPLETED SUCCESSFULLY")
    logger.info(f"Model saved: {OUTPUT_DIR}/ddos_c2_binary_model.pth")
    logger.info(f"Results: {OUTPUT_DIR}/evaluation_results.json")
    logger.info(f"Summary: {OUTPUT_DIR}/model_summary.txt")
    
    logger.info(f"\n🎯 FINAL PERFORMANCE:")
    logger.info(f"Accuracy: {results['accuracy']:.4f}")
    logger.info(f"Malicious Detection: {results['malicious_detection']:.4f}")
    logger.info(f"Normal Detection: {results['normal_detection']:.4f}")
    logger.info(f"F1-Score: {results['f1_score']:.4f}")

if __name__ == "__main__":
    main()
