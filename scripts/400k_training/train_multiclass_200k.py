#!/usr/bin/env python3
"""Train Multi-Class TCN Model on Balanced 200K Dataset

Changes implemented:
1. Multi-Class Architecture (7 classes: Benign + 6 attack types)
2. Cost-Sensitive Learning (weighted classes)
3. Turbo-Charged Training Parameters
"""

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import logging
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Device configuration
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
logger.info(f"🖥️ Using device: {device}")

class TemporalBlock(nn.Module):
    """Temporal block for TCN architecture"""
    def __init__(self, in_channels, out_channels, kernel_size, dilation, dropout=0.2):
        super().__init__()
        padding = (kernel_size - 1) * dilation // 2
        
        self.conv = nn.Conv1d(in_channels, out_channels, kernel_size,
                           padding=padding, dilation=dilation)
        self.chomp = nn.ConstantPad1d((-padding, 0), 0)  # Remove future padding
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(dropout)
        
    def forward(self, x):
        out = self.conv(x)
        out = self.chomp(out)
        out = self.relu(out)
        out = self.dropout(out)
        return out

class MultiClassTCN(nn.Module):
    """Multi-Class Temporal Convolutional Network"""
    def __init__(self, input_channels=2, num_classes=7, channels=[32, 64, 64], 
                 kernel_size=3, dropout=0.2):
        super().__init__()
        
        # TCN layers
        layers = []
        in_ch = input_channels
        for i, out_ch in enumerate(channels):
            layers.append(TemporalBlock(in_ch, out_ch, kernel_size, 
                                    dilation=2**i, dropout=dropout))
            in_ch = out_ch
        
        self.tcn = nn.Sequential(*layers)
        
        # Classification head
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(channels[-1], 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_classes)  # 7 classes with softmax
        )
        
    def forward(self, x):
        # x shape: (batch_size, input_channels, sequence_length)
        features = self.tcn(x)
        pooled = self.global_pool(features)
        logits = self.classifier(pooled)
        return logits

class FlowDataset(Dataset):
    """Custom dataset for flow features"""
    def __init__(self, features, labels):
        self.features = torch.FloatTensor(features)
        self.labels = torch.LongTensor(labels)
        
    def __len__(self):
        return len(self.features)
    
    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]

def map_attack_type(pcap_file):
    """Map pcap file names to attack type labels"""
    if pd.isna(pcap_file):
        return "unknown"
    
    pcap_file = str(pcap_file).lower()
    
    if "normal" in pcap_file or "benign" in pcap_file:
        return "benign"
    elif "dos" in pcap_file or "ddos" in pcap_file:
        return "dos"
    elif "brute" in pcap_file or "bruteforce" in pcap_file:
        return "brute_force"
    elif "infiltration" in pcap_file:
        return "infiltration"
    elif "botnet" in pcap_file:
        return "botnet"
    elif "web" in pcap_file or "sql" in pcap_file or "xss" in pcap_file:
        return "web_attack"
    elif "scan" in pcap_file or "portscan" in pcap_file:
        return "port_scan"
    else:
        return "unknown"

def prepare_data():
    """Load and prepare the balanced 200K dataset"""
    logger.info("📊 Loading balanced 200K dataset...")
    
    # Load the balanced dataset
    data_path = Path("data/processed/balanced_train_200k_v2.csv")
    if not data_path.exists():
        logger.error(f"❌ Dataset not found: {data_path}")
        return None, None, None, None
    
    df = pd.read_csv(data_path)
    logger.info(f"✅ Loaded {len(df):,} flows")
    
    # Map attack types
    logger.info("🏷️ Mapping attack types...")
    df['attack_type'] = df['pcap_file'].apply(map_attack_type)
    
    # Remove unknown types
    df = df[df['attack_type'] != 'unknown'].copy()
    logger.info(f"📝 After removing unknown: {len(df):,} flows")
    
    # Encode labels to integers (0-6)
    label_encoder = LabelEncoder()
    df['label_encoded'] = label_encoder.fit_transform(df['attack_type'])
    
    # Show label mapping
    logger.info("🔤 Label encoding:")
    for i, class_name in enumerate(label_encoder.classes_):
        weight = 2.0 if class_name in ['infiltration', 'botnet'] else 1.0
        logger.info(f"   {i}: {class_name} (weight: {weight})")
    
    # Extract SPLT features (packet lengths and inter-arrival times)
    splt_len_cols = [f'splt_len_{i}' for i in range(1, 21)]
    splt_iat_cols = [f'splt_iat_{i}' for i in range(1, 21)]
    
    # Handle missing SPLT features
    for col in splt_len_cols + splt_iat_cols:
        if col not in df.columns:
            df[col] = 0.0
        df[col] = df[col].fillna(0.0)
    
    # Create sequence data (lengths + IATs)
    splt_sequences = []
    labels = []
    
    for _, row in df.iterrows():
        # Get packet lengths and IATs
        lengths = row[splt_len_cols].values.astype(np.float32)
        iats = row[splt_iat_cols].values.astype(np.float32)
        
        # Create 2-channel sequence: [lengths, iats]
        sequence = np.stack([lengths, iats], axis=0)  # Shape: (2, 20)
        splt_sequences.append(sequence)
        labels.append(row['label_encoded'])
    
    X = np.array(splt_sequences)  # Shape: (n_samples, 2, 20)
    y = np.array(labels)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info(f"📊 Data split:")
    logger.info(f"   Training: {len(X_train):,} samples")
    logger.info(f"   Testing: {len(X_test):,} samples")
    
    return X_train, X_test, y_train, y_test, label_encoder

def calculate_class_weights(label_encoder):
    """Calculate class weights for cost-sensitive learning"""
    class_names = label_encoder.classes_
    weights = {}
    
    for i, class_name in enumerate(class_names):
        # Higher weight for sneaky attacks
        if class_name in ['infiltration', 'botnet']:
            weights[i] = 2.0
        else:
            weights[i] = 1.0
    
    return weights

def train_model():
    """Train the multi-class TCN model"""
    logger.info("🚀 Starting multi-class TCN training...")
    
    # Prepare data
    result = prepare_data()
    if result[0] is None:
        return
    
    X_train, X_test, y_train, y_test, label_encoder = result
    
    # Calculate class weights
    class_weights = calculate_class_weights(label_encoder)
    logger.info(f"⚖️ Class weights: {class_weights}")
    
    # Create datasets and dataloaders
    train_dataset = FlowDataset(X_train, y_train)
    test_dataset = FlowDataset(X_test, y_test)
    
    # Turbo-charged parameters
    BATCH_SIZE = 1024
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)
    
    # Initialize model
    model = MultiClassTCN(input_channels=2, num_classes=7).to(device)
    logger.info(f"🧠 Model initialized with {sum(p.numel() for p in model.parameters()):,} parameters")
    
    # Loss function with class weights
    class_weights_tensor = torch.FloatTensor([class_weights[i] for i in range(7)]).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights_tensor)
    
    # Optimizer with turbo-charged learning rate
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    # Learning rate scheduler
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=3, factor=0.5)
    
    # Training metrics
    train_losses = []
    test_losses = []
    train_accuracies = []
    test_accuracies = []
    
    best_test_acc = 0.0
    patience_counter = 0
    max_patience = 5
    
    logger.info("🏃‍♂️ Starting training loop...")
    start_time = time.time()
    
    for epoch in range(10):  # Turbo-charged: 10 epochs
        # Training phase
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        for batch_features, batch_labels in train_loader:
            batch_features = batch_features.to(device)
            batch_labels = batch_labels.to(device)
            
            optimizer.zero_grad()
            outputs = model(batch_features)
            loss = criterion(outputs, batch_labels)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            train_total += batch_labels.size(0)
            train_correct += (predicted == batch_labels).sum().item()
        
        # Testing phase
        model.eval()
        test_loss = 0.0
        test_correct = 0
        test_total = 0
        
        with torch.no_grad():
            for batch_features, batch_labels in test_loader:
                batch_features = batch_features.to(device)
                batch_labels = batch_labels.to(device)
                
                outputs = model(batch_features)
                loss = criterion(outputs, batch_labels)
                
                test_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)
                test_total += batch_labels.size(0)
                test_correct += (predicted == batch_labels).sum().item()
        
        # Calculate metrics
        train_acc = 100 * train_correct / train_total
        test_acc = 100 * test_correct / test_total
        
        train_losses.append(train_loss / len(train_loader))
        test_losses.append(test_loss / len(test_loader))
        train_accuracies.append(train_acc)
        test_accuracies.append(test_acc)
        
        # Learning rate scheduling
        scheduler.step(test_loss)
        
        # Early stopping logic
        if test_acc > best_test_acc:
            best_test_acc = test_acc
            patience_counter = 0
            # Save best model
            torch.save(model.state_dict(), 'models/multiclass_tcn_200k.pth')
            logger.info(f"💾 New best model saved! Test accuracy: {test_acc:.2f}%")
        else:
            patience_counter += 1
        
        logger.info(f"Epoch {epoch+1}/10:")
        logger.info(f"  Train Loss: {train_loss/len(train_loader):.4f}, Train Acc: {train_acc:.2f}%")
        logger.info(f"  Test Loss: {test_loss/len(test_loader):.4f}, Test Acc: {test_acc:.2f}%")
        logger.info(f"  Learning Rate: {optimizer.param_groups[0]['lr']:.6f}")
        
        # Early stopping
        if patience_counter >= max_patience:
            logger.info(f"⏹️ Early stopping triggered! No improvement for {max_patience} epochs.")
            break
    
    training_time = time.time() - start_time
    logger.info(f"⏱️ Training completed in {training_time:.2f} seconds")
    
    # Final evaluation
    logger.info("📊 Final evaluation...")
    model.load_state_dict(torch.load('models/multiclass_tcn_200k.pth'))
    model.eval()
    
    all_predictions = []
    all_labels = []
    
    with torch.no_grad():
        for batch_features, batch_labels in test_loader:
            batch_features = batch_features.to(device)
            outputs = model(batch_features)
            _, predicted = torch.max(outputs, 1)
            
            all_predictions.extend(predicted.cpu().numpy())
            all_labels.extend(batch_labels.cpu().numpy())
    
    # Classification report
    logger.info("\n📋 Classification Report:")
    print(classification_report(all_labels, all_predictions, 
                            target_names=label_encoder.classes_, digits=4))
    
    # Save label encoder
    import joblib
    joblib.dump(label_encoder, 'models/multiclass_label_encoder.joblib')
    
    # Plot training history
    plt.figure(figsize=(15, 5))
    
    plt.subplot(1, 3, 1)
    plt.plot(train_losses, label='Train Loss')
    plt.plot(test_losses, label='Test Loss')
    plt.title('Training and Test Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    
    plt.subplot(1, 3, 2)
    plt.plot(train_accuracies, label='Train Accuracy')
    plt.plot(test_accuracies, label='Test Accuracy')
    plt.title('Training and Test Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy (%)')
    plt.legend()
    
    plt.subplot(1, 3, 3)
    cm = confusion_matrix(all_labels, all_predictions)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=label_encoder.classes_, 
                yticklabels=label_encoder.classes_)
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    
    plt.tight_layout()
    plt.savefig('models/multiclass_training_results.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    logger.info("🎉 Multi-class TCN training completed!")
    logger.info(f"📁 Model saved: models/multiclass_tcn_200k.pth")
    logger.info(f"📁 Label encoder: models/multiclass_label_encoder.joblib")
    logger.info(f"📁 Results plot: models/multiclass_training_results.png")
    logger.info(f"🏆 Best test accuracy: {best_test_acc:.2f}%")

if __name__ == "__main__":
    # Create models directory if it doesn't exist
    Path("models").mkdir(exist_ok=True)
    
    train_model()
