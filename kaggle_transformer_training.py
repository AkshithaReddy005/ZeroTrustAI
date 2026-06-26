# ============================================================
# ZeroTrust-AI: Kaggle Training Notebook
# 1D-Transformer + Autoencoder + GAN + MLP Hierarchical Fuser
#
# ESTIMATED TRAINING TIME (Kaggle GPU T4 x2):
#   Phase 1 - Transformer Lens:    ~15-20 minutes
#   Phase 2 - Score Map Gen:       ~3-5  minutes
#   Phase 3 - MLP Meta-Fuser:      ~2-3  minutes
#   TOTAL:                         ~20-28 minutes
#
# FINAL OUTPUT FILES:
#   network_transformer_lens.pth        -> HuggingFace / local deploy
#   hierarchical_meta_fuser_gan.joblib  -> HuggingFace / local deploy
#   autoencoder.pth                     -> Upload to Kaggle (already trained)
#   gan_discriminator_lens.pth          -> Upload to Kaggle (already trained)
#   scaler_len.joblib                   -> Required for inference
#   scaler_iat.joblib                   -> Required for inference
# ============================================================

# ============================================================
# CELL 1: Install dependencies
# ============================================================
# !pip install scikit-learn joblib pandas numpy torch -q

# ============================================================
# CELL 2: Imports
# ============================================================
import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset, random_split
from sklearn.preprocessing import RobustScaler
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (classification_report, roc_auc_score,
                             confusion_matrix, accuracy_score)
from sklearn.model_selection import train_test_split
import joblib
import warnings
warnings.filterwarnings("ignore")

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {DEVICE}")
print(f"GPUs available: {torch.cuda.device_count()}")

# ============================================================
# CELL 3: Load and Prepare Dataset
# Upload final_balanced_240k_fixed.csv to Kaggle first
# Path: /kaggle/input/<your-dataset-name>/final_balanced_240k_fixed.csv
# ============================================================
DATASET_PATH = "/kaggle/input/zerotrust-dataset/final_balanced_240k_fixed.csv"

print("Loading dataset...")
df = pd.read_csv(DATASET_PATH)
print(f"Dataset shape: {df.shape}")
print(f"Label distribution:\n{df['label'].value_counts()}")

len_cols = [f"splt_len_{i}" for i in range(1, 21)]
iat_cols = [f"splt_iat_{i}" for i in range(1, 21)]

len_features = df[len_cols].values.astype(np.float32)
iat_features = df[iat_cols].values.astype(np.float32)
labels       = df["label"].values.astype(np.float32)

print("Scaling features...")
scaler_len = RobustScaler()
scaler_iat = RobustScaler()
len_features = scaler_len.fit_transform(len_features)
iat_features = scaler_iat.fit_transform(iat_features)
joblib.dump(scaler_len, "scaler_len.joblib")
joblib.dump(scaler_iat, "scaler_iat.joblib")
print("Scalers saved.")

# Stack into [N, 20, 2]  (20 timesteps, 2 features per step)
X_sequences = np.stack([len_features, iat_features], axis=-1)
print(f"Sequence tensor shape: {X_sequences.shape}")

X_tensor = torch.FloatTensor(X_sequences)
y_tensor  = torch.FloatTensor(labels).view(-1, 1)

dataset    = TensorDataset(X_tensor, y_tensor)
train_size = int(0.85 * len(dataset))
val_size   = len(dataset) - train_size
train_ds, val_ds = random_split(dataset, [train_size, val_size])

train_loader = DataLoader(train_ds, batch_size=512, shuffle=True,  num_workers=2, pin_memory=True)
val_loader   = DataLoader(val_ds,   batch_size=512, shuffle=False, num_workers=2, pin_memory=True)
print(f"Train: {train_size} | Val: {val_size}")

# ============================================================
# CELL 4: 1D-Transformer Lens Model Definition
# ============================================================
class NetworkTransformerLens(nn.Module):
    """
    1D Transformer Encoder that treats each packet event as a token.
    Input shape: [batch, 20, 2]  (20 timesteps, len+iat per step)
    """
    def __init__(self, feature_dim=2, embedding_dim=64, nhead=4, num_layers=3):
        super().__init__()
        self.input_projection = nn.Linear(feature_dim, embedding_dim)
        self.pos_encoder       = nn.Parameter(torch.randn(1, 20, embedding_dim))
        self.dropout           = nn.Dropout(0.1)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embedding_dim,
            nhead=nhead,
            dim_feedforward=128,
            dropout=0.1,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        self.classifier = nn.Sequential(
            nn.Linear(embedding_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        x = self.input_projection(x) + self.pos_encoder
        x = self.dropout(x)
        x = self.transformer(x)
        x = x.mean(dim=1)
        return self.classifier(x)

# ============================================================
# CELL 5: Train Transformer Lens  (~15-20 min on T4 x2)
# ============================================================
def train_transformer(model, train_loader, val_loader, epochs=20, lr=3e-4):
    model     = nn.DataParallel(model).to(DEVICE)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    criterion = nn.BCELoss()
    best_val_auc = 0.0

    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        for Xb, yb in train_loader:
            Xb, yb = Xb.to(DEVICE), yb.to(DEVICE)
            optimizer.zero_grad()
            preds = model(Xb)
            loss  = criterion(preds, yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            train_loss += loss.item()

        model.eval()
        all_preds, all_labels = [], []
        with torch.no_grad():
            for Xb, yb in val_loader:
                p = model(Xb.to(DEVICE)).cpu().numpy()
                all_preds.extend(p.flatten())
                all_labels.extend(yb.numpy().flatten())

        val_auc = roc_auc_score(all_labels, all_preds)
        val_acc = accuracy_score(all_labels, (np.array(all_preds) > 0.5).astype(int))
        avg_loss = train_loss / len(train_loader)
        scheduler.step()
        print(f"Epoch {epoch:02d}/{epochs} | Loss: {avg_loss:.4f} | Val AUC: {val_auc:.4f} | Val Acc: {val_acc:.4f}")

        if val_auc > best_val_auc:
            best_val_auc = val_auc
            torch.save(model.module.state_dict(), "network_transformer_lens.pth")
            print(f"  Best model saved (AUC={best_val_auc:.4f})")

    print(f"\nTransformer training complete. Best Val AUC: {best_val_auc:.4f}")
    return model

transformer_model = NetworkTransformerLens(feature_dim=2, embedding_dim=64, nhead=4, num_layers=3)
print("Starting Transformer training...")
transformer_model = train_transformer(transformer_model, train_loader, val_loader, epochs=20)

# ============================================================
# CELL 6: Autoencoder Definition (load pretrained)
# Upload autoencoder.pth to Kaggle before running
# ============================================================
class Autoencoder(nn.Module):
    def __init__(self, input_dim=40):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32), nn.ReLU(),
            nn.Linear(32, 16),        nn.ReLU(),
            nn.Linear(16, 8)
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),        nn.ReLU(),
            nn.Linear(16, 32),       nn.ReLU(),
            nn.Linear(32, input_dim)
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

    def get_score(self, x):
        recon = self.forward(x)
        return torch.mean((x - recon) ** 2, dim=1, keepdim=True)

AE_PATH  = "/kaggle/input/zerotrust-models/autoencoder.pth"
ae_model = Autoencoder(input_dim=40).to(DEVICE)
ae_model.load_state_dict(torch.load(AE_PATH, map_location=DEVICE))
ae_model.eval()
print("Autoencoder loaded.")

X_flat        = np.concatenate([len_features, iat_features], axis=1)
X_flat_tensor = torch.FloatTensor(X_flat)

# ============================================================
# CELL 7: GAN Discriminator Definition (load pretrained)
# Upload gan_discriminator_lens.pth to Kaggle before running
# ============================================================
class GANDiscriminator(nn.Module):
    def __init__(self, input_dim=40):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64), nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            nn.Linear(64, 32),        nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            nn.Linear(32, 1),         nn.Sigmoid()
        )

    def forward(self, x):
        return self.net(x)

GAN_PATH  = "/kaggle/input/zerotrust-models/gan_discriminator_lens.pth"
gan_model = GANDiscriminator(input_dim=40).to(DEVICE)
gan_model.load_state_dict(torch.load(GAN_PATH, map_location=DEVICE))
gan_model.eval()
print("GAN Discriminator loaded.")

# ============================================================
# CELL 8: Generate Score Map  (~3-5 minutes)
# ============================================================
print("\nGenerating score map from all 3 lenses...")
BATCH = 1024

def get_scores_in_batches(model, tensor, device):
    scores = []
    loader = DataLoader(TensorDataset(tensor), batch_size=BATCH, shuffle=False, num_workers=2)
    with torch.no_grad():
        for (Xb,) in loader:
            out = model(Xb.to(device))
            scores.extend(out.cpu().numpy().flatten())
    return np.array(scores)

best_transformer = NetworkTransformerLens(feature_dim=2, embedding_dim=64, nhead=4, num_layers=3).to(DEVICE)
best_transformer.load_state_dict(torch.load("network_transformer_lens.pth", map_location=DEVICE))
best_transformer.eval()

transformer_scores = get_scores_in_batches(best_transformer, X_tensor, DEVICE)
ae_scores          = get_scores_in_batches(ae_model, X_flat_tensor, DEVICE)
gan_scores         = get_scores_in_batches(gan_model, X_flat_tensor, DEVICE)

print(f"Transformer: min={transformer_scores.min():.4f} max={transformer_scores.max():.4f}")
print(f"AE:          min={ae_scores.min():.4f}          max={ae_scores.max():.4f}")
print(f"GAN:         min={gan_scores.min():.4f}         max={gan_scores.max():.4f}")

fusion_df = pd.DataFrame({
    "transformer_score": transformer_scores,
    "ae_score":          ae_scores,
    "gan_score":         gan_scores,
    "label":             labels
})
fusion_df.to_csv("kaggle_fusion.csv", index=False)
print(f"\nFusion score map saved: kaggle_fusion.csv  shape={fusion_df.shape}")
print(fusion_df.describe())

# ============================================================
# CELL 9: Train Stage-2 MLP Meta-Fuser  (~2-3 minutes)
# ============================================================
print("\nTraining Stage-2 MLP Meta-Fuser...")
X_fusion = fusion_df[["transformer_score", "ae_score", "gan_score"]].values
y_fusion = fusion_df["label"].values

X_tr, X_te, y_tr, y_te = train_test_split(
    X_fusion, y_fusion, test_size=0.15, random_state=42, stratify=y_fusion
)

mlp_fuser = MLPClassifier(
    hidden_layer_sizes=(64, 32, 16),
    activation="relu",
    solver="adam",
    alpha=1e-4,
    learning_rate_init=1e-3,
    max_iter=300,
    early_stopping=True,
    validation_fraction=0.1,
    n_iter_no_change=15,
    random_state=42,
    verbose=True
)
mlp_fuser.fit(X_tr, y_tr)
joblib.dump(mlp_fuser, "hierarchical_meta_fuser_gan.joblib")
print("\nMLP Meta-Fuser saved: hierarchical_meta_fuser_gan.joblib")

# ============================================================
# CELL 10: Final Evaluation
# ============================================================
y_pred_proba = mlp_fuser.predict_proba(X_te)[:, 1]
y_pred       = (y_pred_proba > 0.40).astype(int)

print("\n" + "=" * 60)
print("FINAL HIERARCHICAL META-FUSER RESULTS")
print("=" * 60)
print(classification_report(y_te, y_pred, target_names=["Benign", "Malicious"]))
print(f"ROC-AUC Score : {roc_auc_score(y_te, y_pred_proba):.4f}")
print(f"Accuracy      : {accuracy_score(y_te, y_pred):.4f}")
cm = confusion_matrix(y_te, y_pred)
print(f"\nConfusion Matrix:\n{cm}")
print(f"  True Negatives  : {cm[0,0]}")
print(f"  False Positives : {cm[0,1]}")
print(f"  False Negatives : {cm[1,0]}")
print(f"  True Positives  : {cm[1,1]}")

# ============================================================
# CELL 11: List output files
# ============================================================
print("\n" + "=" * 60)
print("OUTPUT FILES - Download from Kaggle Output Tab")
print("=" * 60)
output_files = [
    ("network_transformer_lens.pth",       "Transformer Lens weights"),
    ("hierarchical_meta_fuser_gan.joblib", "Stage-2 MLP Meta-Fuser"),
    ("scaler_len.joblib",                  "Packet length RobustScaler"),
    ("scaler_iat.joblib",                  "Packet IAT RobustScaler"),
    ("kaggle_fusion.csv",                  "Fusion score map (optional)"),
]
for fname, desc in output_files:
    exists = os.path.exists(fname)
    print(f"  {'OK' if exists else 'MISSING':<8} {fname:<45} ({desc})")

print("\nDeploy these files to:")
print("  Local  -> c2_ddos/scripts/models/")
print("  Cloud  -> HuggingFace Model Hub")
print()
print("HuggingFace Deployment Steps:")
print("  1. pip install huggingface_hub")
print("  2. huggingface-cli login")
print("  3. from huggingface_hub import HfApi")
print("     api = HfApi()")
print("     api.upload_folder(")
print('         folder_path="./models",')
print('         repo_id="YourUsername/ZeroTrust-AI",')
print('         repo_type="model"')
print("     )")
