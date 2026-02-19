#!/usr/bin/env python3
"""FedAvg Baseline Simulation (Non-IID)

Outputs a per-round comparison for the jury "money shot":
- Hospital isolated model F1 (trained only on hospital data)
- Federated global model F1 evaluated on hospital test set

Input CSVs are created by `federated-learning/create_silo_data.py`:
- data/processed/federated_bank.csv
- data/processed/federated_hospital.csv
- data/processed/federated_tech.csv

Writes results to:
- federated-learning/results/fedavg_hospital_moneyshot.csv
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset


PROJECT_ROOT = Path(__file__).parent.parent


class TCN(nn.Module):
    def __init__(self, input_size: int = 12, num_classes: int = 2):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


@dataclass
class ClientData:
    train_loader: DataLoader
    test_loader: DataLoader


def _select_feature_columns(df: pd.DataFrame) -> List[str]:
    exclude = {"label", "Attack_Type", "flow_id", "Label", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"}
    # Only keep numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    return [c for c in numeric_cols if c not in exclude]


def _load_client_csv(path: Path, test_size: float, seed: int, batch_size: int) -> Tuple[ClientData, List[str]]:
    df = pd.read_csv(path)
    if "label" not in df.columns:
        if "Label" in df.columns:
            df["label"] = df["Label"].astype(int)
        else:
            raise ValueError(f"Missing label column in {path}")

    feature_cols = _select_feature_columns(df)
    X = df[feature_cols].fillna(0).values
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=seed,
        stratify=y if len(np.unique(y)) > 1 else None,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    train_ds = TensorDataset(torch.FloatTensor(X_train_scaled), torch.LongTensor(y_train))
    test_ds = TensorDataset(torch.FloatTensor(X_test_scaled), torch.LongTensor(y_test))

    return (
        ClientData(
            train_loader=DataLoader(train_ds, batch_size=batch_size, shuffle=True),
            test_loader=DataLoader(test_ds, batch_size=batch_size, shuffle=False),
        ),
        feature_cols,
    )


def train_one_epoch(model: nn.Module, loader: DataLoader, device: torch.device, lr: float) -> float:
    model.train()
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    total_loss = 0.0
    n_batches = 0

    for xb, yb in loader:
        xb = xb.to(device)
        yb = yb.to(device)

        optimizer.zero_grad()
        logits = model(xb)
        loss = criterion(logits, yb)
        loss.backward()
        optimizer.step()

        total_loss += float(loss.item())
        n_batches += 1

    return total_loss / max(n_batches, 1)


def evaluate_f1(model: nn.Module, loader: DataLoader, device: torch.device) -> float:
    model.eval()
    preds: List[int] = []
    labels: List[int] = []

    with torch.no_grad():
        for xb, yb in loader:
            xb = xb.to(device)
            yb = yb.to(device)
            logits = model(xb)
            yhat = torch.argmax(logits, dim=1)
            preds.extend(yhat.cpu().numpy().tolist())
            labels.extend(yb.cpu().numpy().tolist())

    return float(f1_score(labels, preds, average="weighted"))


def evaluate_cross_domain(model: nn.Module, test_loaders: Dict[str, DataLoader], device: torch.device) -> Dict[str, float]:
    """Test model on different client test sets to show cross-domain learning"""
    results = {}
    for client_name, loader in test_loaders.items():
        f1 = evaluate_f1(model, loader, device)
        results[client_name] = f1
    return results


def average_weights(state_dicts: Iterable[Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
    state_dicts = list(state_dicts)
    if not state_dicts:
        raise ValueError("No client weights to aggregate")

    out: Dict[str, torch.Tensor] = {}
    keys = state_dicts[0].keys()

    for k in keys:
        stacked = torch.stack([sd[k] for sd in state_dicts], dim=0)
        out[k] = torch.mean(stacked, dim=0)

    return out


def run(rounds: int, local_epochs: int, lr: float, batch_size: int, seed: int) -> Path:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    processed_dir = PROJECT_ROOT / "data" / "processed"
    bank_path = processed_dir / "federated_bank.csv"
    hospital_path = processed_dir / "federated_hospital.csv"
    tech_path = processed_dir / "federated_tech.csv"

    if not bank_path.exists() or not hospital_path.exists() or not tech_path.exists():
        raise FileNotFoundError(
            "Missing one or more silo CSVs. Run `python federated-learning/create_silo_data.py` first."
        )

    bank, bank_cols = _load_client_csv(bank_path, test_size=0.2, seed=seed, batch_size=batch_size)
    hospital, hospital_cols = _load_client_csv(hospital_path, test_size=0.2, seed=seed, batch_size=batch_size)
    tech, tech_cols = _load_client_csv(tech_path, test_size=0.2, seed=seed, batch_size=batch_size)

    feature_dim = min(len(bank_cols), len(hospital_cols), len(tech_cols))

    global_model = TCN(input_size=feature_dim).to(device)

    moneyshot_rows = []
    
    # Store all test loaders for cross-domain evaluation
    all_test_loaders = {
        "bank_on_bank": bank.test_loader,
        "bank_on_hospital": hospital.test_loader,  # Bank model on C2 data (should fail initially)
        "bank_on_tech": tech.test_loader,
        "hospital_on_hospital": hospital.test_loader,
        "hospital_on_bank": bank.test_loader,  # Hospital model on DDoS data (should fail initially)
        "hospital_on_tech": tech.test_loader,
        "tech_on_tech": tech.test_loader,
        "tech_on_bank": bank.test_loader,
        "tech_on_hospital": hospital.test_loader,
        "global_on_all": {
            "bank": bank.test_loader,
            "hospital": hospital.test_loader, 
            "tech": tech.test_loader
        }
    }

    for r in range(rounds + 1):
        # Test each client's isolated model on other domains (cross-domain failure cases)
        cross_domain_results = {}
        
        # Test Bank model on Hospital data (C2 - should fail initially)
        bank_isolated = TCN(input_size=feature_dim).to(device)
        bank_isolated.load_state_dict(global_model.state_dict())
        for _ in range(local_epochs):
            train_one_epoch(bank_isolated, bank.train_loader, device=device, lr=lr)
        bank_on_hospital_f1 = evaluate_f1(bank_isolated, hospital.test_loader, device=device)
        
        # Test Hospital model on Bank data (DDoS - should fail initially) 
        hospital_isolated = TCN(input_size=feature_dim).to(device)
        hospital_isolated.load_state_dict(global_model.state_dict())
        for _ in range(local_epochs):
            train_one_epoch(hospital_isolated, hospital.train_loader, device=device, lr=lr)
        hospital_on_bank_f1 = evaluate_f1(hospital_isolated, bank.test_loader, device=device)
        
        # Test global model on all domains
        global_results = evaluate_cross_domain(global_model, all_test_loaders["global_on_all"], device=device)
        
        moneyshot_rows.append({
            "round": r,
            "bank_isolated_f1": evaluate_f1(bank_isolated, bank.test_loader, device=device),
            "bank_on_hospital_f1": bank_on_hospital_f1,  # Cross-domain: Bank on C2
            "hospital_isolated_f1": evaluate_f1(hospital_isolated, hospital.test_loader, device=device),
            "hospital_on_bank_f1": hospital_on_bank_f1,  # Cross-domain: Hospital on DDoS
            "global_on_bank_f1": global_results["bank"],
            "global_on_hospital_f1": global_results["hospital"],
            "global_on_tech_f1": global_results["tech"],
        })

        if r == rounds:
            break

        client_state_dicts = []
        for client in (bank, hospital, tech):
            local = TCN(input_size=feature_dim).to(device)
            local.load_state_dict(global_model.state_dict())

            for _ in range(local_epochs):
                train_one_epoch(local, client.train_loader, device=device, lr=lr)

            client_state_dicts.append({k: v.detach().cpu() for k, v in local.state_dict().items()})

        new_weights = average_weights(client_state_dicts)
        global_model.load_state_dict(new_weights)

    results_dir = PROJECT_ROOT / "federated-learning" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    out_path = results_dir / "fedavg_hospital_moneyshot.csv"
    pd.DataFrame(moneyshot_rows).to_csv(out_path, index=False)

    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="FedAvg baseline simulation for ZeroTrustAI")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--local-epochs", type=int, default=1)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--seed", type=int, default=42)

    args = parser.parse_args()

    out_path = run(
        rounds=args.rounds,
        local_epochs=args.local_epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        seed=args.seed,
    )

    print(f"✅ Wrote money shot results: {out_path}")


if __name__ == "__main__":
    main()
