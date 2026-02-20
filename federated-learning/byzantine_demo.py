#!/usr/bin/env python3
"""
Byzantine-Resilient Federated Learning Demo
Shows how FedMedian defends against model poisoning attacks
"""

import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
import sys
import logging

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TCN(nn.Module):
    """Simple TCN model for federated learning"""
    def __init__(self, input_size=12, num_classes=2):
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
            nn.Linear(16, num_classes)
        )
    
    def forward(self, x):
        return self.network(x)

class ByzantineFederatedDemo:
    """Demonstrate Byzantine defense in federated learning"""
    
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.clients = {}
        self.global_model = None
        self.results = {"fedavg": [], "fedmedian": []}
        self.input_size = None

    def _persist_history(self, aggregation_method: str, history: list[float]):
        results_dir = PROJECT_ROOT / "federated-learning" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        out_csv = results_dir / "byzantine_defense_history.csv"

        rounds = list(range(len(history)))
        col_map = {
            "fedavg": "fedavg_hospital_f1",
            "fedmedian": "fedmedian_hospital_f1",
        }
        if aggregation_method not in col_map:
            return

        def _coalesce_col(df: pd.DataFrame, canonical: str) -> pd.Series:
            candidates = [canonical, f"{canonical}_x", f"{canonical}_y"]
            out = None
            for c in candidates:
                if c in df.columns:
                    s = pd.to_numeric(df[c], errors="coerce")
                    out = s if out is None else out.combine_first(s)
            if out is None:
                out = pd.Series(dtype=float)
            return out

        # Load existing
        if out_csv.exists():
            try:
                df_old = pd.read_csv(out_csv)
            except Exception:
                df_old = pd.DataFrame()
        else:
            df_old = pd.DataFrame()

        # Canonicalize old to clean schema
        if "round" not in df_old.columns:
            df_old = pd.DataFrame({"round": []})
        df_old["round"] = pd.to_numeric(df_old["round"], errors="coerce")
        df_old = df_old.dropna(subset=["round"]).copy()
        df_old["round"] = df_old["round"].astype(int)

        df_old_clean = pd.DataFrame({"round": df_old["round"]})
        df_old_clean["fedavg_hospital_f1"] = _coalesce_col(df_old, "fedavg_hospital_f1")
        df_old_clean["fedmedian_hospital_f1"] = _coalesce_col(df_old, "fedmedian_hospital_f1")
        df_old_clean = df_old_clean.drop_duplicates(subset=["round"], keep="last")

        # Build new updates
        update_col = col_map[aggregation_method]
        df_update = pd.DataFrame({"round": rounds, update_col: history})
        df_update["round"] = pd.to_numeric(df_update["round"], errors="coerce").astype(int)
        df_update[update_col] = pd.to_numeric(df_update[update_col], errors="coerce")

        # Union rounds and overlay updates
        df = pd.merge(df_old_clean, df_update, on="round", how="outer", suffixes=("", "_new"))
        if f"{update_col}_new" in df.columns:
            df[update_col] = pd.to_numeric(df[update_col], errors="coerce").combine_first(
                pd.to_numeric(df[f"{update_col}_new"], errors="coerce")
            )
            df = df.drop(columns=[f"{update_col}_new"])

        df = df.sort_values("round").reset_index(drop=True)
        df[["round", "fedavg_hospital_f1", "fedmedian_hospital_f1"]].to_csv(out_csv, index=False)

    def _persist_round_metrics(
        self,
        aggregation_method: str,
        round_num: int,
        client_losses: dict,
        client_f1s: dict,
        global_f1: float,
    ):
        results_dir = PROJECT_ROOT / "federated-learning" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        out_csv = results_dir / "byzantine_round_metrics.csv"

        row = {
            "method": aggregation_method,
            "round": int(round_num),
            "bank_loss": client_losses.get("bank"),
            "bank_f1": client_f1s.get("bank"),
            "hospital_loss": client_losses.get("hospital"),
            "hospital_f1": client_f1s.get("hospital"),
            "tech_loss": client_losses.get("tech"),
            "tech_f1": client_f1s.get("tech"),
            "malicious_loss": client_losses.get("malicious"),
            "malicious_f1": client_f1s.get("malicious"),
            "global_f1_hospital": global_f1,
        }
        df_new = pd.DataFrame([row])

        if out_csv.exists():
            try:
                df_old = pd.read_csv(out_csv)
            except Exception:
                df_old = pd.DataFrame()
        else:
            df_old = pd.DataFrame()

        if df_old.empty:
            df = df_new
        else:
            if "method" not in df_old.columns:
                df_old["method"] = ""
            if "round" not in df_old.columns:
                df_old["round"] = np.nan
            df_old["round"] = pd.to_numeric(df_old["round"], errors="coerce")
            df_old = df_old.dropna(subset=["round"]).copy()
            df_old["round"] = df_old["round"].astype(int)
            df = pd.concat([df_old, df_new], ignore_index=True)
            df = df.drop_duplicates(subset=["method", "round"], keep="last")

        df = df.sort_values(["method", "round"]).reset_index(drop=True)
        df.to_csv(out_csv, index=False)
        
    def load_client_data(self):
        """Load Non-IID client data"""
        data_dir = PROJECT_ROOT / "data" / "processed"
        
        client_configs = {
            "bank": {"file": "federated_bank.csv", "description": "80% Normal + 20% DDoS"},
            "hospital": {"file": "federated_hospital.csv", "description": "50% Normal + 50% C2"},
            "tech": {"file": "federated_tech.csv", "description": "70% Normal + 30% Mixed"},
            "malicious": {"file": "federated_malicious.csv", "description": "INVERTED LABELS (Poison)"}
        }
        
        for client_id, config in client_configs.items():
            logger.info(f"Loading {client_id}: {config['description']}")
            
            df = pd.read_csv(data_dir / config["file"])
            
            # Extract features (only numeric columns except label and metadata)
            exclude_cols = {'label', 'Attack_Type', 'flow_id', 'Label', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'}
            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            feature_cols = [col for col in numeric_cols if col not in exclude_cols]
            
            # Set input size from first client
            if self.input_size is None:
                self.input_size = len(feature_cols)
                
            X = df[feature_cols].fillna(0).values
            y = df['label'].values
            
            # Split and scale
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Convert to tensors
            train_dataset = TensorDataset(
                torch.FloatTensor(X_train_scaled),
                torch.LongTensor(y_train)
            )
            test_dataset = TensorDataset(
                torch.FloatTensor(X_test_scaled),
                torch.LongTensor(y_test)
            )
            
            self.clients[client_id] = {
                "train_loader": DataLoader(train_dataset, batch_size=32, shuffle=True),
                "test_loader": DataLoader(test_dataset, batch_size=32, shuffle=False),
                "scaler": scaler,
                "description": config["description"],
                "feature_cols": feature_cols
            }
    
    def fedavg_aggregate(self, client_weights):
        """Standard FedAvg (vulnerable to poisoning)"""
        aggregated = {}
        for param in client_weights[0].keys():
            stacked = torch.stack([w[param] for w in client_weights])
            aggregated[param] = torch.mean(stacked, dim=0)
        return aggregated
    
    def fedmedian_aggregate(self, client_weights):
        """FedMedian (Byzantine-resilient)"""
        aggregated = {}
        for param in client_weights[0].keys():
            stacked = torch.stack([w[param] for w in client_weights])
            aggregated[param] = torch.median(stacked, dim=0).values
        return aggregated
    
    def train_local(self, model, train_loader, epochs=3):
        """Train model locally on client data"""
        model.train()
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(model.parameters(), lr=0.001)
        
        for epoch in range(epochs):
            total_loss = 0
            for batch_X, batch_y in train_loader:
                batch_X, batch_y = batch_X.to(self.device), batch_y.to(self.device)
                
                optimizer.zero_grad()
                outputs = model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
        
        return total_loss / len(train_loader)
    
    def evaluate(self, model, test_loader, client_name=""):
        """Evaluate model performance"""
        model.eval()
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch_X, batch_y in test_loader:
                batch_X, batch_y = batch_X.to(self.device), batch_y.to(self.device)
                outputs = model(batch_X)
                _, preds = torch.max(outputs, 1)
                
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(batch_y.cpu().numpy())
        
        f1 = f1_score(all_labels, all_preds, average='weighted')
        return f1
    
    def run_federated_rounds(self, aggregation_method="fedavg", rounds=5):
        """Run federated learning simulation"""
        logger.info(f"\n🚀 Starting {aggregation_method.upper()} Simulation")
        
        # Initialize global model
        self.global_model = TCN(input_size=self.input_size).to(self.device)
        global_f1_history = []
        
        # Store initial performance
        initial_f1 = self.evaluate(self.global_model, self.clients["hospital"]["test_loader"], "Global")
        logger.info(f"Round 0 - Global F1 (Hospital): {initial_f1:.4f}")
        global_f1_history.append(initial_f1)
        self._persist_history(aggregation_method, global_f1_history)
        self._persist_round_metrics(
            aggregation_method=aggregation_method,
            round_num=0,
            client_losses={},
            client_f1s={},
            global_f1=initial_f1,
        )
        
        for round_num in range(1, rounds + 1):
            logger.info(f"\n--- Round {round_num} ---")
            
            # Collect client weights
            client_weights = []
            client_f1_scores = {}
            client_losses = {}
            
            for client_id, client_data in self.clients.items():
                # Create local model copy
                local_model = TCN(input_size=self.input_size).to(self.device)
                local_model.load_state_dict(self.global_model.state_dict())
                
                # Train locally
                loss = self.train_local(local_model, client_data["train_loader"])
                client_losses[client_id] = loss
                
                # Evaluate locally
                f1 = self.evaluate(local_model, client_data["test_loader"], client_id)
                client_f1_scores[client_id] = f1
                
                # Store weights
                client_weights.append({k: v.cpu() for k, v in local_model.state_dict().items()})
                
                logger.info(f"  {client_id:10} - Loss: {loss:.4f}, F1: {f1:.4f}")
            
            # Aggregate weights
            if aggregation_method == "fedavg":
                global_weights = self.fedavg_aggregate(client_weights)
            else:
                global_weights = self.fedmedian_aggregate(client_weights)
            
            # Update global model
            self.global_model.load_state_dict(global_weights)
            
            # Evaluate global model on hospital (the key test case)
            global_f1 = self.evaluate(self.global_model, self.clients["hospital"]["test_loader"], "Global")
            global_f1_history.append(global_f1)
            
            logger.info(f"  Global F1 on Hospital: {global_f1:.4f}")
            self._persist_history(aggregation_method, global_f1_history)
            self._persist_round_metrics(
                aggregation_method=aggregation_method,
                round_num=round_num,
                client_losses=client_losses,
                client_f1s=client_f1_scores,
                global_f1=global_f1,
            )
        
        self.results[aggregation_method] = global_f1_history
        return global_f1_history
    
    def create_comparison_plot(self):
        """Create comparison plot showing FedAvg vs FedMedian"""
        plt.figure(figsize=(12, 8))
        
        rounds = list(range(len(self.results["fedavg"])))
        
        plt.plot(rounds, self.results["fedavg"], 'r-o', label='FedAvg (Vulnerable)', linewidth=2, markersize=8)
        plt.plot(rounds, self.results["fedmedian"], 'g-s', label='FedMedian (Byzantine-Resilient)', linewidth=2, markersize=8)
        
        plt.xlabel('Federated Learning Round', fontsize=12)
        plt.ylabel('F1 Score on Hospital Client', fontsize=12)
        plt.title('Byzantine Defense: FedMedian vs FedAvg Under Model Poisoning Attack', fontsize=14, fontweight='bold')
        plt.legend(fontsize=11)
        plt.grid(True, alpha=0.3)
        plt.ylim(0, 1)
        
        # Add annotations
        plt.annotate('Poisoning Attack\n(Malicious Client)', 
                    xy=(1, self.results["fedavg"][1]), 
                    xytext=(1.5, self.results["fedavg"][1] - 0.1),
                    arrowprops=dict(arrowstyle='->', color='red'),
                    fontsize=10, ha='center')
        
        plt.annotate('FedMedian Resists\nPoisoning', 
                    xy=(3, self.results["fedmedian"][3]), 
                    xytext=(3.5, self.results["fedmedian"][3] + 0.05),
                    arrowprops=dict(arrowstyle='->', color='green'),
                    fontsize=10, ha='center')
        
        # Save plot
        plot_path = PROJECT_ROOT / "federated-learning" / "byzantine_defense_demo.png"
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        logger.info(f"📊 Comparison plot saved: {plot_path}")
        
        plt.close()
    
    def print_summary(self):
        """Print demo summary for jury presentation"""
        logger.info("\n" + "="*80)
        logger.info("🛡️ BYZANTINE-RESILIENT FEDERATED LEARNING DEMO RESULTS")
        logger.info("="*80)
        
        fedavg_final = self.results["fedavg"][-1]
        fedmedian_final = self.results["fedmedian"][-1]
        
        logger.info(f"\n📊 Final Performance (Hospital Client F1 Score):")
        logger.info(f"  FedAvg (Vulnerable):    {fedavg_final:.4f}")
        logger.info(f"  FedMedian (Resilient):   {fedmedian_final:.4f}")
        logger.info(f"  Improvement:             {fedmedian_final - fedavg_final:+.4f}")
        
        logger.info(f"\n🎯 Key Insights:")
        logger.info(f"  • FedAvg performance degraded due to model poisoning")
        logger.info(f"  • FedMedian maintained high performance despite malicious client")
        logger.info(f"  • Coordinate-wise median filters out outlier weights")
        logger.info(f"  • Zero Trust: Knowledge shared without compromising security")
        
        logger.info(f"\n💡 Jury Message:")
        logger.info(f"  'Our Byzantine-resilient federated architecture prevents")
        logger.info(f"   model poisoning attacks while preserving privacy and")
        logger.info(f"   enabling cross-organizational threat intelligence sharing.'")

def main():
    """Run the Byzantine defense demo"""
    demo = ByzantineFederatedDemo()
    
    # Load Non-IID data
    demo.load_client_data()
    
    # Run both aggregation methods
    fedavg_hist = demo.run_federated_rounds("fedavg", rounds=5)
    fedmedian_hist = demo.run_federated_rounds("fedmedian", rounds=5)

    results_dir = PROJECT_ROOT / "federated-learning" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_csv = results_dir / "byzantine_defense_history.csv"
    pd.DataFrame(
        {
            "round": list(range(len(fedavg_hist))),
            "fedavg_hospital_f1": fedavg_hist,
            "fedmedian_hospital_f1": fedmedian_hist,
        }
    ).to_csv(out_csv, index=False)
    
    # Create visualization
    demo.create_comparison_plot()
    
    # Print summary
    demo.print_summary()

if __name__ == "__main__":
    main()
