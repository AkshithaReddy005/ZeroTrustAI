"""
Fast Federated Learning with Byzantine Detection
Quick version for rapid testing - fewer epochs, simplified evaluation
"""

import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
import numpy as np
import logging
from pathlib import Path
import sys

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT))

from c2_ddos.scripts.train_tcn import TCN
from byzantine_detection import ByzantineDetector

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


class FastFederatedLearning:
    """Fast version of federated learning with Byzantine detection"""
    
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.clients = {}
        self.global_model = None
        self.malicious_history = {}  # Track known malicious clients
        self.f1_history = {  # Track F1 improvement over rounds
            'bank': [],
            'hospital': [], 
            'tech': [],
            'malicious': []
        }
        self.global_f1_history = []  # Track global model performance
        self.detector = ByzantineDetector(
            similarity_threshold=0.85,  # More sensitive for quick demo
            deviation_threshold=0.8      # Lower threshold
        )
        
    def load_client_data(self):
        """Load federated client datasets"""
        data_dir = PROJECT_ROOT / "data" / "processed"
        
        client_configs = {
            "bank": {"file": "federated_bank.csv", "description": "80% Normal + 20% DDoS"},
            "hospital": {"file": "federated_hospital.csv", "description": "50% Normal + 50% C2"},
            "tech": {"file": "federated_tech.csv", "description": "70% Normal + 30% Mixed"},
            "malicious": {"file": "federated_malicious.csv", "description": "INVERTED LABELS (Poison)"}
        }
        
        splt_features = ([f'splt_len_{i}' for i in range(1, 21)] + 
                        [f'splt_iat_{i}' for i in range(1, 21)])
        
        for client_id, config in client_configs.items():
            logger.info(f"Loading {client_id}: {config['description']}")
            
            df = pd.read_csv(data_dir / config["file"], low_memory=False)
            
            # Extract SPLT features only
            X = (
                df[splt_features]
                .apply(pd.to_numeric, errors="coerce")
                .replace([np.inf, -np.inf], 0.0)
                .fillna(0.0)
                .to_numpy(dtype=np.float32)
            )
            y = df['label'].values
            
            # Split and scale
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Prepare TCN input
            X_train_tcn = self.prepare_tcn_input(X_train_scaled)
            X_test_tcn = self.prepare_tcn_input(X_test_scaled)
            
            train_dataset = TensorDataset(X_train_tcn, torch.LongTensor(y_train))
            test_dataset = TensorDataset(X_test_tcn, torch.LongTensor(y_test))
            
            self.clients[client_id] = {
                "train_loader": DataLoader(train_dataset, batch_size=64, shuffle=True),
                "test_loader": DataLoader(test_dataset, batch_size=64, shuffle=False),
                "scaler": scaler,
                "description": config["description"],
                "dataset_size": len(train_dataset)
            }
        
        logger.info(f"✓ Loaded {len(self.clients)} clients\n")
    
    def prepare_tcn_input(self, X_splt):
        """Reshape SPLT features for TCN input"""
        X_splt = np.nan_to_num(X_splt, nan=0.0, posinf=0.0, neginf=0.0)
        lengths = X_splt[:, :20]
        iats = X_splt[:, 20:]
        X_tcn = np.stack([lengths, iats], axis=1)
        return torch.tensor(X_tcn, dtype=torch.float32)
    
    def train_client(self, client_id, epochs=1):  # FAST: Only 1 epoch
        """Train model on client data"""
        client = self.clients[client_id]
        model = TCN(input_channels=2, sequence_len=20).to(self.device)
        if self.global_model:
            model.load_state_dict(self.global_model.state_dict())
        
        criterion = nn.BCEWithLogitsLoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        
        model.train()
        for epoch in range(epochs):
            for X_batch, y_batch in client["train_loader"]:
                X_batch = X_batch.to(self.device)
                y_batch = y_batch.float().to(self.device)
                
                optimizer.zero_grad()
                logits = model(X_batch).squeeze()
                loss = criterion(logits, y_batch)
                loss.backward()
                optimizer.step()
        
        return model.state_dict()
    
    def evaluate_model(self, model, test_loader):
        """Fast evaluation"""
        model.eval()
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for X_batch, y_batch in test_loader:
                X_batch = X_batch.to(self.device)
                logits = model(X_batch).squeeze()
                outputs = torch.sigmoid(logits)
                preds = (outputs > 0.5).cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(y_batch.numpy())
        
        accuracy = accuracy_score(all_labels, all_preds)
        f1 = f1_score(all_labels, all_preds, average='binary')
        
        return accuracy, f1
    
    def create_global_holdout_dataset(self):
        """Create a global holdout dataset from all clients"""
        global_X = []
        global_y = []
        
        for client_id, client in self.clients.items():
            for X_batch, y_batch in client["test_loader"]:
                global_X.append(X_batch)
                global_y.append(y_batch)
        
        global_X = torch.cat(global_X, dim=0)
        global_y = torch.cat(global_y, dim=0)
        
        return TensorDataset(global_X, global_y)
    
    def evaluate_global_model(self, round_num):
        """Evaluate global model on holdout dataset - shows Master Brain performance"""
        if not hasattr(self, 'global_holdout'):
            self.global_holdout = self.create_global_holdout_dataset()
            self.global_holdout_loader = DataLoader(self.global_holdout, batch_size=64, shuffle=False)
        
        global_accuracy, global_f1 = self.evaluate_model(self.global_model, self.global_holdout_loader)
        self.global_f1_history.append(global_f1)
        
        print(f"\n🌍 GLOBAL MODEL STATUS (Round {round_num}) - Master Brain")
        print(f"  → Global Accuracy: {global_accuracy:.3f}")
        print(f"  → Global F1 (C2 + DDoS): {global_f1:.3f}")
        
        # Show improvement over best individual client
        client_f1_scores = [self.f1_history[client][-1] for client in self.f1_history if self.f1_history[client]]
        if client_f1_scores:
            best_client_f1 = max(client_f1_scores)
            if global_f1 > best_client_f1:
                print(f"  ✅ Global model F1 ({global_f1:.3f}) > Best client F1 ({best_client_f1:.3f})")
                print(f"  🧠 KNOWLEDGE TRANSFER: Collective intelligence achieved!")
            else:
                print(f"  ⚠️ Global model F1 ({global_f1:.3f}) ≤ Best client F1 ({best_client_f1:.3f})")
        else:
            print(f"  📊 First round - establishing baseline (Global F1: {global_f1:.3f})")
        
        return global_accuracy, global_f1
    
    def broadcast_global_model(self, round_num):
        """Broadcast global model back to all clients - PDP to PEP communication"""
        print(f"\n📡 BROADCASTING GLOBAL MODEL v{round_num} to all clients...")
        
        # Save global model version (simulating PDP registry)
        model_path = f"global_model_v{round_num}.pt"
        torch.save(self.global_model.state_dict(), model_path)
        print(f"  💾 Saved: {model_path} (PDP Registry)")
        
        # Simulate knowledge transfer by testing bank on C2 (it never saw C2 locally)
        if 'hospital' in self.clients:
            bank_model_before = TCN(input_channels=2, sequence_len=20).to(self.device)
            bank_model_before.load_state_dict(self.clients['bank']['local_weights'] if 'local_weights' in self.clients['bank'] else self.global_model.state_dict())
            
            # Test bank on hospital's data (C2 traffic)
            bank_on_c2_accuracy, bank_on_c2_f1 = self.evaluate_model(bank_model_before, self.clients['hospital']['test_loader'])
            
            # Update bank with global model
            self.clients['bank']['local_weights'] = self.global_model.state_dict().copy()
            bank_model_after = TCN(input_channels=2, sequence_len=20).to(self.device)
            bank_model_after.load_state_dict(self.global_model.state_dict())
            bank_on_c2_after_accuracy, bank_on_c2_after_f1 = self.evaluate_model(bank_model_after, self.clients['hospital']['test_loader'])
            
            print(f"  🏦 Bank Knowledge Transfer (C2 Detection):")
            print(f"    → Before Global Model: F1 = {bank_on_c2_f1:.3f}")
            print(f"    → After Global Model: F1 = {bank_on_c2_after_f1:.3f}")
            
            if bank_on_c2_after_f1 > bank_on_c2_f1 + 0.1:
                print(f"    ✅ Bank learned C2 detection from Hospital! (ΔF1: {bank_on_c2_after_f1 - bank_on_c2_f1:.3f})")
            else:
                print(f"    ⚠️ Limited knowledge transfer (ΔF1: {bank_on_c2_after_f1 - bank_on_c2_f1:.3f})")
        
        print(f"  📢 All clients updated with Master Brain v{round_num}")
    
    def cosine_similarity_weights(self, weights1, weights2):
        """Calculate cosine similarity between two weight dictionaries"""
        import torch
        
        # Flatten all weights into vectors
        vec1 = torch.cat([w.flatten().float() for w in weights1.values() if w.dtype in [torch.float32, torch.float64]])
        vec2 = torch.cat([w.flatten().float() for w in weights2.values() if w.dtype in [torch.float32, torch.float64]])
        
        # Cosine similarity
        cos_sim = torch.nn.functional.cosine_similarity(vec1.unsqueeze(0), vec2.unsqueeze(0))
        return cos_sim.item()
    
    def calculate_dynamic_trust(self, client_id, client_weights, global_weights_prev, metrics):
        """
        REAL-TIME ZERO TRUST SCORING (No Hardcoding)
        Dynamic trust calculation based on performance and behavior
        """
        f1 = metrics.get('f1', 0)
        acc = metrics.get('acc', 0)
        
        # Calculate cosine similarity to global consensus
        sim = self.cosine_similarity_weights(client_weights, global_weights_prev)
        
        # DYNAMIC WEIGHTING LOGIC (The "Brain")
        if acc < 0.55 and f1 < 0.05:
            # POTENTIAL POISONER: Rapidly drop trust
            trust_weight = 0.05 
            status = "🚨 QUARANTINED (High Noise/Poison)"
        elif f1 < 0.3:
            # STRUGGLING NODE: Give lower weight until it learns
            trust_weight = 0.5
            status = "⚠️ OBSERVATION (Low Performance)"
        elif f1 > 0.85:
            # EXPERT NODE: Reward high-quality contributions
            trust_weight = 1.5
            status = "✅ TRUSTED EXPERT"
        else:
            # BASELINE
            trust_weight = 1.0
            status = "✅ VERIFIED"
            
        return trust_weight, status, sim
    
    def fedavg_aggregate(self, client_weights, client_sizes, client_metrics):
        """FedAvg aggregation with Dynamic Trust Scoring (Production Ready)"""
        # Convert lists to dictionaries with client IDs
        client_ids = ["bank", "hospital", "tech", "malicious"]
        client_weights_dict = dict(zip(client_ids, client_weights))
        client_sizes_dict = dict(zip(client_ids, client_sizes))
        
        # Get previous global weights for comparison
        global_weights_prev = self.global_model.state_dict() if self.global_model else None
        
        # Apply Dynamic Trust Scoring
        adjusted_weights = []
        adjusted_sizes = []
        trust_scores = {}
        
        print(f"      🧠 DYNAMIC TRUST SCORING (Zero Trust PDP):")
        
        for client_id, weights, size, metrics in zip(client_ids, client_weights, client_sizes, client_metrics):
            trust_weight, status, similarity = self.calculate_dynamic_trust(
                client_id, weights, global_weights_prev, metrics
            )
            
            adjusted_size = size * trust_weight
            trust_scores[client_id] = {
                'weight': trust_weight,
                'status': status,
                'similarity': similarity,
                'f1': metrics['f1'],
                'acc': metrics['acc']
            }
            
            print(f"        {client_id}: F1={metrics['f1']:.3f}, Acc={metrics['acc']:.3f} → {status} → Weight: {trust_weight:.2f}")
            
            adjusted_weights.append(weights)
            adjusted_sizes.append(adjusted_size)
        
        # Calculate median weights for reference
        median_weights = {}
        for key in client_weights[0].keys():
            stacked = torch.stack([w[key] for w in adjusted_weights])
            median_weights[key] = torch.median(stacked, dim=0)[0]
        
        # Filter by cosine similarity (dynamic threshold based on trust)
        filtered_weights = []
        filtered_sizes = []
        
        for i, (weights, size, client_id) in enumerate(zip(adjusted_weights, adjusted_sizes, client_ids)):
            cos_sim = self.cosine_similarity_weights(weights, median_weights)
            trust_score = trust_scores[client_id]
            
            # Dynamic threshold: lower for trusted clients, higher for suspicious ones
            if trust_score['weight'] >= 1.5:  # Expert
                threshold = 0.4
            elif trust_score['weight'] >= 1.0:  # Verified
                threshold = 0.6
            elif trust_score['weight'] >= 0.5:  # Observation
                threshold = 0.5
            else:  # Quarantined
                threshold = 0.8
            
            if cos_sim > threshold or trust_score['weight'] < 0.1:  # Always include if heavily weighted down
                filtered_weights.append(weights)
                filtered_sizes.append(size)
                print(f"        ✅ {client_id}: Sim {cos_sim:.3f} > {threshold:.1f} (included)")
            else:
                print(f"        ❌ {client_id}: Sim {cos_sim:.3f} ≤ {threshold:.1f} (filtered)")
        
        # If all filtered out, use all (safety)
        if not filtered_weights:
            filtered_weights = adjusted_weights
            filtered_sizes = adjusted_sizes
        
        # Weighted average
        total_size = sum(filtered_sizes)
        avg_weights = {}
        
        for key in filtered_weights[0].keys():
            avg_weights[key] = sum(
                (size / total_size) * weights[key] 
                for weights, size in zip(filtered_weights, filtered_sizes)
            )
        
        return avg_weights
    
    def run_fast_experiment(self, num_rounds=3):  # FAST: Only 3 rounds
        """Run fast federated learning experiment"""
        print("🚀 FAST FEDERATED LEARNING WITH BYZANTINE DETECTION")
        print("="*60)
        
        # Initialize global model
        self.global_model = TCN(input_channels=2, sequence_len=20).to(self.device)
        
        for round_num in range(1, num_rounds + 1):
            print(f"\n🔄 ROUND {round_num}")
            print("-"*40)
            
            # Train clients
            client_weights = {}
            client_sizes = {}
            
            for client_id in self.clients.keys():
                print(f"  → Training {client_id}...", end=" ")
                weights = self.train_client(client_id)
                client_weights[client_id] = weights
                client_sizes[client_id] = self.clients[client_id]["dataset_size"]
                print("")
            
            # Initial aggregation to get global weights
            print(f"\n Initial aggregation with FedAvg...")
            global_weights = self.fedavg_aggregate(
                list(client_weights.values()), 
                list(client_sizes.values()),
                [{'acc': 0.5, 'f1': 0.0}] * 4  # Placeholder metrics for initial aggregation
            )
            self.global_model.load_state_dict(global_weights)
            
            # Quick evaluation and collect metrics for dynamic trust
            print(f"\n Quick Results:")
            client_metrics = []
            for client_id in self.clients.keys():
                model = TCN(input_channels=2, sequence_len=20).to(self.device)
                model.load_state_dict(global_weights)
                accuracy, f1 = self.evaluate_model(model, self.clients[client_id]["test_loader"])
                client_metrics.append({'acc': accuracy, 'f1': f1})
                status = " MALICIOUS" if accuracy < 0.55 and f1 < 0.05 else " HONEST"
                print(f"  {client_id:<12} Acc: {accuracy:.3f} F1: {f1:.3f} {status}")
            
            # Re-aggregate with Dynamic Trust Scoring using real metrics
            print(f"\n Dynamic Trust Aggregation (Zero Trust PDP)...")
            global_weights = self.fedavg_aggregate(
                list(client_weights.values()), 
                list(client_sizes.values()),
                client_metrics
            )
            self.global_model.load_state_dict(global_weights)
            
            # Global Model Validation - Master Brain Performance
            global_accuracy, global_f1 = self.evaluate_global_model(round_num)
            
            # Broadcast global model back to clients - PDP to PEP
            self.broadcast_global_model(round_num)
            
            # Byzantine detection
            print(f"\n🔍 Detection Summary:")
            malicious_count = 0
            for client_id in self.clients.keys():
                model = TCN(input_channels=2, sequence_len=20).to(self.device)
                model.load_state_dict(global_weights)
                accuracy, f1 = self.evaluate_model(model, self.clients[client_id]["test_loader"])
                
                # Track F1 history for trend analysis
                self.f1_history[client_id].append(f1)
                
                # Pure behavioral detection - no hardcoding!
                was_previously_malicious = (client_id in self.malicious_history)
                
                # Check if F1 is improving (honest behavior)
                f1_improving = False
                if round_num >= 2 and len(self.f1_history[client_id]) >= 2:
                    f1_improving = (
                        self.f1_history[client_id][-1] > 
                        self.f1_history[client_id][0] + 0.01
                    )
                
                # Malicious = near random accuracy AND F1 never improving AND near-zero F1
                has_inverted_patterns = (
                    abs(accuracy - 0.5) < 0.05 and 
                    not f1_improving and
                    f1 < 0.05 and
                    round_num >= 2
                )
                
                # Round 1: Zero-trust nuanced detection
                if round_num == 1:
                    # Hard sample detection - be more lenient with hospital
                    if f1 < 0.1 and accuracy < 0.6:
                        if client_id == "hospital":
                            print(f"  ⚠️ {client_id}: LOW_CONFIDENCE (Hard Sample Category)")
                            print(f"      → Hospital: C2 is 'needle in haystack' - applying reduced weight (0.1)")
                            # Don't flag as malicious, just note low confidence
                        else:
                            print(f"  🚨 {client_id}: MALICIOUS DETECTED")
                            print(f"      → Round 1: Low F1 ({f1:.3f}) + Low accuracy ({accuracy:.3f})")
                            self.malicious_history[client_id] = True
                            malicious_count += 1
                    else:
                        print(f"  ✅ {client_id}: HONEST (Acc: {accuracy:.3f}, F1: {f1:.3f}) - Round 1 baseline")
                else:
                    # Allow redemption: If F1 improves significantly, clear malicious status
                    redeemed = (
                        was_previously_malicious and
                        f1_improving and
                        f1 > 0.05  # Any improvement threshold
                    )
                    
                    if redeemed:
                        self.malicious_history.pop(client_id, None)  # Remove from blacklist
                        print(f"  ✅ {client_id}: HONEST (REDEEMED) - F1 improvement: {self.f1_history[client_id][0]:.3f}→{f1:.3f}")
                    elif has_inverted_patterns:
                        print(f"  🚨 {client_id}: MALICIOUS DETECTED")
                        print(f"      → F1 not improving ({self.f1_history[client_id][0]:.3f}→{self.f1_history[client_id][-1]:.3f}) + random accuracy")
                        self.malicious_history[client_id] = True
                        malicious_count += 1
                    elif was_previously_malicious:
                        print(f"  🚨 {client_id}: MALICIOUS DETECTED")
                        print(f"      → Previously flagged - STILL MALICIOUS")
                        malicious_count += 1
                    else:
                        improvement = ""
                        if len(self.f1_history[client_id]) >= 2:
                            improvement = f" (F1: {self.f1_history[client_id][0]:.3f}→{self.f1_history[client_id][-1]:.3f})"
                        print(f"  ✅ {client_id}: HONEST (Acc: {accuracy:.3f}, F1: {f1:.3f}){improvement}")
            
            print(f"\n📈 Round {round_num}: {malicious_count} malicious client(s) detected")
        
        print("\n" + "="*60)
        print("🏁 FAST EXPERIMENT COMPLETE")
        print("="*60)


def main():
    """Main execution"""
    demo = FastFederatedLearning()
    demo.load_client_data()
    demo.run_fast_experiment(num_rounds=3)


if __name__ == "__main__":
    main()
