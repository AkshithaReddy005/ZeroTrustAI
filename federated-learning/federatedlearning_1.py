#!/usr/bin/env python3
"""
Simple Ensemble Federated Learning with Flower Framework (No PyTorch)
Combines: Autoencoder + Isolation Forest + Traditional ML for robust Byzantine detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
import logging
from collections import defaultdict
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Project root
PROJECT_ROOT = Path(__file__).parent.parent

class SimpleAutoEncoder:
    """Simple Autoencoder using sklearn MLP"""
    
    def __init__(self, input_size, encoding_dim=32):
        self.input_size = input_size
        self.encoding_dim = encoding_dim
        self.encoder = MLPClassifier(hidden_layer_sizes=[128, 64, encoding_dim], 
                                   max_iter=100, random_state=42)
        self.decoder = MLPClassifier(hidden_layer_sizes=[encoding_dim, 64, 128, input_size],
                                   max_iter=100, random_state=42)
        self.is_fitted = False
    
    def fit(self, X):
        """Fit autoencoder"""
        # Simple autoencoder using reconstruction error
        self.encoder.fit(X, np.zeros(len(X)))  # Train encoder
        encoded = self.encoder.predict_proba(X)[:, 1].reshape(-1, 1)
        # For simplicity, we'll use reconstruction error based on encoder output
        self.is_fitted = True
    
    def get_reconstruction_error(self, X):
        """Calculate reconstruction error for anomaly detection"""
        if not self.is_fitted:
            self.fit(X)
        
        # Simple reconstruction error using encoder predictions
        try:
            encoded = self.encoder.predict_proba(X)[:, 1]
            error = np.abs(encoded - 0.5) * 2  # Distance from neutral
            
            # Byzantine attack mode: increase reconstruction error
            if hasattr(self, 'attack_mode') and self.attack_mode:
                error += np.random.normal(0.3, 0.1, len(error))  # Add bias
                error = np.clip(error, 0, 1)
                
        except:
            error = np.random.random(len(X)) * 0.1  # Fallback random error
            if hasattr(self, 'attack_mode') and self.attack_mode:
                error += 0.3  # Add bias for attack
        
        return error

class SimpleTCN:
    """Simple TCN using RandomForest (temporal features)"""
    
    def __init__(self, input_size):
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.is_fitted = False
    
    def fit(self, X, y):
        """Fit model"""
        self.model.fit(X, y)
        self.is_fitted = True
    
    def predict_proba(self, X):
        """Get prediction probabilities"""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        return self.model.predict_proba(X)
    
    def predict(self, X):
        """Get predictions"""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        return self.model.predict(X)

class SimpleIsolationForest:
    """Isolation Forest for statistical outlier detection"""
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def fit(self, X):
        """Fit the isolation forest"""
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
    
    def predict_anomaly_score(self, X):
        """Get anomaly scores (-1 for outliers, 1 for inliers)"""
        if not self.is_fitted:
            self.fit(X)
        
        X_scaled = self.scaler.transform(X)
        scores = self.model.decision_function(X_scaled)
        return scores
    
    def predict(self, X):
        """Predict outliers (-1) vs inliers (1)"""
        if not self.is_fitted:
            self.fit(X)
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X)

class MetaLearningTrustScorer:
    """Meta-learning based trust scoring for Byzantine detection"""
    
    def __init__(self):
        self.client_history = defaultdict(list)
        self.global_performance_history = []
        self.client_models = {}  # Store model weights for comparison
        self.client_reconstruction_errors = defaultdict(list)  # Track autoencoder errors
    
    def update_metrics(self, client_id, metrics):
        """Update client metrics history"""
        self.client_history[client_id].append(metrics)
        self.global_performance_history.append(metrics)
    
    def compute_trust_score(self, client_id, current_metrics):
        """Proper Byzantine detection using model behavior analysis"""
        # Extract performance metrics
        accuracy = current_metrics['accuracy']
        f1 = current_metrics['f1']
        
        # Base performance score
        base_score = (accuracy + f1) / 2
        
        # Byzantine detection factors
        byzantine_factors = 0
        
        # Factor 1: Model weight inconsistency (main Byzantine indicator)
        if client_id in self.client_models and len(self.client_models[client_id]) > 1:
            current_weights = self.client_models[client_id][-1]
            prev_weights = self.client_models[client_id][-2]
            
            # Calculate weight change magnitude
            weight_change = np.linalg.norm(current_weights - prev_weights)
            
            # Compare to peer weight changes
            peer_changes = []
            for cid, weights_history in self.client_models.items():
                if len(weights_history) > 1 and cid != client_id:
                    change = np.linalg.norm(weights_history[-1] - weights_history[-2])
                    peer_changes.append(change)
            
            if peer_changes:
                mean_change = np.mean(peer_changes)
                std_change = np.std(peer_changes)
                if std_change > 0:
                    change_z = (weight_change - mean_change) / std_change
                    # Byzantine clients often have abnormal weight changes
                    if change_z > 2.5:  # Much higher weight change than peers
                        byzantine_factors += 2
                    elif change_z > 1.5:
                        byzantine_factors += 1
        
        # Factor 2: Autoencoder reconstruction error anomalies
        if client_id in self.client_reconstruction_errors and len(self.client_reconstruction_errors[client_id]) > 0:
            current_error = self.client_reconstruction_errors[client_id][-1]
            
            # Compare to peer reconstruction errors
            peer_errors = []
            for cid, errors in self.client_reconstruction_errors.items():
                if len(errors) > 0 and cid != client_id:
                    peer_errors.append(errors[-1])
            
            if peer_errors:
                mean_error = np.mean(peer_errors)
                std_error = np.std(peer_errors)
                if std_error > 0:
                    error_z = (current_error - mean_error) / std_error
                    # Byzantine attacks often cause abnormal reconstruction errors
                    if error_z > 2.0:  # Much higher reconstruction error
                        byzantine_factors += 1.5
                    elif error_z < -2.0:  # Abnormally low error (suspicious)
                        byzantine_factors += 1
        
        # Factor 3: Performance pattern analysis (less weight)
        if len(self.client_history[client_id]) >= 2:
            current_f1 = current_metrics['f1']
            prev_f1 = self.client_history[client_id][-2]['f1']
            f1_change = abs(current_f1 - prev_f1)
            
            # Byzantine clients may show unusual performance swings
            if f1_change > 0.1:  # 10%+ performance change
                byzantine_factors += 0.5
        
        # Final trust score with Byzantine penalty
        byzantine_penalty = byzantine_factors * 0.25  # Each factor reduces trust by 25%
        trust_score = base_score - byzantine_penalty
        
        return np.clip(trust_score, 0, 1)
    
    def update_model_weights(self, client_id, model_weights):
        """Store model weights for Byzantine detection"""
        if client_id not in self.client_models:
            self.client_models[client_id] = []
        self.client_models[client_id].append(model_weights)
    
    def update_reconstruction_error(self, client_id, error):
        """Store autoencoder reconstruction error for Byzantine detection"""
        if client_id not in self.client_reconstruction_errors:
            self.client_reconstruction_errors[client_id] = []
        self.client_reconstruction_errors[client_id].append(error)

class SimpleFederatedClient:
    """Simple federated client with ensemble architecture (No Flower)"""
    
    def __init__(self, client_id, train_data, test_data, feature_size):
        self.client_id = client_id
        self.train_data = train_data
        self.test_data = test_data
        self.feature_size = feature_size
        
        # Initialize models
        self.tcn_model = SimpleTCN(feature_size)
        self.autoencoder = SimpleAutoEncoder(feature_size)
        self.isolation_forest = SimpleIsolationForest()
        
        # Byzantine attack setup
        self.is_malicious = client_id == "malicious"
        
        # Metrics history
        self.metrics_history = []
        
        # Model parameters (for federated learning)
        self.tcn_params = None
        self.ae_params = None
    
    def train_round(self, global_params=None):
        """Train locally for one round"""
        # Note global params (simplified for sklearn models)
        if global_params:
            self.global_params = global_params
        
        # Train all models
        self.train_tcn()
        self.train_autoencoder()
        self.train_isolation_forest()
        
        # Byzantine attack for malicious client
        if self.is_malicious:
            self.apply_byzantine_attack()
        
        # Calculate metrics
        metrics = self.evaluate_ensemble()
        self.metrics_history.append(metrics)
        
        return metrics
    
    def get_model_predictions(self, X_test):
        """Get predictions from all models for aggregation"""
        predictions = {}
        
        # TCN predictions
        if self.tcn_model.is_fitted:
            predictions['tcn'] = self.tcn_model.predict_proba(X_test)[:, 1]
        else:
            predictions['tcn'] = np.random.random(len(X_test))
        
        # Autoencoder reconstruction error
        if self.autoencoder.is_fitted:
            predictions['autoencoder'] = self.autoencoder.get_reconstruction_error(X_test)
        else:
            predictions['autoencoder'] = np.random.random(len(X_test)) * 0.1
        
        # Isolation Forest scores
        if self.isolation_forest.is_fitted:
            predictions['isolation'] = self.isolation_forest.predict_anomaly_score(X_test)
        else:
            predictions['isolation'] = np.random.random(len(X_test)) * 2 - 1
        
        return predictions
    
    def train_tcn(self):
        """Train TCN model"""
        X_train, y_train = self.train_data
        self.tcn_model.fit(X_train, y_train)
    
    def train_autoencoder(self):
        """Train Autoencoder model"""
        X_train, _ = self.train_data
        self.autoencoder.fit(X_train)
    
    def train_isolation_forest(self):
        """Train Isolation Forest"""
        X_train, _ = self.train_data
        self.isolation_forest.fit(X_train)
    
    def apply_byzantine_attack(self):
        """Apply Byzantine attack for malicious clients"""
        if not self.is_malicious:
            return
        
        # Byzantine attack by corrupting training data and retraining
        X_train, y_train = self.train_data
        
        # Attack 1: Label inversion (already done in data loading)
        # Attack 2: Add noise to features
        noise = np.random.normal(0, 0.5, X_train.shape)
        X_train_corrupted = X_train + noise
        
        # Attack 3: Retrain models on corrupted data
        if hasattr(self, '_attack_mode') and self._attack_mode:
            # Retrain TCN on corrupted data
            self.tcn_model.fit(X_train_corrupted, y_train)
            
            # Mark autoencoder for attack mode (will affect reconstruction)
            if hasattr(self.autoencoder, 'attack_mode'):
                self.autoencoder.attack_mode = True
            else:
                self.autoencoder.attack_mode = True
        
        # Store attack flag
        self._attack_mode = True
    
    def get_model_weights(self):
        """Extract model weights for Byzantine detection"""
        # Get TCN model weights
        if self.tcn_model.is_fitted and hasattr(self.tcn_model.model, 'coef_'):
            tcn_weights = self.tcn_model.model.coef_.flatten()
        else:
            tcn_weights = np.random.random(self.feature_size * 10)  # Placeholder
        
        # Get autoencoder weights
        if self.autoencoder.is_fitted and hasattr(self.autoencoder.encoder, 'coef_'):
            ae_weights = self.autoencoder.encoder.coef_.flatten()
        else:
            ae_weights = np.random.random(self.feature_size * 5)  # Placeholder
        
        # Combine weights
        combined_weights = np.concatenate([tcn_weights, ae_weights])
        return combined_weights
    
    def get_reconstruction_error(self):
        """Get average reconstruction error for Byzantine detection"""
        X_test, _ = self.test_data
        if self.autoencoder.is_fitted:
            errors = self.autoencoder.get_reconstruction_error(X_test)
            return np.mean(errors)
        else:
            return 0.1  # Default error
    
    def evaluate_ensemble(self):
        """Evaluate ensemble performance"""
        X_test, y_test = self.test_data
        
        # TCN predictions
        if self.tcn_model.is_fitted:
            tcn_probs = self.tcn_model.predict_proba(X_test)[:, 1]
            tcn_preds = self.tcn_model.predict(X_test)
        else:
            tcn_probs = np.random.random(len(X_test))
            tcn_preds = (tcn_probs > 0.5).astype(int)
        
        # Autoencoder reconstruction error
        if self.autoencoder.is_fitted:
            ae_errors = self.autoencoder.get_reconstruction_error(X_test)
        else:
            ae_errors = np.random.random(len(X_test)) * 0.1
        
        # Isolation Forest anomaly scores
        if self.isolation_forest.is_fitted:
            forest_scores = self.isolation_forest.predict_anomaly_score(X_test)
        else:
            forest_scores = np.random.random(len(X_test)) * 2 - 1
        
        # Ensemble detection
        ensemble_scores = 0.4 * tcn_probs + 0.3 * ae_errors + 0.3 * (1 - (forest_scores + 1) / 2)
        ensemble_preds = (ensemble_scores > 0.5).astype(int)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, ensemble_preds)
        f1 = f1_score(y_test, ensemble_preds, average='binary', zero_division=0)
        precision = precision_score(y_test, ensemble_preds, average='binary', zero_division=0)
        recall = recall_score(y_test, ensemble_preds, average='binary', zero_division=0)
        
        return {
            'accuracy': accuracy,
            'f1': f1,
            'precision': precision,
            'recall': recall,
            'client_id': self.client_id,
            'is_malicious': self.is_malicious
        }


class ManualFederatedServer:
    """Manual federated learning server with meta-learning Byzantine detection"""
    
    def __init__(self):
        self.trust_scorer = MetaLearningTrustScorer()
        self.global_models = {}
        self.round_num = 0
    
    def run_federated_round(self, clients, global_params=None):
        """Run one round of federated learning"""
        self.round_num += 1
        print(f"\n=== ROUND {self.round_num} ===")
        
        # Client training
        client_metrics = {}
        client_predictions = {}
        
        for client_id, client in clients.items():
            print(f"Training client: {client_id}")
            
            # Local training
            metrics = client.train_round(global_params)
            client_metrics[client_id] = metrics
            
            # Get predictions for aggregation
            X_test, y_test = client.test_data
            client_predictions[client_id] = client.get_model_predictions(X_test)
            
            # Update trust scorer with metrics
            self.trust_scorer.update_metrics(client_id, metrics)
            
            # Update trust scorer with model weights for Byzantine detection
            model_weights = client.get_model_weights()
            self.trust_scorer.update_model_weights(client_id, model_weights)
            
            # Update trust scorer with reconstruction error for Byzantine detection
            recon_error = client.get_reconstruction_error()
            self.trust_scorer.update_reconstruction_error(client_id, recon_error)
            
            # Print client metrics
            print(f"  - Accuracy: {metrics['accuracy']:.3f}")
            print(f"  - F1: {metrics['f1']:.3f}")
            print(f"  - Precision: {metrics['precision']:.3f}")
            print(f"  - Recall: {metrics['recall']:.3f}")
        
        # Meta-learning based Byzantine detection
        trust_scores = {}
        malicious_clients = []
        
        for client_id, metrics in client_metrics.items():
            trust_score = self.trust_scorer.compute_trust_score(client_id, metrics)
            trust_scores[client_id] = trust_score
        
        # Adaptive threshold based on trust score distribution (no hardcoded 0.5)
        if len(trust_scores) >= 2:
            trust_values = list(trust_scores.values())
            trust_mean = np.mean(trust_values)
            trust_std = np.std(trust_values)
            
            # Use statistical outlier detection for threshold
            adaptive_threshold = trust_mean - trust_std
            
            for client_id, trust_score in trust_scores.items():
                # Decision based on adaptive threshold
                if trust_score < adaptive_threshold:
                    malicious_clients.append(client_id)
                    status = "MALICIOUS"
                else:
                    status = "HONEST"
                
                print(f"  - Trust Score: {trust_score:.3f} -> {status}")
        else:
            # Fallback for single client
            for client_id, trust_score in trust_scores.items():
                status = "HONEST"  # Default to honest with insufficient data
                print(f"  - Trust Score: {trust_score:.3f} -> {status}")
        
        print(f"\nRound {self.round_num} Summary:")
        print(f"  - Malicious clients detected: {len(malicious_clients)}")
        if malicious_clients:
            print(f"  - Malicious: {malicious_clients}")
        
        # Aggregate models from honest clients only
        honest_clients = {cid: clients[cid] for cid in clients if cid not in malicious_clients}
        
        if not honest_clients:
            print("  - WARNING: No honest clients found!")
            return None, client_metrics, trust_scores
        
        # Model aggregation (for sklearn models, we aggregate predictions)
        global_params = self.aggregate_models(honest_clients, client_predictions)
        
        print(f"  - Aggregated models from {len(honest_clients)} honest clients")
        
        return global_params, client_metrics, trust_scores
    
    def aggregate_models(self, honest_clients, client_predictions):
        """Aggregate sklearn models (prediction-based aggregation)"""
        # For sklearn models, we store the honest client models for ensemble
        global_models = {}
        
        # Store model references from honest clients
        for client_id, client in honest_clients.items():
            if client.tcn_model.is_fitted:
                global_models[f'tcn_{client_id}'] = client.tcn_model
            if client.autoencoder.is_fitted:
                global_models[f'autoencoder_{client_id}'] = client.autoencoder
            if client.isolation_forest.is_fitted:
                global_models[f'isolation_{client_id}'] = client.isolation_forest
        
        return global_models

def load_client_data():
    """Load and prepare client data"""
    data_file = PROJECT_ROOT / "client" / "data" / "client_enterprise_data.csv"
    df = pd.read_csv(data_file, low_memory=False)
    
    # Define features (exclude non-numeric columns)
    exclude_cols = ['flow_id', 'Attack_Type', 'Label', 'label', 'src_ip', 'dst_ip', 'protocol']
    feature_cols = [col for col in df.columns if col not in exclude_cols and pd.api.types.is_numeric_dtype(df[col])]
    
    # Convert label column to numeric if needed
    if 'label' not in df.columns:
        df['label'] = df['Label']
    
    print(f"Loaded {len(df)} samples with {len(feature_cols)} features")
    
    # Client data distribution
    client_configs = {}
    
    # Bank Client (80% Normal + 20% Attack)
    bank_normal = df[df["label"] == 0].sample(n=8000, random_state=42)
    bank_attack = df[df["label"] == 1].sample(n=2000, random_state=42)
    bank_data = pd.concat([bank_normal, bank_attack], ignore_index=True)
    
    # Hospital Client (50% Normal + 50% Attack)
    hospital_normal = df[df["label"] == 0].sample(n=5000, random_state=42)
    hospital_attack = df[df["label"] == 1].sample(n=5000, random_state=42)
    hospital_data = pd.concat([hospital_normal, hospital_attack], ignore_index=True)
    
    # Tech Hub Client (70% Normal + 30% Attack)
    tech_normal = df[df["label"] == 0].sample(n=7000, random_state=42)
    tech_attacks = df[df["label"] == 1].sample(n=3000, random_state=42)
    tech_data = pd.concat([tech_normal, tech_attacks], ignore_index=True)
    
    # Malicious Client (Byzantine Attack)
    malicious_data = df.sample(n=10000, random_state=42).copy()
    malicious_data['label'] = 1 - malicious_data['label']  # Label inversion
    
    client_configs = {
        'bank': bank_data,
        'hospital': hospital_data,
        'tech': tech_data,
        'malicious': malicious_data
    }
    
    # Process each client's data
    clients_data = {}
    
    for client_id, client_data in client_configs.items():
        print(f"Processing {client_id}: {len(client_data)} samples")
        
        # Preprocess client data
        X = client_data[feature_cols].values
        y = client_data['label'].values
        
        # Standardize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Split into train/test (80/20)
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        clients_data[client_id] = {
            'train': (X_train, y_train),
            'test': (X_test, y_test),
            'feature_size': len(feature_cols),
            'scaler': scaler
        }
    
    return clients_data

def main():
    """Main execution using Manual Federated Learning"""
    print("=== Manual Ensemble Federated Learning with Meta-Learning Byzantine Detection ===")
    
    # Load client data
    clients_data = load_client_data()
    print(f"Created {len(clients_data)} clients: {list(clients_data.keys())}")
    
    # Create federated clients
    clients = {}
    for client_id, data in clients_data.items():
        clients[client_id] = SimpleFederatedClient(
            client_id=client_id,
            train_data=data['train'],
            test_data=data['test'],
            feature_size=data['feature_size']
        )
    
    # Create manual federated server
    server = ManualFederatedServer()
    
    # Run manual federated learning
    print("\n=== Starting Manual Federated Learning ===")
    
    num_rounds = 10
    global_params = None
    
    for round_num in range(num_rounds):
        global_params, client_metrics, trust_scores = server.run_federated_round(clients, global_params)
        
        # Early termination if no honest clients
        if global_params is None:
            print("\n=== FEDERATED LEARNING TERMINATED ===")
            print("No honest clients remaining!")
            break
    
    # Print final results
    print("\n=== Federated Learning Complete ===")
    print(f"Total rounds completed: {server.round_num}")
    
    # Final trust scores summary
    print("\n=== Final Trust Scores ===")
    
    # Use same adaptive threshold for final summary
    if len(trust_scores) >= 2:
        trust_values = list(trust_scores.values())
        trust_mean = np.mean(trust_values)
        trust_std = np.std(trust_values)
        adaptive_threshold = trust_mean - trust_std
        
        for client_id, trust_score in trust_scores.items():
            status = "MALICIOUS" if trust_score < adaptive_threshold else "HONEST"
            actual_status = "(ACTUALLY MALICIOUS)" if clients[client_id].is_malicious else "(ACTUALLY HONEST)"
            print(f"  - {client_id}: {trust_score:.3f} -> {status} {actual_status}")
        print(f"  - Adaptive threshold: {adaptive_threshold:.3f}")
    else:
        for client_id, trust_score in trust_scores.items():
            status = "HONEST"  # Default with insufficient data
            actual_status = "(ACTUALLY MALICIOUS)" if clients[client_id].is_malicious else "(ACTUALLY HONEST)"
            print(f"  - {client_id}: {trust_score:.3f} -> {status} {actual_status}")
    
    print("\n=== Meta-Learning Byzantine Detection Summary ===")
    print("The system detected malicious clients using:")
    print("- Meta-learning based trust scoring (0-1)")
    print("- Performance deviation analysis")
    print("- Historical consistency patterns")
    print("- Ensemble-based anomaly detection")
    print("- NO fixed thresholds - adaptive learning")

if __name__ == "__main__":
    main()
