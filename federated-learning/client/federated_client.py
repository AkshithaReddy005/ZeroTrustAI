#!/usr/bin/env python3
"""
Federated Learning Client for ZeroTrust-AI
Implements local training and server communication
"""

import os
import sys
import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import pandas as pd
import yaml
import requests
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "shared"))

try:
    from schemas import FlowFeatures
except ImportError:
    logging.warning("Shared schemas not found, using fallback")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FederatedClient:
    """Federated Learning Client with local training"""
    
    def __init__(self, client_id: str, config_path: str = "config.yaml"):
        self.client_id = client_id
        self.config = self._load_config(config_path)
        self.local_model = None
        self.server_url = None
        self.current_round = 0
        self.training_data = None
        self.scaler = None
        
        # Client info for registration
        self.client_info = {
            "client_id": client_id,
            "platform": "ZeroTrust-AI Client",
            "version": "1.0.0",
            "data_size": 0,
            "environment": "local"
        }
        
        # Initialize connection
        self._connect_to_server()
        
        # Load local data
        self._load_local_data()
        
        logger.info(f"Federated Client {client_id} initialized")
    
    def _load_config(self, config_path: str) -> dict:
        """Load client configuration"""
        default_config = {
            "server": {
                "host": "localhost",
                "port": 5000,
                "protocol": "http"
            },
            "federated": {
                "local_epochs": 5,
                "batch_size": 32,
                "learning_rate": 0.001,
                "optimizer": "adam",
                "loss_function": "cross_entropy"
            },
            "data": {
                "data_path": "data/local_client_data.csv",
                "test_size": 0.2,
                "random_state": 42
            },
            "model": {
                "input_size": 12,
                "hidden_size": 64,
                "num_classes": 2,
                "sequence_length": 50
            },
            "training": {
                "device": "auto",  # auto, cpu, cuda
                "save_local_models": True,
                "log_interval": 10
            }
        }
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                # Merge with defaults
                for key in default_config:
                    if key not in config:
                        config[key] = default_config[key]
                return config
        else:
            logger.warning(f"Config file {config_path} not found, using defaults")
            return default_config
    
    def _connect_to_server(self):
        """Connect to federated server"""
        server_config = self.config["server"]
        self.server_url = f"{server_config['protocol']}://{server_config['host']}:{server_config['port']}"
        
        try:
            # Register with server
            response = requests.post(f"{self.server_url}/register", json={
                "client_id": self.client_id,
                "client_info": self.client_info
            }, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                self.current_round = data.get("global_round", 0)
                logger.info(f"Connected to server at {self.server_url}")
                logger.info(f"Current global round: {self.current_round}")
            else:
                logger.error(f"Registration failed: {response.text}")
                raise ConnectionError("Server registration failed")
                
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            raise
    
    def _load_local_data(self):
        """Load and prepare local training data"""
        data_path = self.config["data"]["data_path"]
        
        if not os.path.exists(data_path):
            logger.warning(f"Data file {data_path} not found, generating synthetic data")
            self._generate_synthetic_data(data_path)
        
        try:
            # Load data
            df = pd.read_csv(data_path)
            
            # Extract features and labels
            feature_columns = [col for col in df.columns if col not in ['label', 'flow_id']]
            X = df[feature_columns].values
            y = df['label'].values
            
            # Split data
            test_size = self.config["data"]["test_size"]
            random_state = self.config["data"]["random_state"]
            
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
            
            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Convert to tensors
            device = self._get_device()
            X_train_tensor = torch.FloatTensor(X_train_scaled).to(device)
            y_train_tensor = torch.LongTensor(y_train).to(device)
            X_test_tensor = torch.FloatTensor(X_test_scaled).to(device)
            y_test_tensor = torch.LongTensor(y_test).to(device)
            
            self.training_data = {
                "X_train": X_train_tensor,
                "y_train": y_train_tensor,
                "X_test": X_test_tensor,
                "y_test": y_test_tensor,
                "feature_names": feature_columns
            }
            
            # Update client info
            self.client_info["data_size"] = len(X_train)
            self.client_info["num_features"] = len(feature_columns)
            
            logger.info(f"Loaded {len(X_train)} training samples, {len(X_test)} test samples")
            logger.info(f"Features: {len(feature_columns)}")
            
        except Exception as e:
            logger.error(f"Failed to load data: {e}")
            raise
    
    def _generate_synthetic_data(self, data_path: str, num_samples: int = 1000):
        """Generate synthetic training data for demonstration"""
        logger.info(f"Generating {num_samples} synthetic samples")
        
        np.random.seed(42)
        
        # Generate features (12 network traffic features)
        feature_names = [
            'total_packets', 'total_bytes', 'avg_packet_size', 'std_packet_size',
            'flow_duration', 'bytes_per_second', 'packets_per_second',
            'src_to_dst_bytes', 'dst_to_src_bytes', 'src_to_dst_packets',
            'dst_to_src_packets', 'tcp_flags'
        ]
        
        # Generate benign traffic (70%)
        benign_samples = int(num_samples * 0.7)
        attack_samples = num_samples - benign_samples
        
        # Benign traffic patterns
        benign_data = {
            'total_packets': np.random.normal(100, 30, benign_samples),
            'total_bytes': np.random.normal(50000, 15000, benign_samples),
            'avg_packet_size': np.random.normal(500, 100, benign_samples),
            'std_packet_size': np.random.normal(50, 20, benign_samples),
            'flow_duration': np.random.normal(10, 3, benign_samples),
            'bytes_per_second': np.random.normal(5000, 1000, benign_samples),
            'packets_per_second': np.random.normal(10, 3, benign_samples),
            'src_to_dst_bytes': np.random.normal(25000, 7500, benign_samples),
            'dst_to_src_bytes': np.random.normal(25000, 7500, benign_samples),
            'src_to_dst_packets': np.random.normal(50, 15, benign_samples),
            'dst_to_src_packets': np.random.normal(50, 15, benign_samples),
            'tcp_flags': np.random.normal(2, 1, benign_samples)
        }
        
        # Attack traffic patterns (different characteristics)
        attack_data = {
            'total_packets': np.random.normal(1000, 200, attack_samples),
            'total_bytes': np.random.normal(500000, 100000, attack_samples),
            'avg_packet_size': np.random.normal(500, 150, attack_samples),
            'std_packet_size': np.random.normal(100, 30, attack_samples),
            'flow_duration': np.random.normal(5, 2, attack_samples),
            'bytes_per_second': np.random.normal(100000, 20000, attack_samples),
            'packets_per_second': np.random.normal(200, 50, attack_samples),
            'src_to_dst_bytes': np.random.normal(100000, 20000, attack_samples),
            'dst_to_src_bytes': np.random.normal(400000, 80000, attack_samples),
            'src_to_dst_packets': np.random.normal(200, 40, attack_samples),
            'dst_to_src_packets': np.random.normal(800, 160, attack_samples),
            'tcp_flags': np.random.normal(5, 2, attack_samples)
        }
        
        # Combine data
        all_data = {}
        for feature in feature_names:
            all_data[feature] = np.concatenate([benign_data[feature], attack_data[feature]])
        
        # Add labels (0=benign, 1=attack)
        all_data['label'] = [0] * benign_samples + [1] * attack_samples
        all_data['flow_id'] = [f"flow_{i}" for i in range(num_samples)]
        
        # Create DataFrame
        df = pd.DataFrame(all_data)
        
        # Save to file
        os.makedirs(os.path.dirname(data_path), exist_ok=True)
        df.to_csv(data_path, index=False)
        
        logger.info(f"Synthetic data saved to {data_path}")
    
    def _get_device(self) -> torch.device:
        """Get training device"""
        device_config = self.config["training"]["device"]
        
        if device_config == "auto":
            if torch.cuda.is_available():
                return torch.device("cuda")
            else:
                return torch.device("cpu")
        elif device_config == "cuda":
            if torch.cuda.is_available():
                return torch.device("cuda")
            else:
                logger.warning("CUDA requested but not available, using CPU")
                return torch.device("cpu")
        else:
            return torch.device("cpu")
    
    def _download_global_model(self):
        """Download current global model from server"""
        try:
            response = requests.get(
                f"{self.server_url}/get_global_model",
                params={"client_id": self.client_id},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Convert lists back to tensors
                model_state = {}
                for k, v in data["model_state"].items():
                    if isinstance(v, list):
                        model_state[k] = torch.tensor(v)
                    else:
                        model_state[k] = v
                
                # Initialize local model if needed
                if self.local_model is None:
                    # Define TCN model directly for federated learning
                    class TCN(nn.Module):
                        def __init__(self, in_ch=12, n_classes=2):
                            super().__init__()
                            self.tcn = nn.Sequential(
                                nn.Linear(in_ch, 64),
                                nn.ReLU(),
                                nn.Linear(64, 32),
                                nn.ReLU(),
                                nn.Linear(32, 16),
                                nn.ReLU()
                            )
                            self.head = nn.Sequential(
                                nn.Linear(16, n_classes)
                            )

                        def forward(self, x):
                            # Flatten input for linear layers
                            if x.dim() > 2:
                                x = x.view(x.size(0), -1)
                            z = self.tcn(x)
                            return self.head(z)
                    
                    self.local_model = TCN(
                        in_ch=self.config["model"]["input_size"],
                        n_classes=self.config["model"]["num_classes"]
                    )
                
                # Load global model state
                self.local_model.load_state_dict(model_state)
                self.current_round = data["round"]
                
                logger.info(f"Downloaded global model for round {self.current_round}")
                return True
            else:
                logger.error(f"Failed to download model: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Model download error: {e}")
            return False
    
    def _local_training(self) -> Tuple[Dict, Dict]:
        """Perform local training on client data"""
        if self.local_model is None or self.training_data is None:
            logger.error("Model or data not available for training")
            return {}, {}
        
        device = self._get_device()
        self.local_model.to(device)
        self.local_model.train()
        
        # Setup optimizer and loss function
        learning_rate = self.config["federated"]["learning_rate"]
        optimizer_name = self.config["federated"]["optimizer"]
        
        if optimizer_name.lower() == "adam":
            optimizer = optim.Adam(self.local_model.parameters(), lr=learning_rate)
        else:
            optimizer = optim.SGD(self.local_model.parameters(), lr=learning_rate)
        
        loss_function = nn.CrossEntropyLoss()
        
        # Training parameters
        local_epochs = self.config["federated"]["local_epochs"]
        batch_size = self.config["federated"]["batch_size"]
        log_interval = self.config["training"]["log_interval"]
        
        X_train = self.training_data["X_train"]
        y_train = self.training_data["y_train"]
        X_test = self.training_data["X_test"]
        y_test = self.training_data["y_test"]
        
        num_samples = len(X_train)
        num_batches = (num_samples + batch_size - 1) // batch_size
        
        logger.info(f"Starting local training: {num_samples} samples, {num_batches} batches, {local_epochs} epochs")
        
        # Training loop
        epoch_losses = []
        for epoch in range(local_epochs):
            epoch_loss = 0.0
            
            # Shuffle data
            indices = torch.randperm(num_samples)
            X_train_shuffled = X_train[indices]
            y_train_shuffled = y_train[indices]
            
            for batch_idx in range(num_batches):
                start_idx = batch_idx * batch_size
                end_idx = min(start_idx + batch_size, num_samples)
                
                batch_X = X_train_shuffled[start_idx:end_idx]
                batch_y = y_train_shuffled[start_idx:end_idx]
                
                # Reshape for TCN (add sequence dimension)
                batch_X = batch_X.unsqueeze(1)  # [batch, 1, features]
                
                optimizer.zero_grad()
                
                # Forward pass
                outputs = self.local_model(batch_X)
                loss = loss_function(outputs, batch_y)
                
                # Backward pass
                loss.backward()
                optimizer.step()
                
                epoch_loss += loss.item()
                
                if batch_idx % log_interval == 0:
                    logger.info(f"Epoch {epoch+1}/{local_epochs}, Batch {batch_idx}/{num_batches}, Loss: {loss.item():.4f}")
            
            avg_epoch_loss = epoch_loss / num_batches
            epoch_losses.append(avg_epoch_loss)
            logger.info(f"Epoch {epoch+1}/{local_epochs} completed, Avg Loss: {avg_epoch_loss:.4f}")
        
        # Evaluation
        self.local_model.eval()
        with torch.no_grad():
            # Reshape test data
            X_test_reshaped = X_test.unsqueeze(1)  # [batch, 1, features]
            
            test_outputs = self.local_model(X_test_reshaped)
            _, predicted = torch.max(test_outputs.data, 1)
            
            # Calculate metrics
            total = y_test.size(0)
            correct = (predicted == y_test).sum().item()
            accuracy = correct / total
            
            # Calculate loss
            test_loss = loss_function(test_outputs, y_test).item()
        
        # Get model updates (difference from initial state)
        model_updates = {}
        for name, param in self.local_model.named_parameters():
            model_updates[name] = param.detach().cpu().numpy().tolist()
        
        metrics = {
            "accuracy": accuracy,
            "loss": test_loss,
            "num_samples": num_samples,
            "epochs": local_epochs,
            "epoch_losses": epoch_losses
        }
        
        logger.info(f"Local training completed: Accuracy={accuracy:.4f}, Loss={test_loss:.4f}")
        
        return model_updates, metrics
    
    def _submit_update(self, model_updates: Dict, metrics: Dict):
        """Submit model updates to server"""
        try:
            payload = {
                "client_id": self.client_id,
                "round": self.current_round,
                "model_update": model_updates,
                "metrics": metrics,
                "num_samples": metrics["num_samples"],
                "timestamp": datetime.now().isoformat()
            }
            
            response = requests.post(
                f"{self.server_url}/submit_update",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info(f"Model update submitted for round {self.current_round}")
                return True
            else:
                logger.error(f"Failed to submit update: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Update submission error: {e}")
            return False
    
    def _save_local_model(self):
        """Save local model checkpoint"""
        if not self.config["training"]["save_local_models"]:
            return
        
        try:
            models_dir = PROJECT_ROOT / "models" / "federated" / "clients"
            models_dir.mkdir(parents=True, exist_ok=True)
            
            model_path = models_dir / f"{self.client_id}_round_{self.current_round}.pth"
            torch.save(self.local_model.state_dict(), model_path)
            
            logger.info(f"Local model saved: {model_path}")
            
        except Exception as e:
            logger.error(f"Failed to save local model: {e}")
    
    def run_federated_round(self):
        """Execute one round of federated learning"""
        logger.info(f"Starting federated round {self.current_round}")
        
        # Step 1: Download global model
        if not self._download_global_model():
            logger.error("Failed to download global model")
            return False
        
        # Step 2: Local training
        model_updates, metrics = self._local_training()
        if not model_updates:
            logger.error("Local training failed")
            return False
        
        # Step 3: Submit updates
        if not self._submit_update(model_updates, metrics):
            logger.error("Failed to submit updates")
            return False
        
        # Step 4: Save local model
        self._save_local_model()
        
        logger.info(f"Federated round {self.current_round} completed successfully")
        return True
    
    def start_federated_learning(self, max_rounds: Optional[int] = None):
        """Start continuous federated learning"""
        if max_rounds is None:
            max_rounds = self.config.get("federated", {}).get("max_rounds", 10)
        
        logger.info(f"Starting federated learning for {max_rounds} rounds")
        
        for round_num in range(max_rounds):
            logger.info(f"=== Round {round_num + 1}/{max_rounds} ===")
            
            success = self.run_federated_round()
            if not success:
                logger.error(f"Round {round_num + 1} failed, stopping")
                break
            
            # Wait before next round (optional)
            time.sleep(2)
        
        logger.info("Federated learning completed")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Federated Learning Client")
    parser.add_argument("--client-id", required=True, help="Unique client identifier")
    parser.add_argument("--config", default="config.yaml", help="Configuration file")
    parser.add_argument("--server-host", help="Override server host")
    parser.add_argument("--server-port", type=int, help="Override server port")
    parser.add_argument("--data-path", help="Override data path")
    parser.add_argument("--rounds", type=int, help="Number of federated rounds")
    
    args = parser.parse_args()
    
    # Initialize client
    client = FederatedClient(args.client_id, args.config)
    
    # Override config if provided
    if args.server_host:
        client.config["server"]["host"] = args.server_host
    if args.server_port:
        client.config["server"]["port"] = args.server_port
    if args.data_path:
        client.config["data"]["data_path"] = args.data_path
    
    # Reconnect with updated config
    client._connect_to_server()
    
    # Start federated learning
    client.start_federated_learning(args.rounds)

if __name__ == "__main__":
    main()
