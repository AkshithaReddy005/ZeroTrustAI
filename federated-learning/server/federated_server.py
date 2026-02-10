#!/usr/bin/env python3
"""
Federated Learning Server for ZeroTrust-AI
Implements FedAvg aggregation and client coordination
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
import numpy as np
import yaml
from flask import Flask, request, jsonify
from flask_cors import CORS

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

class FederatedServer:
    """Federated Learning Server with FedAvg aggregation"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.global_model = None
        self.client_updates = {}
        self.round_number = 0
        self.client_metrics = {}
        self.aggregation_history = []
        
        # Initialize Flask app
        self.app = Flask(__name__)
        CORS(self.app)
        
        # Setup routes
        self._setup_routes()
        
        # Initialize global model
        self._initialize_global_model()
        
        logger.info("Federated Server initialized")
    
    def _load_config(self, config_path: str) -> dict:
        """Load server configuration"""
        default_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 5000,
                "debug": False
            },
            "federated": {
                "min_clients": 2,
                "max_clients": 10,
                "rounds": 10,
                "local_epochs": 5,
                "learning_rate": 0.001,
                "aggregation_strategy": "fedavg"
            },
            "model": {
                "input_size": 12,
                "hidden_size": 64,
                "num_classes": 2,
                "sequence_length": 50
            },
            "security": {
                "require_auth": False,
                "api_key": None,
                "update_validation": True
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
    
    def _initialize_global_model(self):
        """Initialize the global TCN model"""
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
        
        self.global_model = TCN(
            in_ch=self.config["model"]["input_size"],
            n_classes=self.config["model"]["num_classes"]
        )
        
        # Load pretrained model if available
        model_path = PROJECT_ROOT / "models" / "tcn_classifier.pth"
        if model_path.exists():
            try:
                self.global_model.load_state_dict(torch.load(model_path, map_location='cpu'))
                logger.info("Loaded pretrained global model")
            except Exception as e:
                logger.warning(f"Could not load pretrained model: {e}")
        
        self.global_model.eval()
        logger.info("Global model initialized")
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                "status": "healthy",
                "round": self.round_number,
                "connected_clients": len(self.client_updates),
                "timestamp": datetime.now().isoformat()
            })
        
        @self.app.route('/register', methods=['POST'])
        def register_client():
            """Register a new client"""
            try:
                data = request.get_json()
                client_id = data.get('client_id')
                client_info = data.get('client_info', {})
                
                if not client_id:
                    return jsonify({"error": "client_id required"}), 400
                
                if client_id in self.client_updates:
                    logger.info(f"Client {client_id} re-registered")
                
                self.client_updates[client_id] = {
                    "status": "registered",
                    "last_update": None,
                    "client_info": client_info
                }
                
                logger.info(f"Client {client_id} registered: {client_info}")
                
                return jsonify({
                    "status": "registered",
                    "client_id": client_id,
                    "global_round": self.round_number
                })
                
            except Exception as e:
                logger.error(f"Registration error: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/get_global_model', methods=['GET'])
        def get_global_model():
            """Send current global model to client"""
            try:
                client_id = request.args.get('client_id')
                if not client_id:
                    return jsonify({"error": "client_id required"}), 400
                
                if client_id not in self.client_updates:
                    return jsonify({"error": "Client not registered"}), 404
                
                # Serialize model state dict
                model_state = self.global_model.state_dict()
                serialized_state = {k: v.tolist() for k, v in model_state.items()}
                
                response = {
                    "round": self.round_number,
                    "model_state": serialized_state,
                    "config": self.config["federated"],
                    "timestamp": datetime.now().isoformat()
                }
                
                logger.info(f"Global model sent to client {client_id}")
                return jsonify(response)
                
            except Exception as e:
                logger.error(f"Model distribution error: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/submit_update', methods=['POST'])
        def submit_update():
            """Receive model update from client"""
            try:
                data = request.get_json()
                client_id = data.get('client_id')
                round_num = data.get('round')
                model_update = data.get('model_update')
                metrics = data.get('metrics', {})
                num_samples = data.get('num_samples', 1)
                
                if not all([client_id, round_num, model_update]):
                    return jsonify({"error": "Missing required fields"}), 400
                
                if client_id not in self.client_updates:
                    return jsonify({"error": "Client not registered"}), 404
                
                if round_num != self.round_number:
                    return jsonify({"error": f"Round mismatch. Expected {self.round_number}, got {round_num}"}), 400
                
                # Convert lists back to tensors
                update_tensors = {}
                for k, v in model_update.items():
                    if isinstance(v, list):
                        update_tensors[k] = torch.tensor(v)
                    else:
                        update_tensors[k] = v
                
                # Store client update
                self.client_updates[client_id].update({
                    "status": "updated",
                    "last_update": datetime.now().isoformat(),
                    "round": round_num,
                    "model_update": update_tensors,
                    "metrics": metrics,
                    "num_samples": num_samples
                })
                
                self.client_metrics[client_id] = metrics
                
                logger.info(f"Received update from client {client_id} for round {round_num}")
                
                # Check if we have enough updates for aggregation
                if self._ready_for_aggregation():
                    threading.Thread(target=self._aggregate_updates).start()
                
                return jsonify({
                    "status": "received",
                    "round": round_num,
                    "client_id": client_id
                })
                
            except Exception as e:
                logger.error(f"Update submission error: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/status', methods=['GET'])
        def get_status():
            """Get server status and metrics"""
            return jsonify({
                "round": self.round_number,
                "total_rounds": self.config["federated"]["rounds"],
                "connected_clients": len(self.client_updates),
                "ready_for_aggregation": self._ready_for_aggregation(),
                "client_metrics": self.client_metrics,
                "aggregation_history": self.aggregation_history[-5:],  # Last 5 rounds
                "timestamp": datetime.now().isoformat()
            })
    
    def _ready_for_aggregation(self) -> bool:
        """Check if enough clients have submitted updates"""
        min_clients = self.config["federated"]["min_clients"]
        updated_clients = sum(1 for client in self.client_updates.values() 
                            if client.get("status") == "updated" and 
                            client.get("round") == self.round_number)
        return updated_clients >= min_clients
    
    def _aggregate_updates(self):
        """Aggregate client updates using FedAvg"""
        try:
            logger.info(f"Starting aggregation for round {self.round_number}")
            
            # Collect updates from current round
            round_updates = {}
            total_samples = 0
            
            for client_id, client_data in self.client_updates.items():
                if (client_data.get("status") == "updated" and 
                    client_data.get("round") == self.round_number):
                    
                    update = client_data["model_update"]
                    num_samples = client_data["num_samples"]
                    
                    round_updates[client_id] = {
                        "update": update,
                        "num_samples": num_samples
                    }
                    total_samples += num_samples
            
            if not round_updates:
                logger.error("No updates found for aggregation")
                return
            
            # Perform FedAvg aggregation
            aggregated_state = {}
            
            # Get parameter names from first client
            first_client = list(round_updates.values())[0]
            param_names = first_client["update"].keys()
            
            for param_name in param_names:
                weighted_sum = None
                for client_data in round_updates.values():
                    update = client_data["update"]
                    weight = client_data["num_samples"] / total_samples
                    
                    if weighted_sum is None:
                        weighted_sum = update[param_name] * weight
                    else:
                        weighted_sum += update[param_name] * weight
                
                aggregated_state[param_name] = weighted_sum
            
            # Update global model
            self.global_model.load_state_dict(aggregated_state)
            
            # Calculate aggregation metrics
            avg_accuracy = np.mean([
                client_data["metrics"].get("accuracy", 0) 
                for client_data in round_updates.values()
            ])
            
            avg_loss = np.mean([
                client_data["metrics"].get("loss", 0) 
                for client_data in round_updates.values()
            ])
            
            # Record aggregation
            aggregation_record = {
                "round": self.round_number,
                "timestamp": datetime.now().isoformat(),
                "num_clients": len(round_updates),
                "total_samples": total_samples,
                "avg_accuracy": avg_accuracy,
                "avg_loss": avg_loss,
                "client_ids": list(round_updates.keys())
            }
            
            self.aggregation_history.append(aggregation_record)
            
            # Save global model
            self._save_global_model()
            
            logger.info(f"Round {self.round_number} aggregation complete:")
            logger.info(f"  - Clients: {len(round_updates)}")
            logger.info(f"  - Samples: {total_samples}")
            logger.info(f"  - Avg Accuracy: {avg_accuracy:.4f}")
            logger.info(f"  - Avg Loss: {avg_loss:.4f}")
            
            # Increment round
            self.round_number += 1
            
            # Reset client statuses for next round
            for client_data in self.client_updates.values():
                if client_data.get("round") == self.round_number - 1:
                    client_data["status"] = "registered"
            
        except Exception as e:
            logger.error(f"Aggregation error: {e}")
    
    def _save_global_model(self):
        """Save current global model"""
        try:
            models_dir = PROJECT_ROOT / "models" / "federated"
            models_dir.mkdir(exist_ok=True)
            
            model_path = models_dir / f"global_model_round_{self.round_number}.pth"
            torch.save(self.global_model.state_dict(), model_path)
            
            # Also save as latest
            latest_path = models_dir / "global_model_latest.pth"
            torch.save(self.global_model.state_dict(), latest_path)
            
            logger.info(f"Global model saved for round {self.round_number}")
            
        except Exception as e:
            logger.error(f"Model saving error: {e}")
    
    def run(self):
        """Start the federated server"""
        host = self.config["server"]["host"]
        port = self.config["server"]["port"]
        debug = self.config["server"]["debug"]
        
        logger.info(f"Starting Federated Server on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug, threaded=True)

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Federated Learning Server")
    parser.add_argument("--config", default="config.yaml", help="Configuration file")
    parser.add_argument("--host", default=None, help="Override host")
    parser.add_argument("--port", type=int, default=None, help="Override port")
    
    args = parser.parse_args()
    
    # Initialize server
    server = FederatedServer(args.config)
    
    # Override config if provided
    if args.host:
        server.config["server"]["host"] = args.host
    if args.port:
        server.config["server"]["port"] = args.port
    
    # Start server
    server.run()

if __name__ == "__main__":
    main()
