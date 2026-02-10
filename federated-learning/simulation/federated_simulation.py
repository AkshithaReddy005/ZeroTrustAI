#!/usr/bin/env python3
"""
Federated Learning Simulation for ZeroTrust-AI
Simulates multiple clients training collaboratively
"""

import os
import sys
import json
import time
import logging
import threading
import subprocess
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

import yaml
import requests
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FederatedSimulation:
    """Federated Learning Simulation Manager"""
    
    def __init__(self, config_path: str = "simulation_config.yaml"):
        self.config = self._load_config(config_path)
        self.server_process = None
        self.client_processes = {}
        self.simulation_results = {}
        self.start_time = None
        
        logger.info("Federated Learning Simulation initialized")
    
    def _load_config(self, config_path: str) -> dict:
        """Load simulation configuration"""
        default_config = {
            "simulation": {
                "name": "federated_demo",
                "duration_minutes": 10,
                "round_interval_seconds": 30,
                "auto_cleanup": True
            },
            "server": {
                "host": "localhost",
                "port": 5000,
                "config_file": "server_config.yaml"
            },
            "clients": [
                {
                    "client_id": "enterprise_a",
                    "data_type": "enterprise",
                    "data_size": 1000,
                    "attack_ratio": 0.3
                },
                {
                    "client_id": "university_b",
                    "data_type": "university", 
                    "data_size": 800,
                    "attack_ratio": 0.2
                },
                {
                    "client_id": "datacenter_c",
                    "data_type": "datacenter",
                    "data_size": 1200,
                    "attack_ratio": 0.4
                }
            ],
            "federated": {
                "rounds": 5,
                "local_epochs": 3,
                "min_clients": 2,
                "aggregation_strategy": "fedavg"
            },
            "visualization": {
                "generate_plots": True,
                "real_time_monitoring": True,
                "save_results": True
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
    
    def _create_server_config(self):
        """Create server configuration file"""
        server_config = {
            "server": {
                "host": self.config["server"]["host"],
                "port": self.config["server"]["port"],
                "debug": False
            },
            "federated": {
                "min_clients": self.config["federated"]["min_clients"],
                "max_clients": len(self.config["clients"]),
                "rounds": self.config["federated"]["rounds"],
                "local_epochs": self.config["federated"]["local_epochs"],
                "learning_rate": 0.001,
                "aggregation_strategy": self.config["federated"]["aggregation_strategy"]
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
        
        config_path = PROJECT_ROOT / "federated-learning" / "server" / self.config["server"]["config_file"]
        with open(config_path, 'w') as f:
            yaml.dump(server_config, f, default_flow_style=False)
        
        logger.info(f"Server config created: {config_path}")
        return config_path
    
    def _create_client_configs(self):
        """Create client configuration files"""
        client_configs = []
        
        for client in self.config["clients"]:
            client_config = {
                "server": {
                    "host": self.config["server"]["host"],
                    "port": self.config["server"]["port"],
                    "protocol": "http"
                },
                "federated": {
                    "local_epochs": self.config["federated"]["local_epochs"],
                    "batch_size": 32,
                    "learning_rate": 0.001,
                    "optimizer": "adam",
                    "loss_function": "cross_entropy"
                },
                "data": {
                    "data_path": f"data/client_{client['client_id']}_data.csv",
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
                    "device": "auto",
                    "save_local_models": True,
                    "log_interval": 10
                }
            }
            
            config_path = PROJECT_ROOT / "federated-learning" / "client" / f"client_{client['client_id']}_config.yaml"
            with open(config_path, 'w') as f:
                yaml.dump(client_config, f, default_flow_style=False)
            
            client_configs.append({
                "client_id": client["client_id"],
                "config_path": config_path
            })
            
            logger.info(f"Client config created: {config_path}")
        
        return client_configs
    
    def _generate_client_data(self):
        """Generate synthetic data for each client"""
        from sklearn.datasets import make_classification
        
        for client in self.config["clients"]:
            logger.info(f"Generating data for client {client['client_id']}")
            
            # Generate synthetic network traffic data
            n_samples = client["data_size"]
            n_features = 12
            n_informative = 8
            n_redundant = 2
            n_clusters_per_class = 2
            
            X, y = make_classification(
                n_samples=n_samples,
                n_features=n_features,
                n_informative=n_informative,
                n_redundant=n_redundant,
                n_clusters_per_class=n_clusters_per_class,
                flip_y=0.05,
                random_state=42 + hash(client["client_id"]) % 100
            )
            
            # Adjust attack ratio
            current_attack_ratio = sum(y) / len(y)
            target_attack_ratio = client["attack_ratio"]
            
            if abs(current_attack_ratio - target_attack_ratio) > 0.05:
                # Resample to achieve target ratio
                n_attacks = int(n_samples * target_attack_ratio)
                n_benign = n_samples - n_attacks
                
                # Get indices
                attack_indices = [i for i, label in enumerate(y) if label == 1]
                benign_indices = [i for i, label in enumerate(y) if label == 0]
                
                # Resample
                import random
                selected_attacks = random.choices(attack_indices, k=n_attacks)
                selected_benign = random.choices(benign_indices, k=n_benign)
                
                selected_indices = selected_attacks + selected_benign
                random.shuffle(selected_indices)
                
                X = X[selected_indices]
                y = y[selected_indices]
            
            # Create feature names
            feature_names = [
                'total_packets', 'total_bytes', 'avg_packet_size', 'std_packet_size',
                'flow_duration', 'bytes_per_second', 'packets_per_second',
                'src_to_dst_bytes', 'dst_to_src_bytes', 'src_to_dst_packets',
                'dst_to_src_packets', 'tcp_flags'
            ]
            
            # Create DataFrame
            df = pd.DataFrame(X, columns=feature_names)
            df['label'] = y
            df['flow_id'] = [f"{client['client_id']}_flow_{i}" for i in range(len(df))]
            
            # Add client-specific characteristics
            if client["data_type"] == "enterprise":
                # Enterprise: moderate traffic, balanced patterns
                df['total_packets'] *= 1.2
                df['total_bytes'] *= 1.5
            elif client["data_type"] == "university":
                # University: variable traffic, more web traffic
                df['total_packets'] *= 0.8
                df['flow_duration'] *= 1.3
            elif client["data_type"] == "datacenter":
                # Datacenter: high volume, consistent patterns
                df['total_packets'] *= 2.0
                df['total_bytes'] *= 2.5
                df['flow_duration'] *= 0.7
            
            # Save data
            data_path = PROJECT_ROOT / "federated-learning" / "client" / f"data/client_{client['client_id']}_data.csv"
            data_path.parent.mkdir(parents=True, exist_ok=True)
            df.to_csv(data_path, index=False)
            
            logger.info(f"Generated {len(df)} samples for client {client['client_id']}")
            logger.info(f"Attack ratio: {sum(y)/len(y):.3f}")
    
    def _start_server(self):
        """Start the federated server"""
        logger.info("Starting federated server...")
        
        server_config_path = self._create_server_config()
        server_script = PROJECT_ROOT / "federated-learning" / "server" / "federated_server.py"
        
        cmd = [
            sys.executable, str(server_script),
            "--config", str(server_config_path),
            "--host", self.config["server"]["host"],
            "--port", str(self.config["server"]["port"])
        ]
        
        self.server_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(PROJECT_ROOT)
        )
        
        # Wait for server to start
        time.sleep(5)
        
        # Check if server is running
        try:
            response = requests.get(f"http://{self.config['server']['host']}:{self.config['server']['port']}/health", timeout=5)
            if response.status_code == 200:
                logger.info("Server started successfully")
                return True
            else:
                logger.error(f"Server health check failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            return False
    
    def _start_clients(self):
        """Start all federated clients"""
        client_configs = self._create_client_configs()
        
        for client_config in client_configs:
            client_id = client_config["client_id"]
            logger.info(f"Starting client {client_id}...")
            
            client_script = PROJECT_ROOT / "federated-learning" / "client" / "federated_client.py"
            
            cmd = [
                sys.executable, str(client_script),
                "--client-id", client_id,
                "--config", str(client_config["config_path"]),
                "--server-host", self.config["server"]["host"],
                "--server-port", str(self.config["server"]["port"]),
                "--rounds", str(self.config["federated"]["rounds"])
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(PROJECT_ROOT)
            )
            
            self.client_processes[client_id] = process
            
            # Stagger client starts
            time.sleep(2)
        
        logger.info(f"Started {len(self.client_processes)} clients")
    
    def _monitor_simulation(self):
        """Monitor the federated learning simulation"""
        if not self.config["visualization"]["real_time_monitoring"]:
            return
        
        server_url = f"http://{self.config['server']['host']}:{self.config['server']['port']}"
        
        while self._is_simulation_running():
            try:
                response = requests.get(f"{server_url}/status", timeout=5)
                if response.status_code == 200:
                    status = response.json()
                    
                    # Log status
                    logger.info(f"Round {status['round']}/{status['total_rounds']}, "
                              f"Clients: {status['connected_clients']}, "
                              f"Ready: {status['ready_for_aggregation']}")
                    
                    # Store results
                    self.simulation_results[datetime.now()] = status
                
            except Exception as e:
                logger.warning(f"Monitoring error: {e}")
            
            time.sleep(self.config["simulation"]["round_interval_seconds"])
    
    def _is_simulation_running(self) -> bool:
        """Check if simulation is still running"""
        if self.server_process and self.server_process.poll() is not None:
            return False
        
        for client_id, process in self.client_processes.items():
            if process.poll() is not None:
                logger.warning(f"Client {client_id} has stopped")
        
        return True
    
    def _cleanup(self):
        """Cleanup simulation processes"""
        logger.info("Cleaning up simulation...")
        
        # Stop clients
        for client_id, process in self.client_processes.items():
            if process.poll() is None:
                logger.info(f"Stopping client {client_id}")
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
        
        # Stop server
        if self.server_process and self.server_process.poll() is None:
            logger.info("Stopping server")
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
    
    def _generate_visualizations(self):
        """Generate visualization plots"""
        if not self.config["visualization"]["generate_plots"]:
            return
        
        logger.info("Generating visualization plots...")
        
        # Create output directory
        output_dir = PROJECT_ROOT / "federated-learning" / "simulation" / "results"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Plot 1: Simulation timeline
        if self.simulation_results:
            timestamps = list(self.simulation_results.keys())
            rounds = [status["round"] for status in self.simulation_results.values()]
            clients = [status["connected_clients"] for status in self.simulation_results.values()]
            
            plt.figure(figsize=(12, 6))
            plt.subplot(2, 1, 1)
            plt.plot(timestamps, rounds, 'b-', linewidth=2)
            plt.title('Federated Learning Progress')
            plt.ylabel('Round Number')
            plt.grid(True)
            
            plt.subplot(2, 1, 2)
            plt.plot(timestamps, clients, 'g-', linewidth=2)
            plt.xlabel('Time')
            plt.ylabel('Connected Clients')
            plt.grid(True)
            
            plt.tight_layout()
            plt.savefig(output_dir / "simulation_timeline.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        # Plot 2: Client data distribution
        client_data = []
        for client in self.config["clients"]:
            data_path = PROJECT_ROOT / "federated-learning" / "client" / f"data/client_{client['client_id']}_data.csv"
            if data_path.exists():
                df = pd.read_csv(data_path)
                attack_ratio = df['label'].mean()
                client_data.append({
                    "client": client["client_id"],
                    "data_type": client["data_type"],
                    "samples": len(df),
                    "attack_ratio": attack_ratio
                })
        
        if client_data:
            df_clients = pd.DataFrame(client_data)
            
            plt.figure(figsize=(10, 6))
            colors = sns.color_palette("husl", len(df_clients))
            
            plt.subplot(1, 2, 1)
            plt.bar(df_clients["client"], df_clients["samples"], color=colors)
            plt.title('Client Data Sizes')
            plt.ylabel('Number of Samples')
            plt.xticks(rotation=45)
            
            plt.subplot(1, 2, 2)
            plt.bar(df_clients["client"], df_clients["attack_ratio"], color=colors)
            plt.title('Client Attack Ratios')
            plt.ylabel('Attack Ratio')
            plt.xticks(rotation=45)
            
            plt.tight_layout()
            plt.savefig(output_dir / "client_distribution.png", dpi=300, bbox_inches='tight')
            plt.close()
        
        logger.info(f"Visualizations saved to {output_dir}")
    
    def _save_results(self):
        """Save simulation results"""
        if not self.config["visualization"]["save_results"]:
            return
        
        results_dir = PROJECT_ROOT / "federated-learning" / "simulation" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Save simulation configuration
        config_path = results_dir / "simulation_config.yaml"
        with open(config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
        
        # Save monitoring results
        if self.simulation_results:
            results_data = []
            for timestamp, status in self.simulation_results.items():
                status["timestamp"] = timestamp.isoformat()
                results_data.append(status)
            
            results_path = results_dir / "simulation_results.json"
            with open(results_path, 'w') as f:
                json.dump(results_data, f, indent=2)
        
        logger.info(f"Results saved to {results_dir}")
    
    def run_simulation(self):
        """Run the complete federated learning simulation"""
        logger.info("Starting Federated Learning Simulation")
        self.start_time = datetime.now()
        
        try:
            # Step 1: Generate client data
            self._generate_client_data()
            
            # Step 2: Start server
            if not self._start_server():
                logger.error("Failed to start server")
                return False
            
            # Step 3: Start clients
            self._start_clients()
            
            # Step 4: Monitor simulation
            monitor_thread = threading.Thread(target=self._monitor_simulation)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Step 5: Wait for completion
            duration_minutes = self.config["simulation"]["duration_minutes"]
            logger.info(f"Simulation running for {duration_minutes} minutes...")
            
            time.sleep(duration_minutes * 60)
            
            # Step 6: Generate outputs
            self._generate_visualizations()
            self._save_results()
            
            logger.info("Simulation completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Simulation failed: {e}")
            return False
        
        finally:
            # Step 7: Cleanup
            if self.config["simulation"]["auto_cleanup"]:
                self._cleanup()

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Federated Learning Simulation")
    parser.add_argument("--config", default="simulation_config.yaml", help="Simulation configuration")
    parser.add_argument("--duration", type=int, help="Simulation duration in minutes")
    parser.add_argument("--rounds", type=int, help="Number of federated rounds")
    parser.add_argument("--clients", type=int, help="Number of clients")
    
    args = parser.parse_args()
    
    # Initialize simulation
    sim = FederatedSimulation(args.config)
    
    # Override config if provided
    if args.duration:
        sim.config["simulation"]["duration_minutes"] = args.duration
    if args.rounds:
        sim.config["federated"]["rounds"] = args.rounds
    if args.clients:
        # Adjust client list
        base_clients = sim.config["clients"][:args.clients]
        sim.config["clients"] = base_clients
    
    # Run simulation
    success = sim.run_simulation()
    
    if success:
        logger.info("Federated Learning Simulation completed successfully")
    else:
        logger.error("Federated Learning Simulation failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
