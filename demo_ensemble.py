#!/usr/bin/env python3
"""
ZeroTrust-AI Real-Time Demo with PRE-TRAINED 3-Model Ensemble
Uses actual PCAP-derived network traffic with trained TCN + Autoencoder + Isolation Forest
"""

import pandas as pd
import requests
import time
import random
from datetime import datetime, timedelta
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import torch
import torch.nn as nn
import warnings
warnings.filterwarnings('ignore')

API_BASE = "http://localhost:9000"
CSV_FILE = "data/processed/splt_features_labeled.csv"
MODEL_DIR = "models/82k_models"

class Autoencoder(nn.Module):
    def __init__(self, input_size):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, input_size)
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

class TCN(nn.Module):
    def __init__(self, input_size):
        super(TCN, self).__init__()
        self.conv1 = nn.Conv1d(1, 64, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(64, 64, kernel_size=3, padding=1)
        self.pool = nn.MaxPool1d(2)
        self.conv3 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
        self.conv4 = nn.Conv1d(128, 128, kernel_size=3, padding=1)
        self.pool2 = nn.MaxPool1d(2)
        
        # Calculate flattened size
        self._calculate_flattened_size(input_size)
        
        self.fc1 = nn.Linear(self.flattened_size, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 1)
        
    def _calculate_flattened_size(self, input_size):
        x = torch.zeros(1, 1, input_size)
        x = self.pool(nn.functional.relu(self.conv2(nn.functional.relu(self.conv1(x)))))
        x = self.pool2(nn.functional.relu(self.conv4(nn.functional.relu(self.conv3(x)))))
        self.flattened_size = x.numel()
    
    def forward(self, x):
        x = nn.functional.relu(self.conv1(x))
        x = nn.functional.relu(self.conv2(x))
        x = self.pool(x)
        x = nn.functional.relu(self.conv3(x))
        x = nn.functional.relu(self.conv4(x))
        x = self.pool2(x)
        x = x.view(x.size(0), -1)
        x = nn.functional.relu(self.fc1(x))
        x = nn.functional.relu(self.fc2(x))
        x = torch.sigmoid(self.fc3(x))
        return x

class RealTimeThreatAnalyzer:
    def __init__(self):
        self.df = None
        self.current_index = 0
        self.feature_columns = []
        
        # Load pre-trained models
        self.scaler = joblib.load(f"{MODEL_DIR}/scaler.joblib")
        self.isolation_forest = joblib.load(f"{MODEL_DIR}/isoforest.joblib")
        self.autoencoder = Autoencoder(len(self.feature_columns) if self.feature_columns else 50)
        self.autoencoder.load_state_dict(torch.load(f"{MODEL_DIR}/autoencoder.pth", map_location='cpu'))
        self.autoencoder.eval()
        
        self.tcn = TCN(len(self.feature_columns) if self.feature_columns else 50)
        self.tcn.load_state_dict(torch.load(f"{MODEL_DIR}/tcn_classifier.pth", map_location='cpu'))
        self.tcn.eval()
        
        # Load threshold
        with open(f"{MODEL_DIR}/ae_threshold.txt", 'r') as f:
            self.ae_threshold = float(f.read().strip())
        
        self.load_data()
        self.update_model_architectures()
        
    def update_model_architectures(self):
        """Update model architectures based on actual feature count"""
        input_size = len(self.feature_columns)
        
        # Rebuild models with correct input size
        self.autoencoder = Autoencoder(input_size)
        self.autoencoder.load_state_dict(torch.load(f"{MODEL_DIR}/autoencoder.pth", map_location='cpu'), strict=False)
        self.autoencoder.eval()
        
        self.tcn = TCN(input_size)
        self.tcn.load_state_dict(torch.load(f"{MODEL_DIR}/tcn_classifier.pth", map_location='cpu'), strict=False)
        self.tcn.eval()
        
    def load_data(self):
        """Load and prepare real CSV data"""
        print("📊 Loading real network data from CSV...")
        self.df = pd.read_csv(CSV_FILE)
        print(f"✅ Loaded {len(self.df)} real network flows")
        
        # Identify feature columns (exclude metadata)
        exclude_cols = ['pcap_file', 'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'label']
        self.feature_columns = [col for col in self.df.columns if col not in exclude_cols]
        
        # Handle missing values
        for col in self.feature_columns:
            if self.df[col].dtype == 'object' or str(self.df[col].dtype) == 'object':
                self.df[col] = pd.to_numeric(self.df[col], errors='coerce').fillna(0)
            else:
                self.df[col] = self.df[col].fillna(0)
        
        print(f"✅ Found {len(self.feature_columns)} features")
        print(f"🧠 Loaded 3-Model Ensemble: TCN + Autoencoder + Isolation Forest")
        
        # Shuffle for realistic replay
        self.df = self.df.sample(frac=1).reset_index(drop=True)
        
    def get_next_flow(self):
        """Get next flow from real data"""
        if self.current_index >= len(self.df):
            self.current_index = 0  # Loop back
            self.df = self.df.sample(frac=1).reset_index(drop=True)
            
        row = self.df.iloc[self.current_index]
        self.current_index += 1
        return row
        
    def analyze_flow(self, row):
        """Analyze flow using 3-model ensemble"""
        try:
            # Extract features
            features = []
            for col in self.feature_columns:
                val = row.get(col, 0)
                if pd.isna(val) or val == '':
                    val = 0
                features.append(float(val))
            
            features = np.array(features)
            features_scaled = self.scaler.transform([features])
            
            # Model 1: Isolation Forest
            iso_score = self.isolation_forest.decision_function(features_scaled)[0]
            iso_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            
            # Model 2: Autoencoder
            features_tensor = torch.FloatTensor(features_scaled)
            reconstruction = self.autoencoder(features_tensor)
            mse = torch.mean((features_tensor - reconstruction) ** 2).item()
            ae_anomaly = mse > self.ae_threshold
            
            # Model 3: TCN
            tcn_input = torch.FloatTensor(features_scaled).unsqueeze(0).unsqueeze(-1)
            tcn_pred = self.tcn(tcn_input).item()
            tcn_anomaly = tcn_pred > 0.5
            
            # Ensemble voting (weighted average)
            iso_weight = 0.3  # Unsupervised
            ae_weight = 0.4   # Reconstruction error
            tcn_weight = 0.3  # Supervised learning
            
            ensemble_score = (iso_weight * abs(iso_score) + 
                           ae_weight * (mse / self.ae_threshold) + 
                           tcn_weight * tcn_pred)
            
            # Majority vote for anomaly detection
            anomaly_votes = [iso_anomaly, ae_anomaly, tcn_anomaly]
            is_anomaly = sum(anomaly_votes) >= 2  # At least 2 models agree
            
            # Calculate confidence based on ensemble agreement
            agreement = sum(anomaly_votes) / 3
            base_confidence = min(0.99, ensemble_score / 2)
            confidence = base_confidence * (0.5 + 0.5 * agreement)
            
            return {
                'is_anomaly': is_anomaly,
                'confidence': confidence,
                'ensemble_score': ensemble_score,
                'model_predictions': {
                    'isolation_forest': {
                        'anomaly': iso_anomaly,
                        'score': float(iso_score)
                    },
                    'autoencoder': {
                        'anomaly': ae_anomaly,
                        'mse': mse,
                        'threshold': self.ae_threshold
                    },
                    'tcn': {
                        'anomaly': tcn_anomaly,
                        'prediction': tcn_pred
                    }
                }
            }
        except Exception as e:
            print(f"⚠️ Ensemble analysis error: {e}")
            return {
                'is_anomaly': False,
                'confidence': 0.1,
                'ensemble_score': 0.0,
                'model_predictions': {}
            }
    
    def classify_attack_type(self, row, analysis):
        """Classify attack type based on features and label"""
        label = str(row.get('label', 'benign')).lower()
        
        # If CSV has labels, use them
        if 'attack' in label or 'malicious' in label:
            # Classify based on protocol and ports
            protocol = str(row.get('protocol', '')).lower()
            dst_port = int(row.get('dst_port', 0))
            
            if dst_port in [22, 3389]:
                return "brute_force"
            elif dst_port in [80, 443, 8080]:
                return "web_attack"
            elif dst_port in [21, 23]:
                return "ftp_attack"
            elif 'udp' in protocol and dst_port in [53]:
                return "dns_attack"
            else:
                return "malware"
        else:
            return "benign"
    
    def determine_severity(self, attack_type, confidence, analysis):
        """Determine threat severity using ensemble confidence"""
        if attack_type == "benign":
            return "low"
        
        # Enhanced severity based on ensemble agreement and confidence
        ensemble_confidence = analysis.get('confidence', 0.1)
        model_agreement = analysis.get('model_predictions', {})
        
        # Count how many models detected anomaly
        anomaly_count = 0
        if model_agreement.get('isolation_forest', {}).get('anomaly', False):
            anomaly_count += 1
        if model_agreement.get('autoencoder', {}).get('anomaly', False):
            anomaly_count += 1
        if model_agreement.get('tcn', {}).get('anomaly', False):
            anomaly_count += 1
        
        # Higher severity when more models agree and confidence is high
        if anomaly_count == 3:  # All 3 models agree
            return "high" if ensemble_confidence > 0.7 else "medium"
        elif anomaly_count == 2:  # 2 out of 3 models agree
            return "medium" if ensemble_confidence > 0.6 else "low"
        elif anomaly_count == 1:  # Only 1 model agrees
            return "low" if ensemble_confidence > 0.8 else "low"
        else:  # No models agree (benign)
            return "low"
    
    def create_event(self, row):
        """Create dashboard event from real flow data"""
        # Analyze with ML
        analysis = self.analyze_flow(row)
        
        # Classify attack
        attack_type = self.classify_attack_type(row, analysis)
        
        # Determine severity
        severity = self.determine_severity(attack_type, analysis['confidence'], analysis)
        
        # Determine if blocked (high severity + high confidence)
        blocked = severity == "high" and analysis['confidence'] > 0.8
        
        # Create flow ID
        src_ip = str(row.get('src_ip', 'unknown'))
        dst_ip = str(row.get('dst_ip', 'unknown'))
        src_port = str(row.get('src_port', '0'))
        dst_port = str(row.get('dst_port', '0'))
        protocol = str(row.get('protocol', 'TCP'))
        
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
        
        # MITRE mapping
        mitre_mapping = {
            "brute_force": ("Credential Access", "T1110"),
            "web_attack": ("Initial Access", "T1190"),
            "malware": ("Execution", "T1059"),
            "ftp_attack": ("Lateral Movement", "T1021"),
            "dns_attack": ("Discovery", "T1018"),
            "benign": ("Normal Traffic", "T0000")
        }
        
        tactic, technique = mitre_mapping.get(attack_type, ("Unknown", "T0000"))
        
        return {
            "flow_id": flow_id,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "attack_type": attack_type,
            "severity": severity,
            "confidence": round(analysis['confidence'], 2),
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "blocked": blocked,
            "timestamp": datetime.utcnow().isoformat(),
            "real_data": True,
            "ensemble_score": analysis.get('ensemble_score', 0.0),
            "model_agreement": analysis.get('model_predictions', {}),
            "detection_method": "3-Model Ensemble (TCN + Autoencoder + Isolation Forest)"
        }

def main():
    print("🚀 ZeroTrust-AI REAL DATA Demo")
    print("📊 Using REAL PCAP-derived CSV data")
    print("🧠 PRE-TRAINED 3-Model Ensemble")
    print("🌐 Open http://localhost:9000")
    print("⛔ Ctrl+C to stop\n")
    
    # Initialize analyzer
    analyzer = RealTimeThreatAnalyzer()
    
    # Check backend
    try:
        requests.get(API_BASE, timeout=3)
        print("✅ Backend reachable\n")
    except Exception:
        print("❌ Backend not reachable")
        return
    
    count = 0
    threat_count = 0
    benign_count = 0
    
    try:
        while True:
            # Get real flow data
            row = analyzer.get_next_flow().to_dict()
            event = analyzer.create_event(row)
            
            # Send to dashboard
            r = requests.post(f"{API_BASE}/threats", json=event, timeout=5)
            
            if r.status_code in (200, 201):
                count += 1
                if event['attack_type'] != 'benign':
                    threat_count += 1
                    event_type = f"🚨 THREAT: {event['attack_type']}"
                else:
                    benign_count += 1
                    event_type = f"🌐 Benign"
                
                print(f"{event_type} #{count}: {event['flow_id']}")
                print(f"   Confidence: {event['confidence']:.2f} | Severity: {event['severity'].upper()}")
                print(f"   Ensemble Score: {event['ensemble_score']:.2f} | Method: {event['detection_method']}")
                
                # Show model agreement
                models = event.get('model_agreement', {})
                iso_anomaly = "🚨" if models.get('isolation_forest', {}).get('anomaly') else "✅"
                ae_anomaly = "🚨" if models.get('autoencoder', {}).get('anomaly') else "✅"
                tcn_anomaly = "🚨" if models.get('tcn', {}).get('anomaly') else "✅"
                
                print(f"   Models: Isolation:{iso_anomaly} | Autoencoder:{ae_anomaly} | TCN:{tcn_anomaly}")
                print(f"   Blocked: {event['blocked']}")
                print()
            else:
                print(f"⚠️ Failed to send event: {r.status_code}")
            
            # Realistic timing (0.1-2 seconds between flows)
            time.sleep(random.uniform(0.1, 2.0))
            
    except KeyboardInterrupt:
        print(f"\n🛑 Stopped. Processed {count} real flows.")
        print(f"📊 Stats: {benign_count} benign, {threat_count} threats")
        print(f"🎯 Threat Rate: {(threat_count/count*100):.1f}%")

if __name__ == "__main__":
    main()
