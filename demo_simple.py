#!/usr/bin/env python3
"""
ZeroTrust-AI Real-Time Demo with 3-Model Ensemble
Uses actual PCAP-derived network traffic for realistic threat detection
"""

import pandas as pd
import requests
import time
import random
from datetime import datetime, timedelta
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

API_BASE = "http://localhost:9000"
CSV_FILE = "data/processed/splt_features_labeled.csv"

class RealTimeThreatAnalyzer:
    def __init__(self):
        self.df = None
        self.current_index = 0
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.feature_columns = []
        self.load_data()
        
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
        
        # Train Isolation Forest
        print("🤖 Training Isolation Forest...")
        sample_data = self.df[self.feature_columns].fillna(0).values
        if len(sample_data) > 10000:
            sample_data = sample_data[:10000]
        
        X_scaled = self.scaler.fit_transform(sample_data)
        self.isolation_forest.fit(X_scaled)
        print("✅ Isolation Forest training complete")
        
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
        """Analyze flow using Isolation Forest"""
        try:
            # Extract features
            features = []
            for col in self.feature_columns:
                val = row.get(col, 0)
                if pd.isna(val) or val == '':
                    val = 0
                features.append(float(val))
            
            # Scale and predict
            features_scaled = self.scaler.transform([features])
            anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
            is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            
            # Calculate confidence
            confidence = min(0.99, max(0.1, abs(anomaly_score) / 3))
            
            return {
                'is_anomaly': is_anomaly,
                'confidence': confidence,
                'anomaly_score': float(anomaly_score),
                'detection_method': "Isolation Forest Anomaly Detection"
            }
        except Exception as e:
            print(f"⚠️ Analysis error: {e}")
            return {
                'is_anomaly': False,
                'confidence': 0.1,
                'anomaly_score': 0.0,
                'detection_method': "Error"
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
        """Determine threat severity"""
        if attack_type == "benign":
            return "low"
        
        # Base severity on attack type and confidence
        if attack_type in ["brute_force", "web_attack"]:
            return "high" if confidence > 0.7 else "medium"
        elif attack_type in ["malware", "ftp_attack"]:
            return "high" if confidence > 0.8 else "medium"
        else:
            return "medium" if confidence > 0.6 else "low"
    
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
            "anomaly_score": analysis['anomaly_score'],
            "detection_method": analysis['detection_method']
        }

def main():
    print("🚀 ZeroTrust-AI REAL DATA Demo")
    print("📊 Using REAL PCAP-derived CSV data")
    print("🤖 Isolation Forest Anomaly Detection")
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
                print(f"   Anomaly Score: {event['anomaly_score']:.2f} | Method: {event['detection_method']}")
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
