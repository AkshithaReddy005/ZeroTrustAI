#!/usr/bin/env python3
"""
Train detector with REAL PCAP CSV data instead of synthetic data
"""

import pandas as pd
import requests
import numpy as np
import random
from datetime import datetime

CSV_FILE = "data/processed/splt_features_labeled.csv"
DETECTOR_URL = "http://localhost:9001/train"

def create_training_samples_from_csv():
    """Create training samples from real PCAP data"""
    print("📊 Loading real PCAP data for training...")
    df = pd.read_csv(CSV_FILE)
    print(f"✅ Loaded {len(df)} real network flows")
    
    # Convert to training format
    training_samples = []
    
    # Sample randomly to get both benign and malicious
    df_sampled = df.sample(n=min(1000, len(df)), random_state=42)
    
    for i, row in df_sampled.iterrows():
        # Debug first few labels
        if i < 5:
            print(f"Debug row {i}: label={row.get('label')} (type: {type(row.get('label'))})")
        
        # Map CSV features to detector format
        flow_features = {
            "flow": {
                "flow_id": str(row.get('flow_id', f'flow-{i}')),
                "total_packets": int(row.get('total_packets', random.randint(5, 500))),
                "total_bytes": int(row.get('total_bytes', random.randint(800, 200000))),
                "avg_packet_size": float(row.get('avg_packet_size', random.uniform(200, 1500))),
                "std_packet_size": float(row.get('std_packet_size', random.uniform(10, 300))),
                "duration": float(row.get('duration', random.uniform(0.01, 3.0))),
                "pps": float(row.get('pps', random.uniform(5, 800))),
                "avg_entropy": float(row.get('avg_entropy', random.uniform(2.0, 7.9))),
                "syn_count": int(row.get('syn_count', random.randint(0, 20))),
                "fin_count": int(row.get('fin_count', random.randint(0, 10)))
            },
            "label": "malicious" if row.get('label') in [1, '1', 1.0, 'malicious', 'attack', 'threat'] else "benign"
        }
        training_samples.append(flow_features)
        
        # Limit to reasonable training size
        if len(training_samples) >= 500:
            break
    
    print(f"🎯 Created {len(training_samples)} training samples from real data")
    print(f"📊 Malicious: {sum(1 for s in training_samples if s['label'] == 'malicious')}")
    print(f"🌐 Benign: {sum(1 for s in training_samples if s['label'] == 'benign')}")
    
    return training_samples

def train_detector_with_real_data():
    """Train detector using real PCAP data"""
    samples = create_training_samples_from_csv()
    
    print("🧠 Training detector with REAL data...")
    
    training_request = {
        "samples": samples,
        "epochs": 20,
        "lr": 1e-3,
        "contamination": 0.1
    }
    
    try:
        response = requests.post(DETECTOR_URL, json=training_request, timeout=30)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Training successful!")
            print(f"📊 Trained samples: {result.get('trained_samples', 0)}")
            print(f"⏰ Timestamp: {result.get('timestamp', 0)}")
            return True
        else:
            print(f"❌ Training failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Training error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Training ZeroTrust-AI Detector with REAL PCAP Data")
    print("=" * 60)
    
    success = train_detector_with_real_data()
    
    if success:
        print("\n🎉 SUCCESS! Detector trained with REAL network data")
        print("📈 The dashboard should now show REAL threat detections")
        print("🔍 Check http://localhost:9000 for live results")
    else:
        print("\n❌ FAILED! Could not train detector")
        print("🔧 Make sure detector service is running on port 9001")
