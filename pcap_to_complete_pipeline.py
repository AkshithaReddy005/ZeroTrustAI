#!/usr/bin/env python3
"""
ZeroTrust-AI Complete Pipeline: PCAP → SPLT → 3 Models → Ensemble → Meta-Learning → Dashboard
============================================================================================
Complete end-to-end pipeline:
1. Extract SPLT features from PCAP files
2. Score with 3 models (TCN, Autoencoder, Isolation Forest)
3. Ensemble fusion with learned weights
4. Meta-learning for adaptive trust scoring
5. Send real-time results to dashboard
"""

import sys
import os
import time
import json
import requests
import dpkt
import socket
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from collections import defaultdict
import joblib
from sklearn.preprocessing import StandardScaler

# Configuration
WS_SERVER = "http://localhost:9001"  # Your detector API
REPO_ROOT = Path(__file__).resolve().parent
RAW_DIR = REPO_ROOT / "data" / "raw"
MODEL_DIR = REPO_ROOT / "c2_ddos" / "scripts" / "models"
DELAY = 0.3
MAX_FLOWS_PER_MINUTE = 150

# SPLT Configuration
SEQ_LEN = 20  # First 20 packets for SPLT

# ── SPLT FEATURE EXTRACTION ─────────────────────────────────────────────────────

def extract_splt_features(pcap_path: Path) -> List[Dict[str, Any]]:
    """Extract SPLT features from PCAP file"""
    print(f"📂 Extracting SPLT from: {pcap_path.name}")
    
    flows = {}
    try:
        with open(pcap_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    
                    ip = eth.data
                    if not hasattr(ip, 'p'):
                        continue
                    
                    # Get transport layer
                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        l4 = ip.data
                        if not isinstance(l4, dpkt.tcp.TCP):
                            continue
                    elif ip.p == dpkt.ip.IP_PROTO_UDP:
                        l4 = ip.data
                        if not isinstance(l4, dpkt.udp.UDP):
                            continue
                    else:
                        continue
                    
                    # Extract 5-tuple
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    src_port = getattr(l4, 'sport', 0)
                    dst_port = getattr(l4, 'dport', 0)
                    proto = ip.p
                    
                    flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}"
                    
                    # Initialize flow if not exists
                    if flow_key not in flows:
                        flows[flow_key] = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': proto,
                            'packet_lengths': [],
                            'packet_times': [],
                            'first_time': ts,
                            'last_time': ts,
                            'total_bytes': 0,
                            'total_packets': 0
                        }
                    
                    flow = flows[flow_key]
                    
                    # Add packet info
                    packet_len = len(buf)
                    flow['packet_lengths'].append(packet_len)
                    flow['packet_times'].append(ts)
                    flow['total_bytes'] += packet_len
                    flow['total_packets'] += 1
                    flow['last_time'] = ts
                    
                except Exception:
                    continue
    
    except Exception as e:
        print(f"❌ Error reading PCAP: {e}")
        return []
    
    # Convert to SPLT features
    splt_flows = []
    for flow_key, flow in flows.items():
        if len(flow['packet_lengths']) < 2:  # Need at least 2 packets
            continue
        
        # Calculate basic flow metrics
        duration = flow['last_time'] - flow['first_time']
        pps = flow['total_packets'] / max(duration, 0.001)
        bps = flow['total_bytes'] / max(duration, 0.001)
        
        # Extract SPLT (first SEQ_LEN packets)
        packet_lengths = flow['packet_lengths'][:SEQ_LEN]
        packet_times = flow['packet_times'][:SEQ_LEN]
        
        # Calculate inter-arrival times
        iat = []
        for i in range(1, len(packet_times)):
            iat.append(packet_times[i] - packet_times[i-1])
        
        # Pad sequences to SEQ_LEN
        while len(packet_lengths) < SEQ_LEN:
            packet_lengths.append(0)
        while len(iat) < SEQ_LEN - 1:
            iat.append(0)
        
        # Create SPLT feature vector (lengths + iats)
        splt_features = packet_lengths + iat[:SEQ_LEN-1]
        
        splt_flows.append({
            'flow_id': flow_key,
            'src_ip': flow['src_ip'],
            'dst_ip': flow['dst_ip'],
            'src_port': flow['src_port'],
            'dst_port': flow['dst_port'],
            'protocol': flow['protocol'],
            'duration': duration,
            'total_packets': flow['total_packets'],
            'total_bytes': flow['total_bytes'],
            'pps': pps,
            'bps': bps,
            'splt_features': splt_features,
            'packet_lengths': packet_lengths,
            'inter_arrival_times': iat[:SEQ_LEN-1]
        })
    
    print(f"✅ Extracted {len(splt_flows)} flows with SPLT features")
    return splt_flows

# ── 3-MODEL ENSEMBLE WITH META-LEARNING ───────────────────────────────────────────

class MetaLearningEnsemble:
    """Meta-learning ensemble for adaptive threat detection"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.meta_learner = None
        self.experience_buffer = []
        self.load_models()
    
    def load_models(self):
        """Load the 3 trained models"""
        try:
            # TCN Model
            tcn_path = MODEL_DIR / "tcn_model.pth"
            if tcn_path.exists():
                self.models['tcn'] = torch.load(tcn_path, map_location='cpu')
                self.models['tcn'].eval()
                print("✅ TCN model loaded")
            
            # Autoencoder
            ae_path = MODEL_DIR / "autoencoder.pt"
            if ae_path.exists():
                self.models['ae'] = torch.load(ae_path, map_location='cpu')
                self.models['ae'].eval()
                print("✅ Autoencoder model loaded")
            
            # Isolation Forest
            iso_path = MODEL_DIR / "isolation_forest.pkl"
            if iso_path.exists():
                self.models['iso'] = joblib.load(iso_path)
                print("✅ Isolation Forest model loaded")
            
            # Load scalers
            scaler_path = MODEL_DIR / "scaler_splt_focused.joblib"
            if scaler_path.exists():
                self.scalers['splt'] = joblib.load(scaler_path)
            
            # Ensemble config
            config_path = MODEL_DIR / "ensemble_config.pkl"
            if config_path.exists():
                config = joblib.load(config_path)
                self.weights = config.get('weights', {'tcn': 0.7, 'ae': 0.2, 'iso': 0.1})
                self.threshold = config.get('quarantine_threshold', 0.5)
                print(f"✅ Ensemble weights: {self.weights}")
            
        except Exception as e:
            print(f"⚠️ Model loading error: {e}")
            self.weights = {'tcn': 0.7, 'ae': 0.2, 'iso': 0.1}
            self.threshold = 0.5
    
    def extract_features(self, flow_data: Dict[str, Any]) -> np.ndarray:
        """Extract features for model input"""
        splt_features = flow_data['splt_features']
        
        # Add volumetric features
        features = splt_features + [
            flow_data['duration'],
            flow_data['total_packets'],
            flow_data['total_bytes'],
            flow_data['pps'],
            flow_data['bps']
        ]
        
        return np.array(features)
    
    def score_with_models(self, flow_data: Dict[str, Any]) -> Dict[str, float]:
        """Score flow with all 3 models"""
        features = self.extract_features(flow_data)
        scores = {}
        
        try:
            # TCN scoring
            if 'tcn' in self.models and 'splt' in self.scalers:
                features_scaled = self.scalers['splt'].transform(features.reshape(1, -1))
                with torch.no_grad():
                    tcn_input = torch.FloatTensor(features_scaled).unsqueeze(0).unsqueeze(0)
                    tcn_output = self.models['tcn'](tcn_input)
                    scores['tcn'] = float(torch.sigmoid(tcn_output).item())
            else:
                scores['tcn'] = 0.5
            
            # Autoencoder scoring
            if 'ae' in self.models:
                with torch.no_grad():
                    ae_input = torch.FloatTensor(features).unsqueeze(0)
                    ae_output = self.models['ae'](ae_input)
                    reconstruction_error = torch.mean((ae_input - ae_output) ** 2).item()
                    scores['ae'] = min(reconstruction_error / 10.0, 1.0)  # Normalize
            else:
                scores['ae'] = 0.5
            
            # Isolation Forest scoring
            if 'iso' in self.models:
                iso_score = self.models['iso'].decision_function(features.reshape(1, -1))[0]
                scores['iso'] = (iso_score + 1) / 2  # Normalize to 0-1
            else:
                scores['iso'] = 0.5
                
        except Exception as e:
            print(f"⚠️ Scoring error: {e}")
            scores = {'tcn': 0.5, 'ae': 0.5, 'iso': 0.5}
        
        return scores
    
    def ensemble_fusion(self, model_scores: Dict[str, float]) -> float:
        """Ensemble fusion with learned weights"""
        ensemble_score = (
            model_scores['tcn'] * self.weights['tcn'] +
            model_scores['ae'] * self.weights['ae'] +
            model_scores['iso'] * self.weights['iso']
        )
        return ensemble_score
    
    def meta_learning_update(self, flow_data: Dict, model_scores: Dict, ensemble_score: float):
        """Meta-learning: learn from experience"""
        # Add to experience buffer
        experience = {
            'features': self.extract_features(flow_data),
            'model_scores': model_scores,
            'ensemble_score': ensemble_score,
            'timestamp': time.time()
        }
        self.experience_buffer.append(experience)
        
        # Keep buffer size manageable
        if len(self.experience_buffer) > 1000:
            self.experience_buffer = self.experience_buffer[-1000:]
        
        # Update weights based on performance (simple adaptive learning)
        if len(self.experience_buffer) > 50:
            # Analyze recent performance and adjust weights
            recent_scores = [exp['ensemble_score'] for exp in self.experience_buffer[-50:]]
            avg_performance = np.mean(recent_scores)
            
            # If performance is low, adjust weights
            if avg_performance < 0.6:
                # Give more weight to better performing model
                tcn_performance = np.mean([exp['model_scores']['tcn'] for exp in self.experience_buffer[-20:]])
                ae_performance = np.mean([exp['model_scores']['ae'] for exp in self.experience_buffer[-20:]])
                
                if tcn_performance > ae_performance:
                    self.weights['tcn'] = min(0.9, self.weights['tcn'] + 0.05)
                    self.weights['ae'] = max(0.05, self.weights['ae'] - 0.05)
                else:
                    self.weights['ae'] = min(0.4, self.weights['ae'] + 0.05)
                    self.weights['tcn'] = max(0.5, self.weights['tcn'] - 0.05)
                
                print(f"🧠 Meta-learning updated weights: {self.weights}")
    
    def classify_flow(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Complete classification pipeline"""
        # Score with 3 models
        model_scores = self.score_with_models(flow_data)
        
        # Ensemble fusion
        ensemble_score = self.ensemble_fusion(model_scores)
        
        # Meta-learning update
        self.meta_learning_update(flow_data, model_scores, ensemble_score)
        
        # Determine threat level
        if ensemble_score >= self.threshold:
            threat_level = "malicious"
            severity = "critical" if ensemble_score >= 0.8 else "high"
        elif ensemble_score >= 0.35:
            threat_level = "suspicious"
            severity = "medium"
        else:
            threat_level = "benign"
            severity = "low"
        
        # Attack type classification based on patterns
        attack_type = self.classify_attack_type(flow_data, model_scores)
        
        return {
            'flow_id': flow_data['flow_id'],
            'threat_level': threat_level,
            'severity': severity,
            'confidence': ensemble_score,
            'attack_type': attack_type,
            'model_scores': model_scores,
            'ensemble_weights': self.weights.copy(),
            'meta_learning_enabled': True
        }
    
    def classify_attack_type(self, flow_data: Dict, model_scores: Dict) -> str:
        """Classify attack type based on flow patterns and model scores"""
        pps = flow_data['pps']
        packet_count = flow_data['total_packets']
        
        # Heuristic attack classification
        if pps > 1000:
            return "ddos"
        elif pps > 100 and packet_count < 50:
            return "port_scan"
        elif flow_data['duration'] > 300 and pps < 1:
            return "botnet"
        elif model_scores['ae'] > 0.8:
            return "anomaly"
        elif model_scores['tcn'] > 0.8:
            return "malware"
        else:
            return "benign"

# ── DASHBOARD INTEGRATION ─────────────────────────────────────────────────────

class DashboardSender:
    """Send classification results to dashboard"""
    
    def __init__(self, api_base: str):
        self.api_base = api_base
    
    def send_to_dashboard(self, flow_data: Dict, classification: Dict) -> bool:
        """Send flow and classification to dashboard"""
        try:
            # Prepare threat event
            threat_event = {
                "flow_id": flow_data['flow_id'],
                "src_ip": flow_data['src_ip'],
                "dst_ip": flow_data['dst_ip'],
                "src_port": flow_data['src_port'],
                "dst_port": flow_data['dst_port'],
                "protocol": flow_data['protocol'],
                "label": classification['threat_level'],
                "confidence": classification['confidence'],
                "severity": classification['severity'],
                "attack_type": classification['attack_type'],
                "reason": [
                    f"tcn_score:{classification['model_scores']['tcn']:.3f}",
                    f"ae_score:{classification['model_scores']['ae']:.3f}",
                    f"iso_score:{classification['model_scores']['iso']:.3f}",
                    "meta_learning_enabled"
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "ensemble_weights": classification['ensemble_weights'],
                    "model_scores": classification['model_scores'],
                    "pps": flow_data['pps'],
                    "total_packets": flow_data['total_packets'],
                    "total_bytes": flow_data['total_bytes'],
                    "duration": flow_data['duration']
                }
            }
            
            # Send to detector API
            response = requests.post(
                f"{self.api_base}/detect",
                json=threat_event,
                timeout=5
            )
            
            if response.status_code == 200:
                return True
            else:
                print(f"⚠️ Dashboard send failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending to dashboard: {e}")
            return False

# ── MAIN PROCESSOR ─────────────────────────────────────────────────────────────

class CompletePipelineProcessor:
    """Complete PCAP to Dashboard pipeline"""
    
    def __init__(self):
        self.ensemble = MetaLearningEnsemble()
        self.dashboard = DashboardSender(WS_SERVER)
        self.flow_count = 0
        self.threat_count = 0
        self.running = True
    
    def process_pcap_file(self, pcap_path: Path):
        """Process complete pipeline for one PCAP file"""
        print(f"\n🚀 Processing: {pcap_path.name}")
        
        # Step 1: Extract SPLT features
        flows = extract_splt_features(pcap_path)
        
        # Step 2-5: Process each flow through complete pipeline
        for i, flow in enumerate(flows):
            if not self.running:
                break
            
            # Rate limiting
            if i % 10 == 0:
                time.sleep(DELAY)
            
            # Step 2: Score with 3 models
            # Step 3: Ensemble fusion
            # Step 4: Meta-learning
            classification = self.ensemble.classify_flow(flow)
            
            # Step 5: Send to dashboard
            success = self.dashboard.send_to_dashboard(flow, classification)
            
            # Update counters
            self.flow_count += 1
            if classification['threat_level'] in ['malicious', 'suspicious']:
                self.threat_count += 1
            
            # Display progress
            icon = "🚨" if classification['threat_level'] != 'benign' else "🌐"
            print(f"{icon} {self.flow_count:4d} ✅ {classification['threat_level']:12} "
                  f"{classification['confidence']:.3f} {flow['flow_id']}")
            
            if self.flow_count % 50 == 0:
                print(f"📊 Processed {self.flow_count} flows, {self.threat_count} threats")
    
    def process_all_pcaps(self):
        """Process all PCAP files in raw directory"""
        pcap_files = list(RAW_DIR.glob("*.pcap")) + list(RAW_DIR.glob("*.pcapng"))
        
        if not pcap_files:
            print(f"❌ No PCAP files found in {RAW_DIR}")
            return
        
        print(f"📁 Found {len(pcap_files)} PCAP files")
        
        # Check if dashboard is running
        try:
            response = requests.get(f"{WS_SERVER}/metrics", timeout=3)
            if response.status_code != 200:
                raise Exception()
            print("✅ Dashboard API is running")
        except:
            print("❌ Dashboard API not running. Start your detector first:")
            print("   cd ZeroTrustAI\\services\\detector\\app")
            print("   python main.py")
            return
        
        # Process each PCAP file
        for pcap_path in pcap_files:
            if not self.running:
                break
            self.process_pcap_file(pcap_path)
        
        print(f"\n📊 Final Results:")
        print(f"   Total flows processed: {self.flow_count}")
        print(f"   Threats detected: {self.threat_count}")
        print(f"   Threat ratio: {self.threat_count/max(1,self.flow_count)*100:.1f}%")
        print(f"   Final ensemble weights: {self.ensemble.weights}")

def main():
    print("=" * 80)
    print("  ZeroTrust-AI Complete Pipeline: PCAP → SPLT → 3 Models → Ensemble → Meta-Learning → Dashboard")
    print("=" * 80)
    
    processor = CompletePipelineProcessor()
    processor.process_all_pcaps()

if __name__ == "__main__":
    main()
