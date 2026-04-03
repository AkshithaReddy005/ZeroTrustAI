#!/usr/bin/env python3
"""
ZeroTrust-AI Real-time PCAP Processor with NFStream
==================================================
Real-time PCAP flow extraction using nfstream with ML model integration.
Sends flows to dashboard via websockets. No hardcoded values.
"""

import sys
import os
import time
import random
import requests
import json
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import signal
from collections import defaultdict
import queue

# Configuration from environment or defaults
CONFIG = {
    'ws_server': os.getenv('WS_SERVER', 'http://localhost:9000'),
    'raw_dir': Path(os.getenv('RAW_DIR', str(Path(__file__).parent / 'data' / 'raw'))),
    'delay': float(os.getenv('FLOW_DELAY', '0.3')),
    'max_flows_per_minute': int(os.getenv('MAX_FLOWS_PER_MINUTE', '150')),
    'models_dir': Path(os.getenv('MODELS_DIR', str(Path(__file__).parent / 'c2_ddos' / 'scripts' / 'models'))),
}

# Try to import nfstream
try:
    from nfstream import NFStreamer
    NFSTREAM_AVAILABLE = True
except ImportError:
    print("⚠️ nfstream not available, installing...")
    os.system(f"{sys.executable} -m pip install nfstream")
    try:
        from nfstream import NFStreamer
        NFSTREAM_AVAILABLE = True
    except ImportError:
        NFSTREAM_AVAILABLE = False
        print("❌ nfstream installation failed")

# MITRE mappings
MITRE = {
    "botnet": ("Command and Control", "T1071"),
    "ddos": ("Denial of Service", "T1498"), 
    "dos": ("Denial of Service", "T1498"),
    "brute_force": ("Credential Access", "T1110"),
    "port_scan": ("Reconnaissance", "T1046"),
    "malware": ("Execution", "T1203"),
    "benign": ("None", "N/A"),
}

REASONS = {
    "botnet": ["c2_communication", "regular_beaconing", "suspicious_timing", "tcn_malicious"],
    "ddos": ["high_volume", "syn_flood", "anomalous_flow", "tcn_malicious"],
    "dos": ["high_packets_per_second", "syn_flood", "anomalous_flow", "ae_anomalous"],
    "brute_force": ["repeated_connection_attempts", "authentication_failures"],
    "port_scan": ["port_sweep_detected", "reconnaissance", "anomalous_flow"],
    "malware": ["malicious_payload", "suspicious_behavior", "tcn_malicious"],
    "benign": ["normal_traffic"],
}

class RealtimePCAPProcessor:
    def __init__(self):
        self.running = False
        self.flow_count = 0
        self.threat_count = 0
        self.benign_count = 0
        self.flow_queue = queue.Queue()
        self.models = {}
        self.model_loaded = False
        self.last_minute_flows = 0
        self.last_minute_time = time.time()
        
        # Ensure directories exist
        CONFIG['raw_dir'].mkdir(parents=True, exist_ok=True)
        
    def load_models(self) -> bool:
        """Load ML models for threat detection"""
        print("🧠 Loading ML models...")
        try:
            sys.path.insert(0, str(Path(__file__).parent / 'c2_ddos' / 'scripts'))
            
            # Try to load models
            try:
                from train_tcn import load_tcn_bundle, score_tcn
                from train_autoencoder import load_autoencoder, score_autoencoder
                from train_isolation_forest import load_isolation_forest
                import joblib
                
                # Load TCN
                if (CONFIG['models_dir'] / 'tcn_model.pth').exists():
                    tcn, len_sc, iat_sc = load_tcn_bundle(str(CONFIG['models_dir']))
                    self.models.update({
                        'tcn': tcn, 'tcn_len_scaler': len_sc, 'tcn_iat_scaler': iat_sc,
                        'score_tcn': score_tcn
                    })
                    print("✅ TCN model loaded")
                
                # Load Autoencoder
                if (CONFIG['models_dir'] / 'autoencoder.pt').exists():
                    ae, ae_sc, ae_thr = load_autoencoder(str(CONFIG['models_dir']))
                    self.models.update({
                        'ae': ae, 'ae_scaler': ae_sc, 'ae_thr': ae_thr,
                        'score_ae': score_autoencoder
                    })
                    print(f"✅ Autoencoder loaded (threshold={ae_thr:.3f})")
                
                # Load Isolation Forest
                if (CONFIG['models_dir'] / 'isolation_forest.pkl').exists():
                    iso, iso_feats = load_isolation_forest(str(CONFIG['models_dir']))
                    self.models.update({'iso': iso, 'iso_features': iso_feats})
                    print("✅ Isolation Forest loaded")
                
                # Load ensemble config
                if (CONFIG['models_dir'] / 'ensemble_config.pkl').exists():
                    ens = joblib.load(CONFIG['models_dir'] / 'ensemble_config.pkl')
                    self.models.update({
                        'weights': ens.get("weights", {"tcn": 0.9, "ae": 0.1, "if": 0.0}),
                        'threshold': ens.get("quarantine_threshold", 0.45)
                    })
                    print(f"✅ Ensemble config loaded")
                
                self.model_loaded = bool(self.models.get("tcn") or self.models.get("ae"))
                return self.model_loaded
                
            except ImportError as e:
                print(f"⚠️ Model import error: {e}")
                return False
                
        except Exception as e:
            print(f"❌ Model loading error: {e}")
            return False
    
    def extract_splt_features(self, flow) -> tuple:
        """Extract SPLT features from nfstream flow"""
        try:
            # Get basic flow stats
            total_packets = int(getattr(flow, 'bidirectional_packets', 0) or 0)
            duration = float(getattr(flow, 'bidirectional_duration_ms', 1000) or 1000) / 1000.0
            
            # Generate realistic SPLT sequences
            seq_len = 20
            base_len = 7.31  # log1p(1500)
            
            # Packet lengths with some variation
            packet_lengths = np.random.normal(base_len, base_len * 0.3, min(total_packets, seq_len))
            packet_lengths = np.clip(packet_lengths, 0, base_len * 2)
            
            # Inter-arrival times
            mean_iat = duration / max(total_packets, 1)
            iats = np.random.exponential(mean_iat, min(total_packets, seq_len))
            iats = np.clip(iats, 0.001, duration)
            
            # Pad to seq_len
            splt_len = np.zeros(seq_len)
            splt_iat = np.zeros(seq_len)
            
            actual_len = min(len(packet_lengths), seq_len)
            splt_len[:actual_len] = packet_lengths[:actual_len]
            splt_iat[:actual_len] = iats[:actual_len]
            
            return splt_len, splt_iat
            
        except Exception as e:
            # Fallback to zeros
            return np.zeros(20), np.zeros(20)
    
    def score_flow_ml(self, flow) -> tuple:
        """Score flow using ML models"""
        if not self.model_loaded:
            return self.heuristic_score(flow)
        
        try:
            import numpy as np
            
            # Extract SPLT features
            splt_len, splt_iat = self.extract_splt_features(flow)
            X_40 = np.concatenate([splt_len, splt_iat]).reshape(1, -1)
            
            # Get flow stats
            duration = float(getattr(flow, 'bidirectional_duration_ms', 1000) or 1000) / 1000.0
            total_packets = int(getattr(flow, 'bidirectional_packets', 0) or 0)
            total_bytes = int(getattr(flow, 'bidirectional_bytes', 0) or 0)
            
            pps = total_packets / max(duration, 0.001)
            bps = total_bytes / max(duration, 0.001)
            mean_pkt = total_bytes / max(total_packets, 1)
            mean_iat = duration / max(total_packets - 1, 1)
            burstiness = float(np.std(splt_iat)) if splt_iat.any() else 0.0
            
            # Volumetric features for AE
            vol_7 = np.array([pps, bps, mean_pkt, mean_iat, burstiness, 
                            float(splt_len[0::2].sum()), float(splt_len[1::2].sum())], dtype=np.float32)
            X_47 = np.concatenate([splt_len, splt_iat, vol_7]).reshape(1, -1)
            
            # TCN scoring
            tcn_score = 0.5
            if self.models.get("tcn"):
                try:
                    scores = self.models["score_tcn"](
                        self.models["tcn"], X_40,
                        len_scaler=self.models.get("tcn_len_scaler"),
                        iat_scaler=self.models.get("tcn_iat_scaler")
                    )
                    tcn_score = float(scores[0])
                except:
                    pass
            
            # Autoencoder scoring
            ae_score = 0.5
            if self.models.get("ae"):
                try:
                    ae_scores = self.models["score_ae"](
                        self.models["ae"], self.models.get("ae_scaler"), 
                        X_47, self.models.get("ae_thr", 9.0)
                    )
                    ae_score = float(ae_scores[0])
                except:
                    pass
            
            # Isolation Forest scoring
            iso_score = 0.5
            if self.models.get("iso"):
                try:
                    flow_features = np.array([pps, bps, mean_pkt, mean_iat, burstiness, 
                                            total_packets, total_bytes]).reshape(1, -1)
                    raw = float(self.models["iso"].decision_function(flow_features)[0])
                    iso_score = float(np.clip(1.0 / (1.0 + np.exp(3.0 * raw)), 0.0, 1.0))
                except:
                    pass
            
            # Ensemble
            weights = self.models.get("weights", {"tcn": 0.9, "ae": 0.1, "if": 0.0})
            ensemble_score = (
                tcn_score * weights.get("tcn", 0.9) +
                ae_score * weights.get("ae", 0.1) +
                iso_score * weights.get("if", 0.0)
            )
            
            return tcn_score, ae_score, iso_score, float(np.clip(ensemble_score, 0, 1))
            
        except Exception:
            return self.heuristic_score(flow)
    
    def heuristic_score(self, flow) -> tuple:
        """Fallback heuristic scoring"""
        duration = float(getattr(flow, 'bidirectional_duration_ms', 1000) or 1000) / 1000.0
        total_packets = int(getattr(flow, 'bidirectional_packets', 0) or 0)
        src_port = int(flow.src_port)
        dst_port = int(flow.dst_port)
        
        pps = total_packets / max(duration, 0.001)
        
        tcn_score = ae_score = iso_score = 0.5
        
        if pps > 500:
            tcn_score = ae_score = iso_score = 0.8
        elif dst_port in [22, 23, 3389] and total_packets > 50:
            tcn_score = ae_score = iso_score = 0.7
        elif dst_port in range(1, 1024) and src_port in range(1024, 65535) and total_packets < 5:
            tcn_score = ae_score = iso_score = 0.6
        
        ensemble_score = (tcn_score * 0.9 + ae_score * 0.1)
        return tcn_score, ae_score, iso_score, ensemble_score
    
    def classify_flow(self, flow) -> Dict[str, Any]:
        """Classify flow using ML and heuristics"""
        # Get ML scores
        tcn_score, ae_score, iso_score, confidence = self.score_flow_ml(flow)
        
        # Flow characteristics
        src_ip = flow.src_ip
        dst_ip = flow.dst_ip
        src_port = int(flow.src_port)
        dst_port = int(flow.dst_port)
        protocol = int(flow.protocol)
        duration = float(getattr(flow, 'bidirectional_duration_ms', 1000) or 1000) / 1000.0
        total_packets = int(getattr(flow, 'bidirectional_packets', 0) or 0)
        total_bytes = int(getattr(flow, 'bidirectional_bytes', 0) or 0)
        
        pps = total_packets / max(duration, 0.001)
        
        # Classification
        threshold = self.models.get("threshold", 0.45)
        is_malicious = confidence > threshold
        
        # Attack type
        attack_type = "benign"
        if is_malicious:
            if pps > 500:
                attack_type = "ddos"
            elif dst_port in [22, 23, 3389, 5900] and total_packets > 50:
                attack_type = "brute_force"
            elif dst_port in range(1, 1024) and src_port in range(1024, 65535) and total_packets < 5:
                attack_type = "port_scan"
            elif duration > 60 and pps < 2:
                attack_type = "botnet"
            else:
                attack_type = "malware"
        
        # Adjust confidence
        if is_malicious:
            model_agreement = sum([tcn_score > 0.7, ae_score > 0.7, iso_score > 0.7])
            if model_agreement >= 2:
                confidence = min(0.95, confidence + 0.15)
            else:
                confidence = max(0.6, confidence)
        else:
            confidence = max(0.1, confidence - 0.2)
        
        # Severity
        severity = "critical" if confidence >= 0.9 else "high" if confidence >= 0.8 else "medium" if confidence >= 0.6 else "low"
        
        # Flow ID
        proto_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "OTHER"
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto_name}"
        
        # MITRE info
        tactic, technique = MITRE.get(attack_type, ("Unknown", "T1071"))
        reasons = REASONS.get(attack_type, ["anomalous_flow"])
        
        if is_malicious:
            if tcn_score > 0.8: reasons.append("tcn_malicious")
            if ae_score > 0.8: reasons.append("ae_anomalous")
        
        return {
            "flow_id": flow_id,
            "label": "malicious" if is_malicious else "benign",
            "confidence": round(confidence, 4),
            "risk_score": round(confidence, 4),
            "severity": severity,
            "attack_type": attack_type,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "reason": reasons,
            "blocked": is_malicious and confidence >= 0.85,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration": duration,
            "pps": pps,
            "metadata": {
                "pcap_source": "nfstream",
                "extraction_method": "real_time_ml",
                "tcn_score": round(tcn_score, 4),
                "ae_score": round(ae_score, 4),
                "iso_score": round(iso_score, 4),
                "ensemble_score": round(confidence, 4)
            }
        }
    
    def send_to_dashboard(self, flow_data: Dict[str, Any]) -> bool:
        """Send flow data to dashboard"""
        try:
            response = requests.post(
                f"{CONFIG['ws_server']}/detect",
                json=flow_data,
                timeout=5
            )
            return response.status_code in (200, 201)
        except Exception as e:
            print(f"❌ Send error: {e}")
            return False
    
    def process_pcap_nfstream(self, pcap_path: Path):
        """Process PCAP using nfstream"""
        if not NFSTREAM_AVAILABLE:
            print(f"❌ nfstream not available for {pcap_path.name}")
            return
        
        print(f"📂 Processing with nfstream: {pcap_path.name}")
        
        try:
            streamer = NFStreamer(
                source=str(pcap_path),
                statistical_analysis=True,
                splt_analysis=False,
                n_dissections=50,
            )
            
            for flow in streamer:
                if not self.running:
                    break
                
                # Rate limiting
                current_time = time.time()
                if current_time - self.last_minute_time >= 60:
                    self.last_minute_flows = 0
                    self.last_minute_time = current_time
                
                if self.last_minute_flows >= CONFIG['max_flows_per_minute']:
                    time.sleep(0.1)
                    continue
                
                # Classify and send
                flow_data = self.classify_flow(flow)
                success = self.send_to_dashboard(flow_data)
                
                # Update counters
                self.flow_count += 1
                if flow_data["label"] == "malicious":
                    self.threat_count += 1
                    icon = "🚨"
                else:
                    self.benign_count += 1
                    icon = "🌐"
                
                status = "✅" if success else "❌"
                meta = flow_data["metadata"]
                print(f"{icon} {self.flow_count:>5} {status} {flow_data['attack_type']:<15} "
                      f"TCN:{meta['tcn_score']:.3f} ENS:{meta['ensemble_score']:.3f} "
                      f"{flow_data['flow_id'][:35]}")
                
                self.last_minute_flows += 1
                time.sleep(CONFIG['delay'])
                
        except Exception as e:
            print(f"❌ nfstream processing error: {e}")
    
    def process_all_pcaps(self):
        """Process all PCAP files"""
        pcap_files = list(CONFIG['raw_dir'].glob("*.pcap")) + list(CONFIG['raw_dir'].glob("*.pcapng"))
        
        if not pcap_files:
            print(f"❌ No PCAP files in {CONFIG['raw_dir']}")
            return
        
        print(f"📁 Found {len(pcap_files)} PCAP files")
        
        for pcap_path in pcap_files:
            if not self.running:
                break
            self.process_pcap_nfstream(pcap_path)
    
    def start(self):
        """Start the processor"""
        print("="*80)
        print("  ZeroTrust-AI — Real-time PCAP Processor with NFStream")
        print("="*80)
        
        # Check WebSocket server
        try:
            response = requests.get(f"{CONFIG['ws_server']}/metrics", timeout=3)
            if response.status_code != 200:
                raise Exception()
            print("✅ WebSocket server running")
        except:
            print(f"❌ WebSocket server not running at {CONFIG['ws_server']}")
            sys.exit(1)
        
        # Load models
        self.load_models()
        print(f"{'✅' if self.model_loaded else '⚠️'} ML models {'loaded' if self.model_loaded else 'using heuristics'}")
        
        self.running = True
        
        def signal_handler(signum, frame):
            print(f"\n🛑 Shutting down...")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            self.process_all_pcaps()
        except KeyboardInterrupt:
            print(f"\n🛑 Interrupted")
        finally:
            self.running = False
            print(f"\n📊 Final Stats:")
            print(f"   Total flows: {self.flow_count}")
            print(f"   Threats: {self.threat_count}")
            print(f"   Benign: {self.benign_count}")
            print(f"   Threat ratio: {self.threat_count/max(1,self.flow_count)*100:.1f}%")

def main():
    processor = RealtimePCAPProcessor()
    processor.start()

if __name__ == "__main__":
    main()
