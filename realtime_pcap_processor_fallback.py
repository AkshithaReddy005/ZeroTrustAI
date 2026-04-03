#!/usr/bin/env python3
"""
ZeroTrust-AI Real-time PCAP Processor (Fallback Version)
====================================================
Works when nfstream has DLL issues. Uses dpkt + manual flow extraction.
Real-time PCAP processing with ML model integration.
"""

import sys
import os
import time
import random
import requests
import json
import dpkt
import socket
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
import signal
from collections import defaultdict
import numpy as np

# Configuration from environment
CONFIG = {
    'ws_server': os.getenv('WS_SERVER', 'http://localhost:9000'),
    'raw_dir': Path(os.getenv('RAW_DIR', str(Path(__file__).parent / 'data' / 'raw'))),
    'delay': float(os.getenv('FLOW_DELAY', '0.2')),
    'max_flows_per_minute': int(os.getenv('MAX_FLOWS_PER_MINUTE', '200')),
    'models_dir': Path(os.getenv('MODELS_DIR', str(Path(__file__).parent / 'c2_ddos' / 'scripts' / 'models'))),
}

# Ensure directories exist
CONFIG['raw_dir'].mkdir(parents=True, exist_ok=True)

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

class FallbackPCAPProcessor:
    def __init__(self):
        self.running = False
        self.flow_count = 0
        self.threat_count = 0
        self.benign_count = 0
        self.models = {}
        self.model_loaded = False
        self.last_minute_flows = 0
        self.last_minute_time = time.time()
        self.flow_buffer = defaultdict(list)
        
    def ip_to_str(self, ip):
        """Convert IP address to string"""
        if isinstance(ip, bytes):
            return socket.inet_ntop(socket.AF_INET, ip)
        return str(ip)
    
    def load_models(self) -> bool:
        """Load ML models"""
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
    
    def extract_flow_features(self, packets: List) -> Dict:
        """Extract features from packet list"""
        if not packets:
            return {}
        
        # Basic stats
        total_packets = len(packets)
        total_bytes = sum(len(pkt['data']) for pkt in packets)
        start_time = packets[0]['timestamp']
        end_time = packets[-1]['timestamp']
        duration = max(end_time - start_time, 0.001)
        
        # Packet sizes
        sizes = [len(pkt['data']) for pkt in packets]
        
        # Inter-arrival times
        iats = []
        for i in range(1, len(packets)):
            iat = packets[i]['timestamp'] - packets[i-1]['timestamp']
            iats.append(max(iat, 0.001))
        
        # Generate SPLT features (20 each)
        seq_len = 20
        splt_len = np.zeros(seq_len)
        splt_iat = np.zeros(seq_len)
        
        # Log-scaled packet lengths
        log_sizes = [np.log1p(s) for s in sizes[:seq_len]]
        splt_len[:len(log_sizes)] = log_sizes
        
        # Inter-arrival times
        splt_iat[:len(iats[:seq_len])] = iats[:seq_len]
        
        # Volumetric features
        pps = total_packets / duration
        bps = total_bytes / duration
        mean_pkt = total_bytes / max(total_packets, 1)
        mean_iat = np.mean(iats) if iats else 0.001
        burstiness = np.std(iats) if iats else 0.0
        
        # Directional bytes (client/server split)
        client_bytes = sum(len(pkt['data']) for pkt in packets if pkt.get('direction') == 'client')
        server_bytes = sum(len(pkt['data']) for pkt in packets if pkt.get('direction') == 'server')
        
        return {
            'splt_len': splt_len,
            'splt_iat': splt_iat,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'duration': duration,
            'pps': pps,
            'bps': bps,
            'mean_packet_size': mean_pkt,
            'mean_iat': mean_iat,
            'burstiness': burstiness,
            'client_bytes': client_bytes,
            'server_bytes': server_bytes,
            'packet_sizes': sizes,
            'iats': iats
        }
    
    def score_flow_ml(self, flow_features: Dict) -> Tuple[float, float, float, float]:
        """Score flow using ML models"""
        if not self.model_loaded or not flow_features:
            return self.heuristic_score(flow_features)
        
        try:
            # Prepare features for TCN (40 features)
            splt_len = flow_features.get('splt_len', np.zeros(20))
            splt_iat = flow_features.get('splt_iat', np.zeros(20))
            X_40 = np.concatenate([splt_len, splt_iat]).reshape(1, -1)
            
            # Prepare features for AE (47 features)
            vol_7 = np.array([
                flow_features.get('pps', 0),
                flow_features.get('bps', 0),
                flow_features.get('mean_packet_size', 0),
                flow_features.get('mean_iat', 0),
                flow_features.get('burstiness', 0),
                flow_features.get('client_bytes', 0),
                flow_features.get('server_bytes', 0)
            ], dtype=np.float32)
            
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
                    flow_features_for_if = np.array([
                        flow_features.get('pps', 0),
                        flow_features.get('bps', 0),
                        flow_features.get('mean_packet_size', 0),
                        flow_features.get('mean_iat', 0),
                        flow_features.get('burstiness', 0),
                        flow_features.get('total_packets', 0),
                        flow_features.get('total_bytes', 0)
                    ]).reshape(1, -1)
                    raw = float(self.models["iso"].decision_function(flow_features_for_if)[0])
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
            
        except Exception as e:
            print(f"❌ ML scoring error: {e}")
            return self.heuristic_score(flow_features)
    
    def heuristic_score(self, flow_features: Dict) -> Tuple[float, float, float, float]:
        """Fallback heuristic scoring"""
        pps = flow_features.get('pps', 0)
        total_packets = flow_features.get('total_packets', 0)
        burstiness = flow_features.get('burstiness', 0)
        
        tcn_score = ae_score = iso_score = 0.5
        
        if pps > 500:
            tcn_score = ae_score = iso_score = 0.85
        elif burstiness > 0.5:
            tcn_score = ae_score = iso_score = 0.7
        elif total_packets > 1000:
            tcn_score = ae_score = iso_score = 0.6
        
        ensemble_score = (tcn_score * 0.9 + ae_score * 0.1)
        return tcn_score, ae_score, iso_score, ensemble_score
    
    def classify_flow(self, flow_key: str, flow_features: Dict, flow_info: Dict) -> Dict[str, Any]:
        """Classify flow and create event data"""
        # Get ML scores
        tcn_score, ae_score, iso_score, confidence = self.score_flow_ml(flow_features)
        
        # Flow characteristics
        pps = flow_features.get('pps', 0)
        total_packets = flow_features.get('total_packets', 0)
        duration = flow_features.get('duration', 0.001)
        
        # Classification
        threshold = self.models.get("threshold", 0.45)
        is_malicious = confidence > threshold
        
        # Attack type
        attack_type = "benign"
        if is_malicious:
            if pps > 500:
                attack_type = "ddos"
            elif flow_info.get('dst_port') in [22, 23, 3389, 5900] and total_packets > 50:
                attack_type = "brute_force"
            elif flow_info.get('dst_port') in range(1, 1024) and flow_info.get('src_port') in range(1024, 65535) and total_packets < 5:
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
        proto_name = "TCP" if flow_info.get('protocol') == 6 else "UDP" if flow_info.get('protocol') == 17 else "OTHER"
        flow_id = f"{flow_info.get('src_ip','unknown')}:{flow_info.get('src_port',0)}->{flow_info.get('dst_ip','unknown')}:{flow_info.get('dst_port',0)}/{proto_name}"
        
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
            "source_ip": flow_info.get('src_ip', 'unknown'),
            "destination_ip": flow_info.get('dst_ip', 'unknown'),
            "src_port": flow_info.get('src_port', 0),
            "dst_port": flow_info.get('dst_port', 0),
            "protocol": flow_info.get('protocol', 0),
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "reason": reasons,
            "blocked": is_malicious and confidence >= 0.85,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_packets": total_packets,
            "total_bytes": flow_features.get('total_bytes', 0),
            "duration": duration,
            "pps": pps,
            "bps": flow_features.get('bps', 0),
            "metadata": {
                "pcap_source": "dpkt_fallback",
                "extraction_method": "real_time_ml_fallback",
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
    
    def process_pcap_dpkt(self, pcap_path: Path):
        """Process PCAP using dpkt with real-time flow extraction"""
        print(f"📂 Processing PCAP (dpkt): {pcap_path.name}")
        
        try:
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                flow_packets = defaultdict(list)
                packet_count = 0
                last_process_time = time.time()
                
                for timestamp, buf in pcap:
                    if not self.running:
                        break
                    
                    packet_count += 1
                    
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                            
                        ip = eth.data
                        src_ip = self.ip_to_str(ip.src)
                        dst_ip = self.ip_to_str(ip.dst)
                        protocol = ip.p
                        
                        # Get ports for TCP/UDP
                        src_port = 0
                        dst_port = 0
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            src_port = ip.data.sport
                            dst_port = ip.data.dport
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            src_port = ip.data.sport
                            dst_port = ip.data.dport
                        
                        # Create flow key
                        if src_ip < dst_ip:
                            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
                            direction = 'client'
                        else:
                            flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
                            direction = 'server'
                        
                        # Store packet
                        packet_info = {
                            'timestamp': timestamp,
                            'data': buf,
                            'direction': direction,
                            'size': len(buf)
                        }
                        flow_packets[flow_key].append(packet_info)
                        
                        # Process flows every 2 seconds or 1000 packets
                        current_time = time.time()
                        if (current_time - last_process_time >= 2.0) or (packet_count % 1000 == 0):
                            self._process_buffered_flows(flow_packets)
                            last_process_time = current_time
                            
                    except Exception as e:
                        continue
                
                # Process remaining flows
                self._process_buffered_flows(flow_packets)
                
        except Exception as e:
            print(f"❌ Error processing PCAP {pcap_path}: {e}")
    
    def _process_buffered_flows(self, flow_packets: dict):
        """Process buffered flows and send to dashboard"""
        flows_to_remove = []
        
        for flow_key, packets in flow_packets.items():
            if len(packets) < 3:  # Need minimum packets for flow
                continue
            
            # Extract flow info from key
            parts = flow_key.split('-')
            if len(parts) >= 3:
                src_parts = parts[0].split(':')
                dst_parts = parts[1].split(':')
                protocol = int(parts[2])
                
                flow_info = {
                    'src_ip': src_parts[0],
                    'src_port': int(src_parts[1]),
                    'dst_ip': dst_parts[0],
                    'dst_port': int(dst_parts[1]),
                    'protocol': protocol
                }
                
                # Extract features
                features = self.extract_flow_features(packets)
                
                # Classify flow
                flow_data = self.classify_flow(flow_key, features, flow_info)
                
                # Rate limiting
                current_time = time.time()
                if current_time - self.last_minute_time >= 60:
                    self.last_minute_flows = 0
                    self.last_minute_time = current_time
                
                if self.last_minute_flows >= CONFIG['max_flows_per_minute']:
                    continue
                
                # Send to dashboard
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
                
                flows_to_remove.append(flow_key)
        
        # Remove processed flows
        for flow_key in flows_to_remove:
            if flow_key in flow_packets:
                del flow_packets[flow_key]
    
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
            self.process_pcap_dpkt(pcap_path)
    
    def start(self):
        """Start processor"""
        print("="*80)
        print("  ZeroTrust-AI — Real-time PCAP Processor (Fallback)")
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
    processor = FallbackPCAPProcessor()
    processor.start()

if __name__ == "__main__":
    main()
