#!/usr/bin/env python3
"""
C2 vs DDoS Detection Project
Unified feature extraction and training pipeline
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging
import dpkt
import socket
import time
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class C2DDoSDetector:
    """Main class for C2 and DDoS traffic detection"""
    
    def __init__(self):
        self.data_dir = Path("data")
        self.processed_dir = Path("data/processed")
        self.models_dir = Path("models")
        
        # Create directories
        self.data_dir.mkdir(exist_ok=True)
        self.processed_dir.mkdir(exist_ok=True)
        self.models_dir.mkdir(exist_ok=True)
        
        logger.info("🚀 C2DDoSDetector initialized")
    
    def get_flow_key(self, eth_packet):
        """Extract flow key from Ethernet packet"""
        try:
            ip = eth_packet.data
            if not isinstance(ip, dpkt.ip.IP):
                return None
                
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            
            # Extract ports based on protocol
            if isinstance(ip.data, dpkt.tcp.TCP):
                src_port = ip.data.sport
                dst_port = ip.data.dport
                protocol = 6  # TCP
            elif isinstance(ip.data, dpkt.udp.UDP):
                src_port = ip.data.sport
                dst_port = ip.data.dport
                protocol = 17  # UDP
            else:
                return None
                
            # Create consistent flow key (smaller IP first)
            if (src_ip, src_port) < (dst_ip, dst_port):
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            else:
                return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
                
        except Exception as e:
            return None
    
    def extract_splt_features(self, packets):
        """Extract SPLT (Sequence Packet Length and Time) features"""
        if len(packets) < 20:
            return None, None
            
        # Get first 20 packets
        first_20 = packets[:20]
        
        # Packet lengths
        lengths = [p['size'] for p in first_20]
        
        # Inter-arrival times
        iats = []
        for i in range(1, len(first_20)):
            iat = first_20[i]['timestamp'] - first_20[i-1]['timestamp']
            iats.append(iat)
        
        # Pad with zeros if needed
        while len(lengths) < 20:
            lengths.append(0)
        while len(iats) < 20:
            iats.append(0)
            
        return lengths, iats
    
    def extract_flow_features(self, packets):
        """Extract basic flow features"""
        if not packets:
            return None
            
        start_time = packets[0]['timestamp']
        end_time = packets[-1]['timestamp']
        duration = end_time - start_time
        
        total_packets = len(packets)
        total_bytes = sum(p['size'] for p in packets)
        
        # Protocol
        protocol = packets[0].get('protocol', 0)
        
        return {
            'duration': duration,
            'protocol': protocol,
            'total_packets': total_packets,
            'total_bytes': total_bytes
        }
    
    def process_pcap(self, pcap_path, attack_type='Unknown'):
        """Process a single PCAP file"""
        logger.info(f"📂 Processing PCAP: {pcap_path}")
        
        flows = {}
        flow_id = 0
        
        try:
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                for timestamp, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        flow_key = self.get_flow_key(eth)
                        
                        if not flow_key:
                            continue
                            
                        if flow_key not in flows:
                            flows[flow_key] = []
                            flow_id += 1
                        
                        # Add packet to flow
                        packet_info = {
                            'timestamp': timestamp,
                            'size': len(buf),
                            'protocol': 6 if isinstance(eth.data.data, dpkt.tcp.TCP) else 17
                        }
                        flows[flow_key].append(packet_info)
                        
                    except Exception as e:
                        continue
                        
        except Exception as e:
            logger.error(f"Error processing PCAP: {e}")
            return None
        
        # Extract features for each flow
        results = []
        for flow_key, packets in flows.items():
            if len(packets) < 5:  # Skip very short flows
                continue
                
            # Extract features
            flow_features = self.extract_flow_features(packets)
            splt_lengths, splt_iats = self.extract_splt_features(packets)
            
            if flow_features and splt_lengths and splt_iats:
                # Combine all features
                feature_dict = {
                    'flow_id': f"{Path(pcap_path).stem}_{flow_key}",
                    'pcap_file': Path(pcap_path).name,
                    'attack_type': attack_type,
                    'label': 1 if attack_type != 'Normal' else 0,
                    **flow_features
                }
                
                # Add SPLT features
                for i, length in enumerate(splt_lengths):
                    feature_dict[f'splt_len_{i+1}'] = length
                    
                for i, iat in enumerate(splt_iats):
                    feature_dict[f'splt_iat_{i+1}'] = iat
                
                results.append(feature_dict)
        
        logger.info(f"✅ Extracted {len(results)} flows from {pcap_path}")
        return results
    
    def create_dataset(self, pcaps_info):
        """Create unified dataset from multiple PCAPs"""
        all_flows = []
        
        for pcap_path, attack_type in pcaps_info:
            flows = self.process_pcap(pcap_path, attack_type)
            if flows:
                all_flows.extend(flows)
        
        if not all_flows:
            logger.error("❌ No flows extracted")
            return None
        
        # Create DataFrame
        df = pd.DataFrame(all_flows)
        
        # Handle missing values
        df = df.fillna(0.001)
        
        logger.info(f"📊 Created dataset: {len(df)} flows")
        logger.info(f"Attack types: {df['attack_type'].value_counts().to_dict()}")
        
        return df

def main():
    """Main function"""
    detector = C2DDoSDetector()
    
    logger.info("🎯 C2 vs DDoS Detection Pipeline")
    logger.info("=" * 50)
    
    # Example PCAP processing
    pcaps_info = [
        ("path/to/c2.pcap", "C2"),
        ("path/to/ddos.pcap", "DDoS"), 
        ("path/to/normal.pcap", "Normal")
    ]
    
    # Create dataset
    dataset = detector.create_dataset(pcaps_info)
    
    if dataset is not None:
        # Save dataset
        output_path = "c2_ddos/unified_dataset.csv"
        dataset.to_csv(output_path, index=False)
        logger.info(f"✅ Dataset saved to {output_path}")

if __name__ == "__main__":
    main()
