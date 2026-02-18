#!/usr/bin/env python3
"""
Unified Feature Extraction using dpkt
Extracts identical features from all PCAP files (C2, DDoS, Normal)

This creates consistent datasets with:
- Basic flow features (Duration, Protocol, Packet counts)
- SPLT temporal features (20-packet sequences)
- Proper handling of missing values
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging
import struct
import socket
import glob
from datetime import datetime
import dpkt

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UnifiedFlowExtractor:
    """Unified flow extractor using dpkt for consistent feature extraction"""
    
    def __init__(self):
        self.flows = {}
        self.flow_id_counter = 0
        
    def parse_ip_address(self, ip_bytes):
        """Convert IP bytes to string."""
        try:
            return socket.inet_ntoa(ip_bytes)
        except:
            return "0.0.0.0"
    
    def get_flow_key(self, eth):
        """Generate flow key from Ethernet packet."""
        if hasattr(eth, 'ip'):
            src_ip = self.parse_ip_address(eth.ip.src)
            dst_ip = self.parse_ip_address(eth.ip.dst)
            
            # Get ports based on protocol
            src_port = 0
            dst_port = 0
            
            if eth.ip.p == 6 and hasattr(eth.ip, 'tcp'):  # TCP
                src_port = eth.ip.tcp.sport
                dst_port = eth.ip.tcp.dport
            elif eth.ip.p == 17 and hasattr(eth.ip, 'udp'):  # UDP
                src_port = eth.ip.udp.sport
                dst_port = eth.ip.udp.dport
            
            protocol = eth.ip.p
            
            # Create bidirectional flow key
            if (src_ip, src_port, dst_ip, dst_port) <= (dst_ip, dst_port, src_ip, src_port):
                return (src_ip, src_port, dst_ip, dst_port, protocol)
            else:
                return (dst_ip, dst_port, src_ip, src_port, protocol)
        return None
    
    def extract_features_from_pcap(self, pcap_path):
        """Extract unified features from PCAP file."""
        logger.info(f"🔍 Extracting unified features from {pcap_path}")
        
        flows = {}
        flow_id = 0
        
        try:
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                for timestamp, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not hasattr(eth, 'ip'):
                            continue
                            
                        flow_key = self.get_flow_key(eth)
                        if not flow_key:
                            continue
                            
                        # Initialize flow if not exists
                        if flow_key not in flows:
                            flows[flow_key] = {
                                'flow_id': flow_id,
                                'src_ip': flow_key[0],
                                'src_port': flow_key[1],
                                'dst_ip': flow_key[2],
                                'dst_port': flow_key[3],
                                'protocol': flow_key[4],
                                'start_time': timestamp,
                                'end_time': timestamp,
                                'packets': [],
                                'packet_lengths': [],
                                'packet_times': [],
                                'fwd_packets': 0,
                                'bwd_packets': 0,
                                'fwd_bytes': 0,
                                'bwd_bytes': 0,
                                'total_packets': 0,
                                'total_bytes': 0
                            }
                            flow_id += 1
                        
                        flow = flows[flow_key]
                        
                        # Update flow timing
                        flow['end_time'] = max(flow['end_time'], timestamp)
                        
                        # Extract packet info
                        packet_length = len(buf)
                        flow['packet_lengths'].append(packet_length)
                        flow['packet_times'].append(timestamp)
                        flow['packets'].append(timestamp)
                        
                        # Determine direction
                        is_forward = (eth.ip.src == socket.inet_aton(flow['src_ip']))
                        
                        if is_forward:
                            flow['fwd_packets'] += 1
                            flow['fwd_bytes'] += packet_length
                        else:
                            flow['bwd_packets'] += 1
                            flow['bwd_bytes'] += packet_length
                        
                        flow['total_packets'] += 1
                        flow['total_bytes'] += packet_length
                        
                    except Exception as e:
                        continue
                        
        except Exception as e:
            logger.error(f"Error reading PCAP: {e}")
            return []
        
        # Convert flows to feature rows
        feature_rows = []
        
        for flow_key, flow in flows.items():
            # Calculate duration
            duration = flow['end_time'] - flow['start_time']
            if duration <= 0:
                duration = 0.001  # Fix for very short flows
            
            # Basic flow features
            features = {
                'flow_id': flow['flow_id'],
                'src_ip': flow['src_ip'],
                'src_port': flow['src_port'],
                'dst_ip': flow['dst_ip'],
                'dst_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'duration': duration,
                'total_packets': flow['total_packets'],
                'total_bytes': flow['total_bytes'],
                'fwd_packets': flow['fwd_packets'],
                'bwd_packets': flow['bwd_packets'],
                'fwd_bytes': flow['fwd_bytes'],
                'bwd_bytes': flow['bwd_bytes'],
                'bytes_per_second': flow['total_bytes'] / duration if duration > 0 else 0,
                'packets_per_second': flow['total_packets'] / duration if duration > 0 else 0,
            }
            
            # Packet statistics
            if flow['packet_lengths']:
                features.update({
                    'min_packet_size': min(flow['packet_lengths']),
                    'max_packet_size': max(flow['packet_lengths']),
                    'mean_packet_size': np.mean(flow['packet_lengths']),
                    'std_packet_size': np.std(flow['packet_lengths']),
                })
            else:
                features.update({
                    'min_packet_size': 0,
                    'max_packet_size': 0,
                    'mean_packet_size': 0,
                    'std_packet_size': 0,
                })
            
            # SPLT features (20-packet sequence)
            splt_lengths = flow['packet_lengths'][:20]
            splt_iats = []
            
            # Calculate inter-arrival times
            for i in range(1, len(flow['packet_times'])):
                iat = flow['packet_times'][i] - flow['packet_times'][i-1]
                splt_iats.append(iat)
            
            # Pad to exactly 20 features
            while len(splt_lengths) < 20:
                splt_lengths.append(0)
            while len(splt_iats) < 20:
                splt_iats.append(0)
            
            # Add SPLT features
            for i in range(20):
                features[f'splt_len_{i+1}'] = splt_lengths[i]
                features[f'splt_iat_{i+1}'] = splt_iats[i]
            
            feature_rows.append(features)
        
        logger.info(f"✅ Extracted {len(feature_rows)} flows from {pcap_path}")
        return feature_rows

def extract_from_all_pcaps():
    """Extract features from all PCAP files in Downloads"""
    
    downloads_path = Path("C:/Users/akshi/Downloads")
    output_path = Path("data/processed/master_unified_data.csv")
    
    # Find all PCAP files
    pcap_files = list(downloads_path.glob("*.pcap"))
    logger.info(f"📂 Found {len(pcap_files)} PCAP files")
    
    extractor = UnifiedFlowExtractor()
    all_flows = []
    
    for pcap_file in pcap_files:
        logger.info(f"Processing: {pcap_file.name}")
        
        # Extract flows
        flows = extractor.extract_features_from_pcap(pcap_file)
        
        # Add source file and determine attack type
        for flow in flows:
            flow['source_file'] = pcap_file.name
            
            # Determine attack type based on filename
            filename = pcap_file.name.lower()
            if 'ddos' in filename:
                flow['attack_type'] = 'DDoS'
                flow['label'] = 1
            elif 'neris' in filename or 'rbot' in filename or 'bot' in filename:
                flow['attack_type'] = 'C2'
                flow['label'] = 1
            elif 'normal' in filename or 'benign' in filename:
                flow['attack_type'] = 'Normal'
                flow['label'] = 0
            else:
                flow['attack_type'] = 'Unknown'
                flow['label'] = 0
        
        all_flows.extend(flows)
    
    if not all_flows:
        logger.error("❌ No flows extracted!")
        return
    
    # Create DataFrame
    df = pd.DataFrame(all_flows)
    
    # THE FIX: Replace NaN with 0.001 for critical features
    critical_cols = ['duration', 'bytes_per_second', 'packets_per_second']
    for col in critical_cols:
        if col in df.columns:
            df[col] = df[col].fillna(0.001)
    
    # Fill any remaining NaN values
    df = df.fillna(0.001)
    
    # Save to CSV
    df.to_csv(output_path, index=False)
    logger.info(f"✅ Saved {len(df)} flows to {output_path}")
    
    # Summary
    logger.info(f"\n📊 EXTRACTION SUMMARY:")
    logger.info(f"Total flows: {len(df):,}")
    logger.info(f"Attack types: {df['attack_type'].value_counts().to_dict()}")
    logger.info(f"SPLT features: {len([col for col in df.columns if 'splt_' in col])}")
    logger.info(f"Basic features: {len([col for col in df.columns if not 'splt_' in col])}")
    
    return output_path

def main():
    """Main extraction function"""
    logger.info("🚀 UNIFIED FEATURE EXTRACTION")
    logger.info("=" * 60)
    logger.info("Extracting identical features from all PCAP files...")
    
    output_file = extract_from_all_pcaps()
    
    if output_file:
        logger.info(f"\n✅ UNIFIED DATASET CREATED: {output_file}")
        logger.info("🎯 Ready for training with consistent features!")
    else:
        logger.error("❌ Extraction failed!")

if __name__ == "__main__":
    main()
