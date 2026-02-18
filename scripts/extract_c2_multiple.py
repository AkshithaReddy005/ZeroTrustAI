#!/usr/bin/env python3
"""Extract C2 traffic from multiple PCAP files and create balanced dataset.

This script processes multiple PCAP files to extract Command & Control traffic
and creates a balanced dataset with DDoS data.
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging
import struct
import socket
import glob

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    import dpkt
    DPKT_AVAILABLE = True
    logger.info("✅ dpkt is available")
except ImportError as e:
    DPKT_AVAILABLE = False
    logger.error(f"❌ dpkt import error: {e}")

def parse_ip_address(ip_bytes):
    """Convert IP bytes to string."""
    try:
        return socket.inet_ntoa(ip_bytes)
    except:
        return "0.0.0.0"

def extract_flows_from_pcap(pcap_path):
    """Extract network flows from PCAP file using dpkt."""
    logger.info(f"🔍 Extracting flows from {pcap_path} using dpkt...")
    
    if not DPKT_AVAILABLE:
        logger.error("❌ dpkt not available. Install with: pip install dpkt")
        return None
    
    try:
        flows = []
        flow_key_to_data = {}
        
        with open(pcap_path, 'rb') as f:
            # Read PCAP file
            pcap = dpkt.pcap.Reader(f)
            
            for timestamp, buf in pcap:
                try:
                    # Parse Ethernet frame
                    eth = dpkt.ethernet.Ethernet(buf)
                    
                    # Skip non-IP packets
                    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        continue
                    
                    # Get IP layer
                    ip = eth.data
                    
                    # Skip non-TCP/UDP packets
                    if not isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        continue
                    
                    # Get transport layer
                    transport = ip.data
                    
                    # Extract flow information
                    src_ip = parse_ip_address(ip.src)
                    dst_ip = parse_ip_address(ip.dst)
                    src_port = transport.sport
                    dst_port = transport.dport
                    protocol = 'TCP' if isinstance(transport, dpkt.tcp.TCP) else 'UDP'
                    
                    # Create flow key (5-tuple)
                    if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                        direction = 'src2dst'
                    else:
                        flow_key = (dst_ip, src_ip, dst_port, src_port, protocol)
                        direction = 'dst2src'
                    
                    # Initialize flow if not exists
                    if flow_key not in flow_key_to_data:
                        flow_key_to_data[flow_key] = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'src2dst_packets': 0,
                            'src2dst_bytes': 0,
                            'dst2src_packets': 0,
                            'dst2src_bytes': 0,
                            'start_time': timestamp,
                            'end_time': timestamp,
                            'src2dst_start_time': timestamp if direction == 'src2dst' else None,
                            'dst2src_start_time': timestamp if direction == 'dst2src' else None,
                        }
                    
                    # Update flow statistics
                    flow = flow_key_to_data[flow_key]
                    packet_len = len(buf)
                    
                    if direction == 'src2dst':
                        flow['src2dst_packets'] += 1
                        flow['src2dst_bytes'] += packet_len
                        if flow['src2dst_start_time'] is None:
                            flow['src2dst_start_time'] = timestamp
                    else:
                        flow['dst2src_packets'] += 1
                        flow['dst2src_bytes'] += packet_len
                        if flow['dst2src_start_time'] is None:
                            flow['dst2src_start_time'] = timestamp
                    
                    # Update timestamps
                    flow['end_time'] = timestamp
                    
                except Exception as e:
                    # Skip malformed packets
                    continue
        
        # Convert flow data to list
        for flow_key, flow_data in flow_key_to_data.items():
            # Calculate derived metrics
            total_packets = flow_data['src2dst_packets'] + flow_data['dst2src_packets']
            total_bytes = flow_data['src2dst_bytes'] + flow_data['dst2src_bytes']
            duration = flow_data['end_time'] - flow_data['start_time']
            
            if duration <= 0:
                duration = 0.001  # Minimum duration to avoid division by zero
            
            # Calculate packet rates
            src2dst_duration = (flow_data['src2dst_start_time'] and 
                              (flow_data['end_time'] - flow_data['src2dst_start_time']) or duration)
            dst2src_duration = (flow_data['dst2src_start_time'] and 
                              (flow_data['end_time'] - flow_data['dst2src_start_time']) or duration)
            
            flow_data.update({
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'duration': duration,
                'packets_per_second': total_packets / duration,
                'bytes_per_second': total_bytes / duration,
                'src2dst_pps': flow_data['src2dst_packets'] / src2dst_duration if src2dst_duration > 0 else 0,
                'dst2src_pps': flow_data['dst2src_packets'] / dst2src_duration if dst2src_duration > 0 else 0,
                'src2dst_bps': flow_data['src2dst_bytes'] / src2dst_duration if src2dst_duration > 0 else 0,
                'dst2src_bps': flow_data['dst2src_bytes'] / dst2src_duration if dst2src_duration > 0 else 0,
            })
            
            flows.append(flow_data)
        
        if flows:
            df = pd.DataFrame(flows)
            logger.info(f"✅ Extracted {len(df)} flows from {pcap_path}")
            return df
        else:
            logger.warning(f"⚠️ No flows extracted from {pcap_path}")
            return None
            
    except Exception as e:
        logger.error(f"❌ Error processing {pcap_path}: {e}")
        return None

def identify_c2_flows(df, pcap_name):
    """Identify potential C2 flows based on characteristics."""
    if df is None or df.empty:
        return None
    
    logger.info(f"🔍 Identifying C2 flows in {pcap_name}...")
    
    c2_flows = []
    
    for _, row in df.iterrows():
        is_c2 = False
        reasons = []
        
        # Get flow information
        src_ip = row.get('src_ip', '')
        dst_ip = row.get('dst_ip', '')
        src_port = row.get('src_port', 0)
        dst_port = row.get('dst_port', 0)
        protocol = row.get('protocol', '')
        total_packets = row.get('total_packets', 0)
        total_bytes = row.get('total_bytes', 0)
        duration = row.get('duration', 0.001)
        pps = row.get('packets_per_second', 0)
        bps = row.get('bytes_per_second', 0)
        
        # C2 Pattern 1: External IP communication (non-private)
        def is_private_ip(ip):
            try:
                parts = ip.split('.')
                if len(parts) != 4:
                    return False
                if parts[0] == '192' and parts[1] == '168':
                    return True
                if parts[0] == '10':
                    return True
                if parts[0] == '172' and 16 <= int(parts[1]) <= 31:
                    return True
                return False
            except:
                return False
        
        if not (is_private_ip(src_ip) and is_private_ip(dst_ip)):
            is_c2 = True
            reasons.append('external_comm')
        
        # C2 Pattern 2: Common C2 ports
        c2_ports = [6667, 6668, 6669, 8080, 443, 53, 25, 587, 1337, 31337, 12345, 80, 8081, 8443]
        if dst_port in c2_ports or src_port in c2_ports:
            is_c2 = True
            reasons.append('c2_port')
        
        # C2 Pattern 3: Persistent low-volume connections
        if 0.1 <= pps <= 10 and duration > 10:  # Low packet rate, long duration
            is_c2 = True
            reasons.append('persistent_low_volume')
        
        # C2 Pattern 4: Small packet sizes
        if total_packets > 0:
            avg_packet_size = total_bytes / total_packets
            if avg_packet_size < 500:  # Small packets
                is_c2 = True
                reasons.append('small_packets')
        
        # C2 Pattern 5: Asymmetric traffic
        src2dst_packets = row.get('src2dst_packets', 0)
        dst2src_packets = row.get('dst2src_packets', 0)
        
        if src2dst_packets > 0 and dst2src_packets > 0:
            ratio = max(src2dst_packets, dst2src_packets) / min(src2dst_packets, dst2src_packets)
            if ratio > 3:  # Highly asymmetric (lowered threshold)
                is_c2 = True
                reasons.append('asymmetric_traffic')
        
        # C2 Pattern 6: Long-lived connections
        if duration > 60:  # More than 1 minute (lowered threshold)
            is_c2 = True
            reasons.append('long_lived')
        
        # C2 Pattern 7: Periodic communication (beaconing)
        if 0.01 <= pps <= 1 and duration > 300:  # Very low rate, long duration
            is_c2 = True
            reasons.append('periodic_beaconing')
        
        if is_c2:
            c2_flows.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'duration': duration,
                'pps': pps,
                'bps': bps,
                'src2dst_packets': src2dst_packets,
                'dst2src_packets': dst2src_packets,
                'reasons': ','.join(reasons),
                'pcap_file': pcap_name
            })
    
    if c2_flows:
        c2_df = pd.DataFrame(c2_flows)
        logger.info(f"🎯 Identified {len(c2_df)} potential C2 flows in {pcap_name}")
        return c2_df
    else:
        logger.info(f"ℹ️ No clear C2 patterns found in {pcap_name}")
        return None

def convert_to_splt_format(c2_df, pcap_name):
    """Convert dpkt C2 data to SPLT format."""
    if c2_df is None or c2_df.empty:
        return None
    
    logger.info(f"🔄 Converting {pcap_name} C2 data to SPLT format...")
    
    converted_data = []
    
    for _, row in c2_df.iterrows():
        # Extract flow metrics
        duration = row.get('duration', 1.0)
        packets = row.get('total_packets', 10)
        bytes_total = row.get('total_bytes', 1000)
        pps = row.get('pps', packets / duration)
        bps = row.get('bps', bytes_total / duration)
        avg_packet_size = bytes_total / packets if packets > 0 else 100
        
        # Protocol encoding
        protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
        protocol = protocol_map.get(str(row.get('protocol', 'TCP')), 6)
        
        # Create SPLT features
        splt_len = [avg_packet_size] * 20
        splt_iat = [duration/packets] * 20 if packets > 0 else [0] * 20
        
        # Create feature dict
        flow_features = {
            'Protocol': protocol,
            'Flow Duration': duration,
            'Total Fwd Packets': row.get('src2dst_packets', packets // 2),
            'Total Backward Packets': row.get('dst2src_packets', packets - (packets // 2)),
            'Fwd Packets Length Total': bytes_total // 2,
            'Bwd Packets Length Total': bytes_total - (bytes_total // 2),
            'Flow Bytes/s': bps,
            'Flow Packets/s': pps,
            'Label': 1,  # Malicious
            'Attack_Type': 'C2',
            'PcapFile': pcap_name,
            'SrcIP': row.get('src_ip', ''),
            'DstIP': row.get('dst_ip', ''),
            'DstPort': row.get('dst_port', 0),
            'C2_Reasons': row.get('reasons', ''),
        }
        
        # Add SPLT features
        for i in range(1, 21):
            flow_features[f'splt_len_{i}'] = splt_len[i-1]
            flow_features[f'splt_iat_{i}'] = splt_iat[i-1]
        
        # Add other required features
        default_features = {
            'Fwd Packet Length Max': avg_packet_size * 1.5,
            'Fwd Packet Length Min': avg_packet_size * 0.5,
            'Fwd Packet Length Mean': avg_packet_size,
            'Fwd Packet Length Std': avg_packet_size * 0.1,
            'Bwd Packet Length Max': avg_packet_size * 1.5,
            'Bwd Packet Length Min': avg_packet_size * 0.5,
            'Bwd Packet Length Mean': avg_packet_size,
            'Bwd Packet Length Std': avg_packet_size * 0.1,
            'Flow IAT Mean': duration/packets if packets > 0 else 0,
            'Flow IAT Std': 0,
            'Flow IAT Max': duration,
            'Flow IAT Min': 0,
            'Fwd IAT Total': duration/2,
            'Fwd IAT Mean': duration/packets/2 if packets > 0 else 0,
            'Fwd IAT Std': 0,
            'Fwd IAT Max': duration,
            'Fwd IAT Min': 0,
            'Bwd IAT Total': duration/2,
            'Bwd IAT Mean': duration/packets/2 if packets > 0 else 0,
            'Bwd IAT Std': 0,
            'Bwd IAT Max': duration,
            'Bwd IAT Min': 0,
            'Fwd PSH Flags': 0,
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'Fwd Header Length': 40,
            'Bwd Header Length': 40,
            'Fwd Packets/s': pps/2,
            'Bwd Packets/s': pps/2,
            'Packet Length Min': avg_packet_size * 0.5,
            'Packet Length Max': avg_packet_size * 1.5,
            'Packet Length Mean': avg_packet_size,
            'Packet Length Std': avg_packet_size * 0.1,
            'Packet Length Variance': (avg_packet_size * 0.1) ** 2,
            'FIN Flag Count': 0,
            'SYN Flag Count': 1,
            'RST Flag Count': 0,
            'PSH Flag Count': 0,
            'ACK Flag Count': 1,
            'URG Flag Count': 0,
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': 1.0,
            'Avg Packet Size': avg_packet_size,
            'Avg Fwd Segment Size': avg_packet_size,
            'Avg Bwd Segment Size': avg_packet_size,
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': row.get('src2dst_packets', packets // 2),
            'Subflow Fwd Bytes': bytes_total // 2,
            'Subflow Bwd Packets': row.get('dst2src_packets', packets - (packets // 2)),
            'Subflow Bwd Bytes': bytes_total - (bytes_total // 2),
            'Init Fwd Win Bytes': 8192,
            'Init Bwd Win Bytes': 8192,
            'Fwd Act Data Packets': packets // 2,
            'Fwd Seg Size Min': avg_packet_size * 0.5,
            'Active Mean': duration,
            'Active Std': 0,
            'Active Max': duration,
            'Active Min': 0,
            'Idle Mean': 0,
            'Idle Std': 0,
            'Idle Max': 0,
            'Idle Min': 0,
        }
        
        flow_features.update(default_features)
        converted_data.append(flow_features)
    
    if converted_data:
        converted_df = pd.DataFrame(converted_data)
        logger.info(f"✅ Converted {len(converted_df)} C2 flows to SPLT format")
        return converted_df
    else:
        logger.warning("⚠️ No valid flows to convert")
        return None

def create_balanced_dataset(c2_df, ddos_path, balance_ratio=1.0):
    """Create a balanced dataset with C2 and DDoS data."""
    logger.info("🔗 Creating balanced dataset...")
    
    # Load existing DDoS data
    try:
        ddos_df = pd.read_csv(ddos_path)
        logger.info(f"✅ Loaded {len(ddos_df)} DDoS samples")
        
        # Ensure DDoS data has Attack_Type column
        if 'Attack_Type' not in ddos_df.columns:
            ddos_df['Attack_Type'] = 'DDoS'
        
        # Ensure DDoS data has numeric label
        if 'Label' not in ddos_df.columns:
            ddos_df['Label'] = 1
        elif ddos_df['Label'].dtype == 'object':
            ddos_df['Label'] = ddos_df['Label'].apply(lambda x: 1 if str(x).strip() == '1' else 0)
        
    except FileNotFoundError:
        logger.error(f"❌ DDoS file not found: {ddos_path}")
        return None
    
    # Determine target sample sizes
    c2_count = len(c2_df)
    ddos_count = len(ddos_df)
    
    if balance_ratio == 1.0:
        # Perfect balance: equal samples
        target_ddos = min(c2_count, ddos_count)
        target_c2 = min(c2_count, ddos_count)
    elif balance_ratio > 1.0:
        # More DDoS than C2
        target_c2 = c2_count
        target_ddos = int(c2_count * balance_ratio)
    else:
        # More C2 than DDoS
        target_ddos = ddos_count
        target_c2 = int(ddos_count / balance_ratio)
    
    # Sample datasets
    if target_ddos < ddos_count:
        ddos_sample = ddos_df.sample(n=target_ddos, random_state=42)
        logger.info(f"📊 Sampled {target_ddos} DDoS samples from {ddos_count}")
    else:
        ddos_sample = ddos_df
        logger.info(f"📊 Using all {ddos_count} DDoS samples")
    
    if target_c2 < c2_count:
        c2_sample = c2_df.sample(n=target_c2, random_state=42)
        logger.info(f"📊 Sampled {target_c2} C2 samples from {c2_count}")
    else:
        c2_sample = c2_df
        logger.info(f"📊 Using all {c2_count} C2 samples")
    
    # Combine datasets
    combined_df = pd.concat([ddos_sample, c2_sample], ignore_index=True)
    
    logger.info(f"📈 Balanced dataset info:")
    logger.info(f"   Total samples: {len(combined_df)}")
    logger.info(f"   DDoS samples: {len(ddos_sample)}")
    logger.info(f"   C2 samples: {len(c2_sample)}")
    logger.info(f"   Balance ratio: {len(ddos_sample)/len(c2_sample):.2f}")
    
    # Show attack type distribution
    if 'Attack_Type' in combined_df.columns:
        attack_counts = combined_df['Attack_Type'].value_counts()
        logger.info(f"🎯 Attack type distribution:")
        for attack_type, count in attack_counts.items():
            logger.info(f"   {attack_type}: {count} samples ({count/len(combined_df)*100:.1f}%)")
    
    return combined_df

def find_pcap_files(download_dir):
    """Find all PCAP files in download directory."""
    download_path = Path(download_dir)
    
    # Look for .pcap files
    pcap_files = list(download_path.rglob("*.pcap"))
    
    # Also look for common botnet capture patterns
    botnet_patterns = [
        "*botnet*.pcap",
        "*bot*.pcap", 
        "*malware*.pcap",
        "*capture*.pcap"
    ]
    
    for pattern in botnet_patterns:
        pcap_files.extend(download_path.rglob(pattern))
    
    # Remove duplicates and sort
    pcap_files = sorted(list(set(pcap_files)))
    
    logger.info(f"📁 Found {len(pcap_files)} PCAP files:")
    for pcap_file in pcap_files:
        logger.info(f"   {pcap_file.name}")
    
    return pcap_files

def extract_c2_from_multiple_pcaps():
    """Main function to extract C2 traffic from multiple PCAP files."""
    
    # Configuration
    download_dir = "C:/Users/akshi/Downloads"  # Your downloads folder
    ddos_path = Path("data/processed/ddos_separate.csv")
    balanced_output_path = Path("data/processed/balanced_ddos_c2.csv")
    full_output_path = Path("data/processed/full_ddos_c2.csv")
    
    logger.info("🚀 Starting multiple PCAP C2 extraction...")
    
    # Check dpkt availability
    if not DPKT_AVAILABLE:
        logger.error("❌ dpkt not installed. Install with: pip install dpkt")
        return
    
    # Find all PCAP files
    pcap_files = find_pcap_files(download_dir)
    
    if not pcap_files:
        logger.error("❌ No PCAP files found")
        return
    
    all_c2_data = []
    
    # Process each PCAP file
    for pcap_file in pcap_files:
        pcap_name = pcap_file.stem
        
        # Skip normal traffic for C2 extraction
        if 'normal' in pcap_name.lower():
            logger.info(f"⏭️ Skipping normal traffic: {pcap_name}")
            continue
        
        logger.info(f"📁 Processing {pcap_name}...")
        
        # Extract flows from PCAP
        flows_df = extract_flows_from_pcap(pcap_file)
        
        if flows_df is not None:
            # Identify C2 flows
            c2_data = identify_c2_flows(flows_df, pcap_name)
            
            if c2_data is not None and not c2_data.empty:
                # Convert to SPLT format
                c2_splt = convert_to_splt_format(c2_data, pcap_name)
                
                if c2_splt is not None:
                    all_c2_data.append(c2_splt)
    
    if not all_c2_data:
        logger.error("❌ No C2 traffic found in any PCAP file")
        return
    
    # Combine all C2 data
    combined_c2 = pd.concat(all_c2_data, ignore_index=True)
    logger.info(f"📊 Total C2 flows extracted: {len(combined_c2)}")
    
    # Show C2 sources
    if 'PcapFile' in combined_c2.columns:
        pcap_counts = combined_c2['PcapFile'].value_counts()
        logger.info(f"📋 C2 flows by source:")
        for pcap_file, count in pcap_counts.items():
            logger.info(f"   {pcap_file}: {count} flows")
    
    # Save full dataset
    logger.info(f"💾 Saving full dataset to {full_output_path}...")
    full_dataset = create_balanced_dataset(combined_c2, ddos_path, balance_ratio=3.4)  # Current ratio
    full_dataset.to_csv(full_output_path, index=False)
    
    # Create balanced dataset
    logger.info(f"💾 Creating balanced dataset...")
    balanced_dataset = create_balanced_dataset(combined_c2, ddos_path, balance_ratio=1.0)
    balanced_dataset.to_csv(balanced_output_path, index=False)
    
    logger.info(f"✅ Extraction complete!")
    logger.info(f"📁 Full dataset: {full_output_path} ({full_output_path.stat().st_size / (1024*1024):.2f} MB)")
    logger.info(f"📁 Balanced dataset: {balanced_output_path} ({balanced_output_path.stat().st_size / (1024*1024):.2f} MB)")
    
    return full_output_path, balanced_output_path

if __name__ == "__main__":
    extract_c2_from_multiple_pcaps()
