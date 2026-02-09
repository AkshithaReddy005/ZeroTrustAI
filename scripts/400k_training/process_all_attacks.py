#!/usr/bin/env python3
"""
Process all parquet attack datasets to create comprehensive training dataset.

This script:
1. Reads all attack parquet files
2. Converts them to SPLT format
3. Combines with existing 82K dataset
4. Creates unified training set with all 7 attack types
"""

import pathlib
import pandas as pd
import numpy as np
from typing import Dict, List

# Paths
DATA_DIR = pathlib.Path("data")
PROCESSED_DIR = DATA_DIR / "processed"
PARQUET_DIR = DATA_DIR
OUTPUT_CSV = PROCESSED_DIR / "comprehensive_splt_features.csv"

# Attack type mapping
ATTACK_MAPPING = {
    "Benign-Monday-no-metadata.parquet": "benign",
    "Botnet-Friday-no-metadata.parquet": "botnet", 
    "Bruteforce-Tuesday-no-metadata.parquet": "brute_force",
    "DDoS-Friday-no-metadata.parquet": "ddos",
    "DoS-Wednesday-no-metadata.parquet": "dos",
    "Infiltration-Thursday-no-metadata.parquet": "infiltration",
    "Portscan-Friday-no-metadata.parquet": "portscan",
    "WebAttacks-Thursday-no-metadata.parquet": "web_attack"
}

def convert_parquet_to_splt_format(df: pd.DataFrame, attack_type: str) -> pd.DataFrame:
    """
    Convert parquet features to SPLT format matching existing dataset structure.
    """
    print(f"Converting {attack_type} dataset with {len(df)} samples...")
    
    # Map parquet columns to SPLT format
    splt_data = []
    
    for _, row in df.iterrows():
        # Basic flow info
        flow_id = f"{attack_type}_{len(splt_data)}"
        src_ip = "0.0.0.0"  # Placeholder - not in parquet
        dst_ip = "0.0.0.0"  # Placeholder - not in parquet
        src_port = 0  # Placeholder
        dst_port = 0  # Placeholder
        protocol = 6  # TCP default
        
        # Extract timing and size features from parquet
        duration = row.get('Flow Duration', 0)
        total_packets = row.get('Total Fwd Packets', 0) + row.get('Total Backward Packets', 0)
        total_bytes = row.get('Fwd Packets Length Total', 0) + row.get('Bwd Packets Length Total', 0)
        
        # Calculate packet statistics
        if total_packets > 0:
            avg_packet_size = total_bytes / total_packets
        else:
            avg_packet_size = 0
            
        # Create SPLT sequences (simplified from available data)
        splt_lengths = []
        splt_iats = []
        
        # Generate synthetic SPLT based on available statistics
        if 'Packet Length Mean' in row:
            mean_len = row['Packet Length Mean']
            std_len = row.get('Packet Length Std', 0)
            
            # Generate 20 packet lengths with normal distribution
            for i in range(20):
                if i < total_packets:
                    length = max(1, int(np.random.normal(mean_len, std_len)))
                    splt_lengths.append(length)
                else:
                    splt_lengths.append(0)
        
        # Generate inter-arrival times based on flow duration
        if total_packets > 1 and duration > 0:
            avg_iat = duration / (total_packets - 1)
            for i in range(20):
                if i < total_packets - 1:
                    iat = max(0.001, np.random.exponential(avg_iat))
                    splt_iats.append(iat)
                else:
                    splt_iats.append(0)
        
        # Create flow record
        flow_record = {
            'flow_id': flow_id,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'duration': duration,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'avg_packet_size': avg_packet_size,
            'std_packet_size': row.get('Packet Length Std', 0),
            'pps': row.get('Flow Packets/s', 0),
            'avg_entropy': np.random.uniform(2.0, 7.0),  # Placeholder
            'syn_count': row.get('SYN Flag Count', 0),
            'fin_count': row.get('FIN Flag Count', 0),
            'pcap_file': f"{attack_type}.parquet",
            'label': 1 if attack_type != "benign" else 0
        }
        
        # Add SPLT features
        for i in range(1, 21):
            if i <= len(splt_lengths):
                flow_record[f'splt_len_{i}'] = splt_lengths[i-1]
                flow_record[f'splt_iat_{i}'] = splt_iats[i-1] if i <= len(splt_iats) else 0
            else:
                flow_record[f'splt_len_{i}'] = 0
                flow_record[f'splt_iat_{i}'] = 0
        
        splt_data.append(flow_record)
    
    return pd.DataFrame(splt_data)

def process_all_parquets():
    """Process all parquet files and combine them."""
    
    print("Starting comprehensive dataset processing...")
    
    all_data = []
    
    # Process each parquet file
    for parquet_file, attack_type in ATTACK_MAPPING.items():
        parquet_path = PARQUET_DIR / parquet_file
        
        if parquet_path.exists():
            print(f"\nProcessing {parquet_file}...")
            
            try:
                df = pd.read_parquet(parquet_path)
                print(f"Loaded {len(df)} samples from {parquet_file}")
                
                # Convert to SPLT format
                splt_df = convert_parquet_to_splt_format(df, attack_type)
                all_data.append(splt_df)
                
                print(f"Converted to {len(splt_df)} SPLT samples")
                
            except Exception as e:
                print(f"Error processing {parquet_file}: {e}")
                continue
        else:
            print(f"File not found: {parquet_path}")
    
    if not all_data:
        print("No data processed!")
        return
    
    # Combine all data
    print("\nCombining all datasets...")
    combined_df = pd.concat(all_data, ignore_index=True)
    
    # Load existing 82K dataset and add it
    existing_csv = PROCESSED_DIR / "splt_features_labeled.csv"
    if existing_csv.exists():
        print("Loading existing 82K dataset...")
        existing_df = pd.read_csv(existing_csv)
        combined_df = pd.concat([existing_df, combined_df], ignore_index=True)
        print(f"Combined dataset size: {len(combined_df)}")
    
    # Save comprehensive dataset
    print(f"Saving comprehensive dataset to {OUTPUT_CSV}")
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    combined_df.to_csv(OUTPUT_CSV, index=False)
    
    # Print statistics
    print(f"\n📊 Dataset Statistics:")
    print(f"Total samples: {len(combined_df)}")
    print(f"Label distribution:")
    print(combined_df['label'].value_counts())
    
    if 'pcap_file' in combined_df.columns:
        print(f"\nAttack type distribution:")
        attack_counts = combined_df['pcap_file'].value_counts()
        for attack, count in attack_counts.items():
            print(f"  {attack}: {count} samples")
    
    print(f"\n✅ Comprehensive dataset saved to: {OUTPUT_CSV}")

if __name__ == "__main__":
    process_all_parquets()
