#!/usr/bin/env python3
"""Extract a balanced 200K dataset from comprehensive 2.3M flows.

This script creates a balanced dataset with:
- 100K benign flows
- 100K attack flows (stratified across all 7 attack types)

Output: data/processed/balanced_train_200k_v2.csv
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_balanced_200k():
    """Extract balanced 200K dataset from comprehensive data"""
    
    # Paths
    comprehensive_path = Path("data/processed/comprehensive_splt_features.csv")
    output_path = Path("data/processed/balanced_train_200k_v2.csv")
    
    logger.info("🔍 Loading comprehensive dataset...")
    
    # Load comprehensive dataset
    try:
        df = pd.read_csv(comprehensive_path)
        logger.info(f"✅ Loaded {len(df):,} flows from comprehensive dataset")
    except Exception as e:
        logger.error(f"❌ Error loading comprehensive dataset: {e}")
        return
    
    # Analyze attack distribution
    logger.info("📊 Analyzing attack distribution...")
    
    # Map attack types based on pcap_file names
    def map_attack_type(pcap_file):
        if pd.isna(pcap_file):
            return "unknown"
        
        pcap_file = str(pcap_file).lower()
        
        if "normal" in pcap_file or "benign" in pcap_file:
            return "benign"
        elif "dos" in pcap_file or "ddos" in pcap_file:
            return "dos"
        elif "brute" in pcap_file or "bruteforce" in pcap_file:
            return "brute_force"
        elif "infiltration" in pcap_file:
            return "infiltration"
        elif "botnet" in pcap_file:
            return "botnet"
        elif "web" in pcap_file or "sql" in pcap_file or "xss" in pcap_file:
            return "web_attack"
        elif "scan" in pcap_file or "portscan" in pcap_file:
            return "port_scan"
        else:
            return "unknown"
    
    # Add attack type column
    df['attack_type'] = df['pcap_file'].apply(map_attack_type)
    
    # Get distribution
    attack_distribution = df['attack_type'].value_counts()
    logger.info("📈 Attack type distribution:")
    for attack_type, count in attack_distribution.items():
        logger.info(f"   {attack_type}: {count:,} flows")
    
    # Separate benign and attacks
    benign_flows = df[df['attack_type'] == 'benign'].copy()
    attack_flows = df[df['attack_type'] != 'benign'].copy()
    
    logger.info(f"📊 Found {len(benign_flows):,} benign flows")
    logger.info(f"📊 Found {len(attack_flows):,} attack flows")
    
    # Sample 100K benign flows
    if len(benign_flows) >= 100000:
        benign_sample = benign_flows.sample(n=100000, random_state=42)
        logger.info(f"✅ Sampled 100,000 benign flows")
    else:
        logger.warning(f"⚠️ Only {len(benign_flows):,} benign flows available, using all")
        benign_sample = benign_flows
    
    # Sample 100K attack flows (stratified by attack type)
    attack_types = attack_flows['attack_type'].value_counts()
    available_attack_types = [at for at in attack_types.index if at != 'unknown']
    
    logger.info("🎯 Stratified sampling for attack flows...")
    
    attack_samples = []
    samples_per_type = 100000 // len(available_attack_types)
    
    for attack_type in available_attack_types:
        type_flows = attack_flows[attack_flows['attack_type'] == attack_type]
        
        if len(type_flows) >= samples_per_type:
            sample = type_flows.sample(n=samples_per_type, random_state=42)
            logger.info(f"   ✅ {attack_type}: {samples_per_type:,} samples")
        else:
            sample = type_flows
            logger.warning(f"   ⚠️ {attack_type}: only {len(sample):,} samples available")
        
        attack_samples.append(sample)
    
    # Combine attack samples
    if attack_samples:
        attack_sample = pd.concat(attack_samples, ignore_index=True)
        logger.info(f"✅ Total attack samples: {len(attack_sample):,}")
    else:
        logger.error("❌ No attack samples found!")
        return
    
    # If we have more than 100K attack samples, randomly sample down to 100K
    if len(attack_sample) > 100000:
        attack_sample = attack_sample.sample(n=100000, random_state=42)
        logger.info(f"📝 Downsampled to 100,000 attack flows")
    
    # Combine benign and attack samples
    balanced_df = pd.concat([benign_sample, attack_sample], ignore_index=True)
    
    # Shuffle the dataset
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Remove the temporary attack_type column (keep only original label column)
    balanced_df = balanced_df.drop('attack_type', axis=1)
    
    # Final statistics
    final_benign = len(balanced_df[balanced_df['label'] == 0])
    final_attack = len(balanced_df[balanced_df['label'] == 1])
    
    logger.info("📊 Final balanced dataset statistics:")
    logger.info(f"   Total flows: {len(balanced_df):,}")
    logger.info(f"   Benign flows: {final_benign:,} ({final_benign/len(balanced_df)*100:.1f}%)")
    logger.info(f"   Attack flows: {final_attack:,} ({final_attack/len(balanced_df)*100:.1f}%)")
    
    # Save the balanced dataset
    logger.info(f"💾 Saving balanced dataset to {output_path}")
    balanced_df.to_csv(output_path, index=False)
    
    logger.info("🎉 Balanced 200K dataset created successfully!")
    logger.info(f"📁 Saved to: {output_path}")
    logger.info(f"📏 File size: {output_path.stat().st_size / (1024*1024):.1f} MB")

if __name__ == "__main__":
    extract_balanced_200k()
