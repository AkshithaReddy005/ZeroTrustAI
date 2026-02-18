#!/usr/bin/env python3
"""Create dataset with 80K flows from each attack type.

This script creates a balanced dataset with 80K DDoS and 80K C2 flows.
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_80k_dataset():
    """Create dataset with 80K flows from each attack type."""
    
    # Paths
    enhanced_c2_path = Path("data/processed/enhanced_ddos_c2.csv")
    original_ddos_path = Path("data/processed/ddos_separate.csv")
    output_path = Path("data/processed/balanced_80k_ddos_c2.csv")
    
    logger.info("🚀 Creating 80K flows per attack type dataset...")
    
    # Load datasets
    try:
        # Load enhanced dataset (has C2 + some DDoS)
        enhanced_df = pd.read_csv(enhanced_c2_path)
        logger.info(f"✅ Loaded enhanced dataset: {len(enhanced_df)} samples")
        
        # Load original DDoS dataset
        original_ddos_df = pd.read_csv(original_ddos_path)
        logger.info(f"✅ Loaded original DDoS dataset: {len(original_ddos_df)} samples")
        
    except FileNotFoundError as e:
        logger.error(f"❌ File not found: {e}")
        return
    
    # Extract C2 flows from enhanced dataset
    c2_flows = enhanced_df[enhanced_df['Attack_Type'] == 'C2'].copy()
    logger.info(f"📊 Available C2 flows: {len(c2_flows)}")
    
    # Extract DDoS flows from original dataset
    ddos_flows = original_ddos_df.copy()
    # Ensure Attack_Type column exists
    if 'Attack_Type' not in ddos_flows.columns:
        ddos_flows['Attack_Type'] = 'DDoS'
    logger.info(f"📊 Available DDoS flows: {len(ddos_flows)}")
    
    # Target samples per type
    target_per_type = 80000
    
    # Sample C2 flows
    if len(c2_flows) >= target_per_type:
        c2_sample = c2_flows.sample(n=target_per_type, random_state=42)
        logger.info(f"📊 Sampled {target_per_type} C2 flows from {len(c2_flows)}")
    else:
        # If we don't have enough C2 flows, use all and duplicate some
        c2_sample = c2_flows
        needed = target_per_type - len(c2_sample)
        if needed > 0:
            # Duplicate random C2 flows to reach target
            duplicate_c2 = c2_flows.sample(n=needed, replace=True, random_state=42)
            c2_sample = pd.concat([c2_sample, duplicate_c2], ignore_index=True)
        logger.info(f"📊 Used all {len(c2_flows)} C2 flows and duplicated {needed} to reach {target_per_type}")
    
    # Sample DDoS flows
    if len(ddos_flows) >= target_per_type:
        ddos_sample = ddos_flows.sample(n=target_per_type, random_state=42)
        logger.info(f"📊 Sampled {target_per_type} DDoS flows from {len(ddos_flows)}")
    else:
        # Use all DDoS flows (shouldn't happen as we have 128K)
        ddos_sample = ddos_flows
        logger.info(f"📊 Used all {len(ddos_flows)} DDoS flows")
    
    # Ensure both have same columns for concatenation
    # Get common columns
    c2_columns = set(c2_sample.columns)
    ddos_columns = set(ddos_sample.columns)
    common_columns = c2_columns.intersection(ddos_columns)
    
    # Add missing columns with default values
    for col in common_columns - c2_columns:
        c2_sample[col] = 0
    for col in common_columns - ddos_columns:
        ddos_sample[col] = 0
    
    # Keep only common columns
    final_columns = list(common_columns)
    c2_sample = c2_sample[final_columns]
    ddos_sample = ddos_sample[final_columns]
    
    # Combine datasets
    combined_df = pd.concat([ddos_sample, c2_sample], ignore_index=True)
    
    # Shuffle the combined dataset
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    logger.info(f"📈 Final 80K dataset info:")
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
    
    # Save dataset
    logger.info(f"💾 Saving 80K dataset to {output_path}...")
    combined_df.to_csv(output_path, index=False)
    
    logger.info(f"✅ 80K dataset created!")
    logger.info(f"📁 Dataset: {output_path} ({output_path.stat().st_size / (1024*1024):.2f} MB)")
    
    return output_path

if __name__ == "__main__":
    create_80k_dataset()
