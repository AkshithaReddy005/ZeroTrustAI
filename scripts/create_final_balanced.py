#!/usr/bin/env python3
"""
Create Final Balanced Dataset for Training
80K C2 + 80K DDoS + 80K Normal = 240K total

This script:
1. Uses the unified C2 data (78K samples)
2. Gets DDoS data from comprehensive dataset 
3. Gets Normal traffic from comprehensive dataset
4. Creates balanced 240K dataset with SPLT features
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_final_balanced_dataset():
    """Create final balanced 240K dataset"""
    
    logger.info("🎯 Creating Final Balanced Dataset (80K C2 + 80K DDoS + 80K Normal)")
    
    # Paths
    unified_c2_path = Path("data/processed/master_unified_data.csv")
    comprehensive_path = Path("data/processed/400k_datasets/comprehensive_splt_features.csv")
    output_path = Path("data/processed/final_balanced_240k.csv")
    
    # Load unified C2 data
    logger.info("📂 Loading unified C2 data...")
    c2_df = pd.read_csv(unified_c2_path)
    c2_samples = c2_df[c2_df['attack_type'] == 'C2'].copy()
    logger.info(f"C2 samples available: {len(c2_samples):,}")
    
    # Load comprehensive dataset for DDoS and Normal
    logger.info("📂 Loading comprehensive dataset...")
    comp_df = pd.read_csv(comprehensive_path, low_memory=False)
    logger.info(f"Comprehensive dataset: {len(comp_df):,} samples")
    
    # Extract DDoS samples (label=1)
    ddos_samples = comp_df[comp_df['label'] == 1].copy()
    logger.info(f"DDoS samples available: {len(ddos_samples):,}")
    
    # Extract Normal samples (label=0)
    normal_samples = comp_df[comp_df['label'] == 0].copy()
    logger.info(f"Normal samples available: {len(normal_samples):,}")
    
    # Sample exactly 80K of each type
    target_size = 80000
    
    # C2 - sample 80K (we have 78K, so use all and pad)
    if len(c2_samples) >= target_size:
        c2_balanced = c2_samples.sample(n=target_size, random_state=42)
    else:
        c2_balanced = c2_samples.copy()
        logger.warning(f"Only {len(c2_samples)} C2 samples available (need {target_size})")
    
    # DDoS - sample 80K
    if len(ddos_samples) >= target_size:
        ddos_balanced = ddos_samples.sample(n=target_size, random_state=42)
    else:
        ddos_balanced = ddos_samples.copy()
        logger.warning(f"Only {len(ddos_samples)} DDoS samples available (need {target_size})")
    
    # Normal - sample 80K
    if len(normal_samples) >= target_size:
        normal_balanced = normal_samples.sample(n=target_size, random_state=42)
    else:
        normal_balanced = normal_samples.copy()
        logger.warning(f"Only {len(normal_samples)} Normal samples available (need {target_size})")
    
    logger.info(f"Selected samples:")
    logger.info(f"C2: {len(c2_balanced):,}")
    logger.info(f"DDoS: {len(ddos_balanced):,}")
    logger.info(f"Normal: {len(normal_balanced):,}")
    
    # Standardize column structure
    logger.info("🔧 Standardizing dataset structure...")
    
    # Get common columns between all datasets
    c2_cols = set(c2_balanced.columns)
    ddos_cols = set(ddos_balanced.columns)
    normal_cols = set(normal_balanced.columns)
    
    common_cols = list(c2_cols & ddos_cols & normal_cols)
    logger.info(f"Common columns: {len(common_cols)}")
    
    # Ensure SPLT features are included
    splt_cols = [col for col in common_cols if 'splt_' in col]
    logger.info(f"SPLT features in common: {len(splt_cols)}")
    
    # Standardize each dataset
    c2_std = c2_balanced[common_cols].copy()
    ddos_std = ddos_balanced[common_cols].copy()
    normal_std = normal_balanced[common_cols].copy()
    
    # Add attack type labels
    c2_std['Attack_Type'] = 'C2'
    c2_std['Label'] = 1
    
    ddos_std['Attack_Type'] = 'DDoS'
    ddos_std['Label'] = 1
    
    normal_std['Attack_Type'] = 'Normal'
    normal_std['Label'] = 0
    
    # Combine datasets
    final_df = pd.concat([c2_std, ddos_std, normal_std], ignore_index=True)
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
    
    logger.info(f"📊 Final dataset: {len(final_df):,} samples")
    logger.info(f"C2: {len(final_df[final_df['Attack_Type'] == 'C2']):,}")
    logger.info(f"DDoS: {len(final_df[final_df['Attack_Type'] == 'DDoS']):,}")
    logger.info(f"Normal: {len(final_df[final_df['Attack_Type'] == 'Normal']):,}")
    
    # Handle missing values
    logger.info("🔧 Handling missing values...")
    # Replace NaN with 0.001 for critical features
    critical_cols = ['duration', 'bytes_per_second', 'packets_per_second']
    for col in critical_cols:
        if col in final_df.columns:
            final_df[col] = final_df[col].fillna(0.001)
    
    # Fill any remaining NaN
    final_df = final_df.fillna(0.001)
    
    # Save final dataset
    final_df.to_csv(output_path, index=False)
    logger.info(f"✅ Final balanced dataset saved to {output_path}")
    
    # Create summary
    summary = {
        'total_samples': len(final_df),
        'c2_samples': len(final_df[final_df['Attack_Type'] == 'C2']),
        'ddos_samples': len(final_df[final_df['Attack_Type'] == 'DDoS']),
        'normal_samples': len(final_df[final_df['Attack_Type'] == 'Normal']),
        'splt_features': len(splt_cols),
        'columns': list(final_df.columns)
    }
    
    summary_path = output_path.with_suffix('.json')
    import json
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info(f"📋 Dataset summary saved to {summary_path}")
    
    return final_df

def main():
    """Main function"""
    logger.info("🚀 Creating Final Balanced Dataset")
    logger.info("=" * 60)
    
    final_df = create_final_balanced_dataset()
    
    logger.info("\n✅ FINAL BALANCED DATASET CREATED")
    logger.info("📁 Output: data/processed/final_balanced_240k.csv")
    logger.info("🎯 Ready for malicious vs normal training!")

if __name__ == "__main__":
    main()
