#!/usr/bin/env python3
"""
Create Balanced 80K DDoS + 80K C2 Dataset

This script:
1. Extracts 80K DDoS samples from comprehensive dataset (with SPLT features)
2. Uses existing 37.6K C2 samples and extracts more to reach 80K
3. Creates balanced dataset with SPLT features for both attack types
4. Outputs: data/processed/balanced_80k_ddos_c2_splt.csv
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging
import random

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_balanced_dataset():
    """Create balanced 80K DDoS + 80K C2 dataset with SPLT features"""
    
    logger.info("🎯 Creating balanced 80K DDoS + 80K C2 dataset...")
    
    # Paths
    comprehensive_path = Path("data/processed/400k_datasets/comprehensive_splt_features.csv")
    full_c2_path = Path("data/processed/full_ddos_c2.csv")
    output_path = Path("data/processed/balanced_80k_ddos_c2_splt.csv")
    
    # Load comprehensive dataset
    logger.info("📂 Loading comprehensive dataset...")
    comp_df = pd.read_csv(comprehensive_path, low_memory=False)
    logger.info(f"Comprehensive dataset: {len(comp_df)} samples")
    
    # Extract DDoS samples (label=1) with SPLT features
    ddos_samples = comp_df[comp_df['label'] == 1].copy()
    logger.info(f"Available DDoS samples: {len(ddos_samples)}")
    
    # Sample 80K DDoS samples
    if len(ddos_samples) >= 80000:
        ddos_balanced = ddos_samples.sample(n=80000, random_state=42)
        logger.info(f"✅ Selected 80K DDoS samples")
    else:
        logger.warning(f"⚠️ Only {len(ddos_samples)} DDoS samples available")
        ddos_balanced = ddos_samples
    
    # Load C2 samples from full dataset
    logger.info("📂 Loading C2 samples...")
    c2_full_df = pd.read_csv(full_c2_path, low_memory=False)
    c2_samples = c2_full_df[c2_full_df['Attack_Type'] == 'C2'].copy()
    logger.info(f"Available C2 samples: {len(c2_samples)}")
    
    # Need more C2 samples to reach 80K
    if len(c2_samples) < 80000:
        needed = 80000 - len(c2_samples)
        logger.info(f"🔍 Need {needed} more C2 samples...")
        
        # Check if we can extract more C2 from comprehensive dataset
        c2_from_comp = comp_df[comp_df['label'] == 0].copy()
        logger.info(f"C2-like samples in comprehensive: {len(c2_from_comp)}")
        
        if len(c2_from_comp) >= needed:
            additional_c2 = c2_from_comp.sample(n=needed, random_state=42)
            logger.info(f"✅ Extracted {needed} additional C2 samples")
            
            # Combine C2 samples
            c2_balanced = pd.concat([c2_samples, additional_c2], ignore_index=True)
            c2_balanced = c2_balanced.sample(n=80000, random_state=42)  # Ensure exactly 80K
        else:
            logger.warning(f"⚠️ Only {len(c2_from_comp)} additional C2 samples available")
            c2_balanced = pd.concat([c2_samples, c2_from_comp], ignore_index=True)
    else:
        # Sample 80K C2 samples
        c2_balanced = c2_samples.sample(n=80000, random_state=42)
        logger.info(f"✅ Selected 80K C2 samples")
    
    logger.info(f"Final C2 samples: {len(c2_balanced)}")
    
    # Standardize column names and structure
    logger.info("🔧 Standardizing dataset structure...")
    
    # Ensure both datasets have same columns
    common_cols = list(set(ddos_balanced.columns) & set(c2_balanced.columns))
    logger.info(f"Common columns: {len(common_cols)}")
    
    ddos_standardized = ddos_balanced[common_cols].copy()
    c2_standardized = c2_balanced[common_cols].copy()
    
    # Add attack type labels
    ddos_standardized['Attack_Type'] = 'DDoS'
    ddos_standardized['Label'] = 1
    
    c2_standardized['Attack_Type'] = 'C2'
    c2_standardized['Label'] = 1
    
    # Combine datasets
    balanced_df = pd.concat([ddos_standardized, c2_standardized], ignore_index=True)
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
    
    logger.info(f"📊 Final balanced dataset: {len(balanced_df)} samples")
    logger.info(f"DDoS: {len(balanced_df[balanced_df['Attack_Type'] == 'DDoS'])}")
    logger.info(f"C2: {len(balanced_df[balanced_df['Attack_Type'] == 'C2'])}")
    
    # Check SPLT features
    splt_cols = [col for col in balanced_df.columns if 'splt_' in col]
    logger.info(f"SPLT features available: {len(splt_cols)}")
    
    # Save balanced dataset
    balanced_df.to_csv(output_path, index=False)
    logger.info(f"✅ Balanced dataset saved to {output_path}")
    
    # Create summary
    summary = {
        'total_samples': len(balanced_df),
        'ddos_samples': len(balanced_df[balanced_df['Attack_Type'] == 'DDoS']),
        'c2_samples': len(balanced_df[balanced_df['Attack_Type'] == 'C2']),
        'splt_features': len(splt_cols),
        'columns': list(balanced_df.columns)
    }
    
    summary_path = output_path.with_suffix('.json')
    import json
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info(f"📋 Dataset summary saved to {summary_path}")
    
    return balanced_df

def main():
    """Main function"""
    logger.info("🚀 Creating Balanced 80K DDoS + 80K C2 Dataset")
    logger.info("=" * 60)
    
    balanced_df = create_balanced_dataset()
    
    logger.info("\n✅ BALANCED DATASET CREATED SUCCESSFULLY")
    logger.info("📁 Output: data/processed/balanced_80k_ddos_c2_splt.csv")
    logger.info("🎯 Ready for training with SPLT features for both attack types")

if __name__ == "__main__":
    main()
