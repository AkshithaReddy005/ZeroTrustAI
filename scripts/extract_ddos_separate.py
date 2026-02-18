#!/usr/bin/env python3
"""Extract DDoS Friday dataset into separate CSV file.

This script extracts only DDoS attack traffic from the DDoS-Friday-no-metadata.parquet
and saves it to a separate CSV file for focused training.
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_ddos_separate():
    """Extract DDoS dataset to separate CSV file."""
    
    # Paths
    ddos_parquet_path = Path("data/DDoS-Friday-no-metadata.parquet")
    output_csv_path = Path("data/processed/ddos_separate.csv")
    
    logger.info("🔍 Loading DDoS Friday dataset...")
    
    # Load DDoS dataset
    try:
        df = pd.read_parquet(ddos_parquet_path)
        logger.info(f"✅ Loaded {len(df)} samples from DDoS Friday dataset")
    except FileNotFoundError:
        logger.error(f"❌ DDoS parquet file not found: {ddos_parquet_path}")
        return
    
    # Display dataset info
    logger.info(f"📊 Dataset shape: {df.shape}")
    logger.info(f"📋 Columns: {list(df.columns)}")
    
    # Check if we have labels
    if 'Label' in df.columns:
        label_counts = df['Label'].value_counts()
        logger.info(f"🏷️ Label distribution:")
        for label, count in label_counts.items():
            logger.info(f"   {label}: {count} samples")
        
        # Filter to only attack samples (assuming 'DDoS' or similar)
        attack_labels = ['DDoS', 'DDoS attack', 'Attack', 'Malicious']
        ddos_mask = df['Label'].isin(attack_labels)
        ddos_df = df[ddos_mask]
        
        logger.info(f"🎯 Filtered to {len(ddos_df)} DDoS attack samples")
    else:
        logger.info("⚠️ No 'Label' column found, using all samples as DDoS attacks")
        ddos_df = df.copy()
        # Add label column if not present
        ddos_df['Label'] = 'DDoS'
    
    # Convert to CSV
    logger.info(f"💾 Saving to {output_csv_path}...")
    ddos_df.to_csv(output_csv_path, index=False)
    
    logger.info(f"✅ Successfully saved {len(ddos_df)} DDoS samples to {output_csv_path}")
    
    # Display final info
    logger.info(f"📈 Final DDoS dataset info:")
    logger.info(f"   Shape: {ddos_df.shape}")
    logger.info(f"   File size: {output_csv_path.stat().st_size / (1024*1024):.2f} MB")
    
    return output_csv_path

if __name__ == "__main__":
    extract_ddos_separate()
