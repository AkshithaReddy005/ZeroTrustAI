#!/usr/bin/env python3
"""Check DDoS source dataset"""

import pandas as pd

# Check the source DDoS parquet file
ddos_path = 'data/DDoS-Friday-no-metadata.parquet'
try:
    df = pd.read_parquet(ddos_path)
    print('📂 DDoS SOURCE DATASET ANALYSIS')
    print('=' * 50)
    print(f'Source file: {ddos_path}')
    print(f'Total samples: {len(df):,}')
    print(f'Columns: {len(df.columns)}')
    
    # Check labels
    if 'Label' in df.columns:
        print(f'\n🏷️ Label distribution:')
        label_dist = df['Label'].value_counts()
        for label, count in label_dist.items():
            percentage = (count / len(df)) * 100
            print(f'{label}: {count:,} ({percentage:.1f}%)')
    else:
        print('\n⚠️ No Label column found')
    
    # Sample columns
    print(f'\n📋 Sample columns:')
    for i, col in enumerate(df.columns[:15]):
        print(f'{i+1:2d}. {col}')
    if len(df.columns) > 15:
        print(f'    ... and {len(df.columns)-15} more')
    
    # Check for SPLT features
    splt_cols = [col for col in df.columns if 'splt_' in col]
    print(f'\n🔢 SPLT features: {len(splt_cols)}')
    
    # Basic stats
    print(f'\n📈 Basic statistics:')
    if 'Protocol' in df.columns:
        protocol_dist = df['Protocol'].value_counts().to_dict()
        print(f'Protocol distribution: {protocol_dist}')
    if 'Flow Duration' in df.columns:
        flow_mean = df['Flow Duration'].mean()
        print(f'Flow Duration - Mean: {flow_mean:.2f}')
    
except Exception as e:
    print(f'❌ Error reading DDoS source: {e}')
