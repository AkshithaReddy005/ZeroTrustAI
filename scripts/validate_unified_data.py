#!/usr/bin/env python3
"""Validate unified dataset"""

import pandas as pd

# Load the unified dataset
df = pd.read_csv('data/processed/master_unified_data.csv')

print('🔍 UNIFIED DATASET VALIDATION')
print('=' * 50)
print(f'Total samples: {len(df):,}')
print(f'Columns: {len(df.columns)}')

# Attack type distribution
print('\n📊 Attack Type Distribution:')
attack_dist = df['attack_type'].value_counts()
for attack, count in attack_dist.items():
    percentage = (count / len(df)) * 100
    print(f'{attack}: {count:,} ({percentage:.1f}%)')

# Check for missing values
print('\n🔍 Missing Values Check:')
critical_cols = ['duration', 'protocol', 'total_packets', 'total_bytes']
for col in critical_cols:
    missing = df[col].isna().sum()
    print(f'{col}: {missing} missing')

# SPLT features check
splt_cols = [col for col in df.columns if 'splt_' in col]
print(f'\n🔢 SPLT Features: {len(splt_cols)}')

# Sample data
print('\n📋 Sample Data:')
sample_cols = ['attack_type', 'label', 'protocol', 'duration', 'total_packets'] + splt_cols[:3]
print(df[sample_cols].head(3).to_string(index=False))

# Basic stats
print(f'\n📈 Basic Statistics:')
duration_mean = df['duration'].mean()
print(f'Duration - Mean: {duration_mean:.2f}')
protocol_dist = df['protocol'].value_counts().to_dict()
print(f'Protocol distribution: {protocol_dist}')

print('\n✅ Unified dataset validation complete!')
