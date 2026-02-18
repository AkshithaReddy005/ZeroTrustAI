#!/usr/bin/env python3
"""Quick data validation script"""

import pandas as pd
import numpy as np

# Load the balanced dataset
df = pd.read_csv('data/processed/balanced_80k_ddos_c2_splt.csv', low_memory=False)

print('🔍 BALANCED DATASET ANALYSIS')
print('=' * 50)
print(f'Total samples: {len(df):,}')
print(f'Columns: {len(df.columns)}')

# Attack type distribution
print('\n📊 Attack Type Distribution:')
attack_dist = df['Attack_Type'].value_counts()
for attack, count in attack_dist.items():
    percentage = (count / len(df)) * 100
    print(f'{attack}: {count:,} ({percentage:.1f}%)')

# Label distribution
print('\n🏷️ Label Distribution:')
label_dist = df['Label'].value_counts()
for label, count in label_dist.items():
    label_name = 'Malicious' if label == 1 else 'Normal'
    percentage = (count / len(df)) * 100
    print(f'{label_name} ({label}): {count:,} ({percentage:.1f}%)')

# SPLT features check
splt_cols = [col for col in df.columns if 'splt_' in col]
print(f'\n🔢 SPLT Features: {len(splt_cols)}')

# Check for missing values in SPLT
splt_missing = df[splt_cols].isna().any().any()
if splt_missing:
    missing_count = df[splt_cols].isna().any(axis=1).sum()
    print(f'⚠️ Rows with missing SPLT: {missing_count:,}')
else:
    print('✅ All SPLT features present')

# Sample data verification
print('\n📋 Sample Data (first 3 rows):')
sample_cols = ['Attack_Type', 'Label', 'protocol', 'duration'] + splt_cols[:3]
print(df[sample_cols].head(3).to_string(index=False))

# Basic statistics
print('\n📈 Basic Flow Statistics:')
flow_mean = df['duration'].mean()
flow_std = df['duration'].std()
print(f'Flow Duration - Mean: {flow_mean:.2f}, Std: {flow_std:.2f}')
protocol_dist = df['protocol'].value_counts().to_dict()
print(f'Protocol distribution: {protocol_dist}')

# Check data types
print('\n🔧 Data Types:')
dtypes = df[['Attack_Type', 'Label', 'protocol', 'duration']].dtypes
print(dtypes)

# Check for any obvious issues
print('\n⚠️ Data Quality Checks:')
zero_duration = (df['duration'] == 0).sum()
negative_duration = (df['duration'] < 0).sum()
missing_overall = df.isna().sum().sum()
print(f'Zero Flow Duration: {zero_duration}')
print(f'Negative Flow Duration: {negative_duration}')
print(f'Missing values overall: {missing_overall}')

print('\n✅ Data validation complete!')
