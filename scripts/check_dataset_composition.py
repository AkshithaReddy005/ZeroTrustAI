#!/usr/bin/env python3
"""Check final dataset composition"""

import pandas as pd

# Load the final dataset
df = pd.read_csv('data/processed/final_balanced_240k.csv')

print('📊 FINAL DATASET COMPOSITION')
print('=' * 50)
print(f'Total samples: {len(df):,}')

# Attack type distribution
attack_dist = df['Attack_Type'].value_counts()
print(f'\n🎯 Attack Type Distribution:')
for attack_type, count in attack_dist.items():
    percentage = (count / len(df)) * 100
    print(f'{attack_type}: {count:,} ({percentage:.1f}%)')

# Label distribution (binary classification)
label_dist = df['Label'].value_counts()
print(f'\n🏷️ Binary Label Distribution:')
for label, count in label_dist.items():
    label_name = 'Malicious' if label == 1 else 'Normal'
    percentage = (count / len(df)) * 100
    print(f'{label_name} (Label {label}): {count:,} ({percentage:.1f}%)')

# Check if we have all three types
has_c2 = 'C2' in attack_dist
has_ddos = 'DDoS' in attack_dist  
has_normal = 'Normal' in attack_dist

print(f'\n✅ Dataset Completeness:')
print(f'C2 Traffic: {"✅ Included" if has_c2 else "❌ Missing"}')
print(f'DDoS Traffic: {"✅ Included" if has_ddos else "❌ Missing"}')
print(f'Normal Traffic: {"✅ Included" if has_normal else "❌ Missing"}')

print(f'\n🎯 Training Objective:')
print('Binary Classification: Normal (0) vs Malicious (1)')
print('Malicious includes: C2 + DDoS attacks')
