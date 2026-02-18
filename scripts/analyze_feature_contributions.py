#!/usr/bin/env python3
"""Analyze feature contributions for C2 vs DDoS detection"""

import pandas as pd
import numpy as np
from scipy import stats

# Load the final dataset
df = pd.read_csv('data/processed/final_balanced_240k.csv')

print('🔍 FEATURE CONTRIBUTION ANALYSIS')
print('=' * 60)

# Separate by attack type
c2_data = df[df['Attack_Type'] == 'C2']
ddos_data = df[df['Attack_Type'] == 'DDoS']
normal_data = df[df['Attack_Type'] == 'Normal']

print(f'C2 samples: {len(c2_data):,}')
print(f'DDoS samples: {len(ddos_data):,}')
print(f'Normal samples: {len(normal_data):,}')

# Key features to analyze
key_features = [
    'duration', 'protocol', 'total_packets', 'total_bytes', 'std_packet_size',
    'splt_len_1', 'splt_len_2', 'splt_len_3', 'splt_len_4', 'splt_len_5',
    'splt_iat_1', 'splt_iat_2', 'splt_iat_3', 'splt_iat_4', 'splt_iat_5'
]

print(f'\n📊 FEATURE ANALYSIS BY ATTACK TYPE')
print('=' * 60)

for feature in key_features:
    if feature in df.columns:
        c2_vals = c2_data[feature].dropna()
        ddos_vals = ddos_data[feature].dropna()
        normal_vals = normal_data[feature].dropna()
        
        if len(c2_vals) > 0 and len(ddos_vals) > 0 and len(normal_vals) > 0:
            c2_mean = c2_vals.mean()
            ddos_mean = ddos_vals.mean()
            normal_mean = normal_vals.mean()
            
            c2_std = c2_vals.std()
            ddos_std = ddos_vals.std()
            normal_std = normal_vals.std()
            
            print(f'\n🔍 {feature.upper()}')
            print(f'   C2:      Mean={c2_mean:.2f}, Std={c2_std:.2f}')
            print(f'   DDoS:    Mean={ddos_mean:.2f}, Std={ddos_std:.2f}')
            print(f'   Normal:  Mean={normal_mean:.2f}, Std={normal_std:.2f}')
            
            # Statistical significance
            if feature not in ['protocol']:  # Skip categorical for t-test
                t_stat_c2_normal, p_c2_normal = stats.ttest_ind(c2_vals, normal_vals)
                t_stat_ddos_normal, p_ddos_normal = stats.ttest_ind(ddos_vals, normal_vals)
                
                print(f'   Significance: C2 vs Normal p={p_c2_normal:.6f}, DDoS vs Normal p={p_ddos_normal:.6f}')

# Protocol analysis
print(f'\n🔍 PROTOCOL DISTRIBUTION')
print('=' * 40)
for attack_type, data in [('C2', c2_data), ('DDoS', ddos_data), ('Normal', normal_data)]:
    protocol_counts = data['protocol'].value_counts()
    total = len(data)
    print(f'\n{attack_type}:')
    for protocol, count in protocol_counts.items():
        protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(int(protocol), f'Proto{protocol}')
        percentage = (count / total) * 100
        print(f'   {protocol_name}: {count:,} ({percentage:.1f}%)')

# SPLT pattern analysis
print(f'\n🎯 SPLT PATTERN ANALYSIS')
print('=' * 40)

# C2 beaconing patterns (regular IATs)
c2_iat_std = c2_data[[f'splt_iat_{i}' for i in range(1, 6)]].std().mean()
ddos_iat_std = ddos_data[[f'splt_iat_{i}' for i in range(1, 6)]].std().mean()
normal_iat_std = normal_data[[f'splt_iat_{i}' for i in range(1, 6)]].std().mean()

print(f'IAT Regularity (lower = more regular):')
print(f'   C2:      {c2_iat_std:.2f} (beaconing = regular)')
print(f'   DDoS:    {ddos_iat_std:.2f} (bursts = irregular)')
print(f'   Normal:  {normal_iat_std:.2f}')

# Packet size consistency
c2_len_std = c2_data[[f'splt_len_{i}' for i in range(1, 6)]].std().mean()
ddos_len_std = ddos_data[[f'splt_len_{i}' for i in range(1, 6)]].std().mean()
normal_len_std = normal_data[[f'splt_len_{i}' for i in range(1, 6)]].std().mean()

print(f'\nPacket Size Consistency (lower = more consistent):')
print(f'   C2:      {c2_len_std:.2f} (command packets = consistent)')
print(f'   DDoS:    {ddos_len_std:.2f} (flood = variable)')
print(f'   Normal:  {normal_len_std:.2f}')

print(f'\n🎯 KEY DETECTION INSIGHTS')
print('=' * 40)
print('1. C2 DETECTION:')
print('   - Regular IAT patterns (beaconing)')
print('   - Consistent packet sizes (commands)')
print('   - Longer duration (persistent sessions)')
print('   - TCP-dominated (reliable C2 channels)')

print('\n2. DDoS DETECTION:')
print('   - High packet counts (flood attacks)')
print('   - Variable IATs (burst patterns)')
print('   - Short duration (quick attacks)')
print('   - Mixed protocols (UDP/TCP floods)')

print('\n3. NORMAL TRAFFIC:')
print('   - Moderate packet counts')
print('   - Variable patterns (diverse applications)')
print('   - Mixed durations')
print('   - Protocol diversity')
