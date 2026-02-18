#!/usr/bin/env python3
"""Feature analysis for the final dataset"""

import pandas as pd

# Load the final dataset
df = pd.read_csv('data/processed/final_balanced_240k.csv')

print('🔍 FEATURE ANALYSIS FOR TRAINING')
print('=' * 50)
print(f'Total features: {len(df.columns)}')

# Categorize features
splt_len_features = [col for col in df.columns if 'splt_len_' in col]
splt_iat_features = [col for col in df.columns if 'splt_iat_' in col]
basic_flow_features = ['duration', 'protocol', 'total_packets', 'total_bytes']
statistical_features = ['bytes_per_second', 'packets_per_second', 'min_packet_size', 'max_packet_size', 'mean_packet_size', 'std_packet_size']
metadata_features = ['flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'attack_type', 'label']

print(f'\n📊 FEATURE BREAKDOWN:')
print(f'SPLT Length features (packet sizes): {len(splt_len_features)}')
print(f'SPLT IAT features (inter-arrival times): {len(splt_iat_features)}')
print(f'Basic Flow features: {len([f for f in basic_flow_features if f in df.columns])}')
print(f'Statistical features: {len([f for f in statistical_features if f in df.columns])}')
print(f'Metadata features: {len([f for f in metadata_features if f in df.columns])}')

print(f'\n🔢 SPLT LENGTH FEATURES (First 10):')
for i, feat in enumerate(splt_len_features[:10]):
    print(f'{i+1:2d}. {feat}')

print(f'\n⏱️ SPLT IAT FEATURES (First 10):')
for i, feat in enumerate(splt_iat_features[:10]):
    print(f'{i+1:2d}. {feat}')

print(f'\n🌊 BASIC FLOW FEATURES:')
for i, feat in enumerate(basic_flow_features):
    if feat in df.columns:
        print(f'{i+1:2d}. {feat}')

print(f'\n📈 STATISTICAL FEATURES:')
for i, feat in enumerate(statistical_features):
    if feat in df.columns:
        print(f'{i+1:2d}. {feat}')

print(f'\n📋 SAMPLE VALUES:')
sample = df.iloc[0]
duration = sample.get('duration', 'N/A')
protocol = sample.get('protocol', 'N/A')
total_packets = sample.get('total_packets', 'N/A')
total_bytes = sample.get('total_bytes', 'N/A')
pps = sample.get('packets_per_second', 'N/A')
bps = sample.get('bytes_per_second', 'N/A')
splt_len_1 = sample.get('splt_len_1', 'N/A')
splt_iat_1 = sample.get('splt_iat_1', 'N/A')

print(f'Duration: {duration:.6f}s' if duration != 'N/A' else 'Duration: N/A')
print(f'Protocol: {protocol}')
print(f'Total Packets: {total_packets}')
print(f'Total Bytes: {total_bytes}')
print(f'Packets/sec: {pps:.2f}' if pps != 'N/A' else 'Packets/sec: N/A')
print(f'Bytes/sec: {bps:.2f}' if bps != 'N/A' else 'Bytes/sec: N/A')
print(f'SPLT Len 1: {splt_len_1}')
print(f'SPLT IAT 1: {splt_iat_1:.6f}s' if splt_iat_1 != 'N/A' else 'SPLT IAT 1: N/A')

print(f'\n🎯 FEATURE IMPORTANCE FOR MALICIOUS DETECTION:')
print('1. SPLT Lengths: Packet size patterns (attack signatures)')
print('2. SPLT IATs: Timing patterns (beaconing, burst attacks)')
print('3. Duration: Flow length (short bursts vs long sessions)')
print('4. Packets/sec: Attack intensity (DDoS flood vs normal)')
print('5. Bytes/sec: Bandwidth consumption patterns')
print('6. Protocol: Attack vectors (TCP/UDP specific attacks)')
