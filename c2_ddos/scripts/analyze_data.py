#!/usr/bin/env python3
"""
Utility functions for C2 vs DDoS detection
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def analyze_dataset(data_path):
    """Analyze dataset composition and patterns"""
    logger.info(f"📊 Analyzing dataset: {data_path}")
    
    df = pd.read_csv(data_path)
    
    print(f"📊 Dataset Overview")
    print(f"Total samples: {len(df):,}")
    print(f"Features: {len(df.columns)}")
    
    # Attack type distribution
    print(f"\n🎯 Attack Type Distribution:")
    attack_dist = df['attack_type'].value_counts()
    for attack_type, count in attack_dist.items():
        percentage = (count / len(df)) * 100
        print(f"{attack_type}: {count:,} ({percentage:.1f}%)")
    
    # Label distribution
    print(f"\n🏷️ Binary Label Distribution:")
    label_dist = df['label'].value_counts()
    for label, count in label_dist.items():
        label_name = 'Malicious' if label == 1 else 'Normal'
        percentage = (count / len(df)) * 100
        print(f"{label_name} (Label {label}): {count:,} ({percentage:.1f}%)")
    
    # Feature analysis
    splt_len_features = [col for col in df.columns if 'splt_len_' in col]
    splt_iat_features = [col for col in df.columns if 'splt_iat_' in col]
    basic_features = ['duration', 'protocol', 'total_packets', 'total_bytes']
    
    print(f"\n🔢 Feature Breakdown:")
    print(f"SPLT Length features: {len(splt_len_features)}")
    print(f"SPLT IAT features: {len(splt_iat_features)}")
    print(f"Basic features: {len([f for f in basic_features if f in df.columns])}")
    
    return df

def compare_attack_patterns(df):
    """Compare patterns between attack types"""
    logger.info("🔍 Comparing attack patterns")
    
    # Separate by attack type
    c2_data = df[df['attack_type'] == 'C2']
    ddos_data = df[df['attack_type'] == 'DDoS']
    normal_data = df[df['attack_type'] == 'Normal']
    
    # Key metrics comparison
    metrics = ['duration', 'total_packets', 'total_bytes']
    
    print(f"\n📈 Attack Pattern Comparison")
    print("=" * 60)
    
    for metric in metrics:
        if metric in df.columns:
            print(f"\n🔍 {metric.upper()}")
            for attack_type, data in [('C2', c2_data), ('DDoS', ddos_data), ('Normal', normal_data)]:
                if len(data) > 0:
                    mean_val = data[metric].mean()
                    std_val = data[metric].std()
                    print(f"   {attack_type:8}: Mean={mean_val:.2f}, Std={std_val:.2f}")
    
    # Protocol distribution
    print(f"\n🌐 Protocol Distribution")
    print("=" * 40)
    for attack_type, data in [('C2', c2_data), ('DDoS', ddos_data), ('Normal', normal_data)]:
        if len(data) > 0 and 'protocol' in data.columns:
            protocol_counts = data['protocol'].value_counts()
            total = len(data)
            print(f"\n{attack_type}:")
            for protocol, count in protocol_counts.items():
                protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(int(protocol), f'Proto{protocol}')
                percentage = (count / total) * 100
                print(f"   {protocol_name}: {count:,} ({percentage:.1f}%)")

def visualize_patterns(df, output_dir="notebooks"):
    """Create visualizations of attack patterns"""
    logger.info("📊 Creating visualizations")
    
    Path(output_dir).mkdir(exist_ok=True)
    
    # Set style
    plt.style.use('seaborn-v0_8')
    
    # 1. Attack type distribution
    plt.figure(figsize=(10, 6))
    attack_counts = df['attack_type'].value_counts()
    plt.pie(attack_counts.values, labels=attack_counts.index, autopct='%1.1f%%')
    plt.title('Attack Type Distribution')
    plt.savefig(Path(output_dir) / "attack_distribution.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    # 2. Duration comparison
    if 'duration' in df.columns:
        plt.figure(figsize=(12, 6))
        for attack_type in df['attack_type'].unique():
            data = df[df['attack_type'] == attack_type]['duration']
            # Log scale for better visualization
            data_log = np.log10(data[data > 0] + 1)
            plt.hist(data_log, alpha=0.6, label=attack_type, bins=50)
        
        plt.xlabel('Duration (log10 seconds)')
        plt.ylabel('Frequency')
        plt.title('Duration Distribution by Attack Type')
        plt.legend()
        plt.savefig(Path(output_dir) / "duration_comparison.png", dpi=300, bbox_inches='tight')
        plt.close()
    
    # 3. Packet count comparison
    if 'total_packets' in df.columns:
        plt.figure(figsize=(12, 6))
        for attack_type in df['attack_type'].unique():
            data = df[df['attack_type'] == attack_type]['total_packets']
            data_log = np.log10(data[data > 0] + 1)
            plt.hist(data_log, alpha=0.6, label=attack_type, bins=50)
        
        plt.xlabel('Total Packets (log10)')
        plt.ylabel('Frequency')
        plt.title('Packet Count Distribution by Attack Type')
        plt.legend()
        plt.savefig(Path(output_dir) / "packet_comparison.png", dpi=300, bbox_inches='tight')
        plt.close()
    
    # 4. SPLT feature heatmap
    splt_features = [col for col in df.columns if 'splt_' in col][:10]  # First 10 for readability
    if splt_features:
        plt.figure(figsize=(15, 8))
        
        # Calculate correlation matrix for each attack type
        for i, attack_type in enumerate(df['attack_type'].unique()):
            data = df[df['attack_type'] == attack_type][splt_features]
            corr_matrix = data.corr()
            
            plt.subplot(1, 3, i+1)
            sns.heatmap(corr_matrix, annot=False, cmap='coolwarm', center=0)
            plt.title(f'{attack_type} SPLT Correlations')
        
        plt.tight_layout()
        plt.savefig(Path(output_dir) / "splt_correlations.png", dpi=300, bbox_inches='tight')
        plt.close()
    
    logger.info(f"✅ Visualizations saved to {output_dir}")

def generate_report(df, output_dir="notebooks"):
    """Generate analysis report"""
    logger.info("📋 Generating analysis report")
    
    Path(output_dir).mkdir(exist_ok=True)
    
    report_path = Path(output_dir) / "analysis_report.md"
    
    with open(report_path, 'w') as f:
        f.write("# C2 vs DDoS Detection Analysis Report\n\n")
        f.write(f"Generated: {pd.Timestamp.now()}\n\n")
        
        # Dataset overview
        f.write("## Dataset Overview\n\n")
        f.write(f"- Total samples: {len(df):,}\n")
        f.write(f"- Features: {len(df.columns)}\n")
        f.write(f"- Attack types: {', '.join(df['attack_type'].unique())}\n\n")
        
        # Attack distribution
        f.write("## Attack Distribution\n\n")
        attack_dist = df['attack_type'].value_counts()
        for attack_type, count in attack_dist.items():
            percentage = (count / len(df)) * 100
            f.write(f"- {attack_type}: {count:,} ({percentage:.1f}%)\n")
        f.write("\n")
        
        # Key insights
        f.write("## Key Insights\n\n")
        
        # Duration analysis
        if 'duration' in df.columns:
            c2_duration = df[df['attack_type'] == 'C2']['duration'].median()
            ddos_duration = df[df['attack_type'] == 'DDoS']['duration'].median()
            normal_duration = df[df['attack_type'] == 'Normal']['duration'].median()
            
            f.write(f"### Duration Analysis\n")
            f.write(f"- C2 median duration: {c2_duration:.2f}s\n")
            f.write(f"- DDoS median duration: {ddos_duration:.2f}s\n")
            f.write(f"- Normal median duration: {normal_duration:.2f}s\n\n")
        
        # Packet analysis
        if 'total_packets' in df.columns:
            c2_packets = df[df['attack_type'] == 'C2']['total_packets'].median()
            ddos_packets = df[df['attack_type'] == 'DDoS']['total_packets'].median()
            normal_packets = df[df['attack_type'] == 'Normal']['total_packets'].median()
            
            f.write(f"### Packet Analysis\n")
            f.write(f"- C2 median packets: {c2_packets:.0f}\n")
            f.write(f"- DDoS median packets: {ddos_packets:.0f}\n")
            f.write(f"- Normal median packets: {normal_packets:.0f}\n\n")
        
        # Protocol analysis
        if 'protocol' in df.columns:
            f.write("### Protocol Analysis\n")
            for attack_type in df['attack_type'].unique():
                data = df[df['attack_type'] == attack_type]
                protocol_counts = data['protocol'].value_counts()
                f.write(f"\n{attack_type} protocols:\n")
                for protocol, count in protocol_counts.items():
                    protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(int(protocol), f'Proto{protocol}')
                    percentage = (count / len(data)) * 100
                    f.write(f"- {protocol_name}: {percentage:.1f}%\n")
    
    logger.info(f"✅ Report saved to {report_path}")

def main():
    """Main function"""
    data_path = "data/processed/final_balanced_240k.csv"
    
    # Analyze dataset
    df = analyze_dataset(data_path)
    
    # Compare patterns
    compare_attack_patterns(df)
    
    # Create visualizations
    visualize_patterns(df)
    
    # Generate report
    generate_report(df)
    
    logger.info("🎉 Analysis completed!")

if __name__ == "__main__":
    main()
