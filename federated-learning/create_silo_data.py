#!/usr/bin/env python3
"""
Create proper federated learning silos:
- Honey-Token Client: C2 attacks + normal traffic
- Enterprise Client: DDoS attacks + normal traffic  
- University Client: Mixed normal + some attacks for diversity
"""

import pandas as pd
import numpy as np
from pathlib import Path
import sys

# Add project root for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT))


def create_demo_processed_silos(df: pd.DataFrame) -> None:
    processed_dir = PROJECT_ROOT / "data" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    # Non-IID Distribution for Byzantine Defense Demo
    
    # Bank (Enterprise): 80% Benign + 20% DDoS (volumetric attacks)
    bank_normal = df[df["Attack_Type"] == "Normal"].sample(n=16000, random_state=42)
    bank_ddos = df[df["Attack_Type"] == "DDoS"].sample(n=4000, random_state=43)
    bank_df = pd.concat([bank_normal, bank_ddos], ignore_index=True)
    bank_df.to_csv(processed_dir / "federated_bank.csv", index=False)

    # Hospital (University): 50% Benign + 50% C2 Beaconing (stealthy/temporal)
    hospital_normal = df[df["Attack_Type"] == "Normal"].sample(n=10000, random_state=44)
    hospital_c2 = df[df["Attack_Type"] == "C2"].sample(n=10000, random_state=45)
    hospital_df = pd.concat([hospital_normal, hospital_c2], ignore_index=True)
    hospital_df.to_csv(processed_dir / "federated_hospital.csv", index=False)

    # Tech Hub (Datacenter): 70% Benign + 30% Mixed attacks
    tech_normal = df[df["Attack_Type"] == "Normal"].sample(n=14000, random_state=46)
    tech_attacks = df[df["Attack_Type"] != "Normal"].sample(n=6000, random_state=47)
    tech_df = pd.concat([tech_normal, tech_attacks], ignore_index=True)
    tech_df.to_csv(processed_dir / "federated_tech.csv", index=False)

    # Malicious Client: Hospital data with INVERTED labels (for poisoning test)
    malicious_df = hospital_df.copy()
    malicious_df["label"] = 1 - malicious_df["label"]  # Invert labels!
    malicious_df["Attack_Type"] = malicious_df["Attack_Type"].replace({
        "Normal": "MALICIOUS_NORMAL",
        "C2": "MALICIOUS_C2"
    })
    malicious_df.to_csv(processed_dir / "federated_malicious.csv", index=False)

    print(
        f"✅ Non-IID Federated Silos Created:\n"
        f"   - Bank (80% Normal + 20% DDoS): {len(bank_df)} samples\n"
        f"   - Hospital (50% Normal + 50% C2): {len(hospital_df)} samples\n"
        f"   - Tech Hub (70% Normal + 30% Mixed): {len(tech_df)} samples\n"
        f"   - Malicious (Inverted labels): {len(malicious_df)} samples"
    )

def create_federated_silos():
    """Create properly separated federated learning data silos"""
    
    print("🔄 Creating Federated Learning Silos...")
    
    # Load the main dataset
    data_path = PROJECT_ROOT / "data" / "processed" / "final_balanced_240k.csv"
    df = pd.read_csv(data_path)
    
    print(f"📊 Loaded dataset: {df.shape}")
    print(f"🎯 Attack types: {df['Attack_Type'].value_counts().to_dict()}")

    create_demo_processed_silos(df)
    
    # Create silos
    silos = {}
    
    # 1. Honey-Token Client (C2-focused)
    c2_data = df[df['Attack_Type'] == 'C2'].copy()
    normal_data_honey = df[df['Attack_Type'] == 'Normal'].sample(n=len(c2_data), random_state=42).copy()
    
    silos['honey_token'] = pd.concat([c2_data, normal_data_honey], ignore_index=True)
    silos['honey_token']['client_id'] = 'honey_token'
    
    # 2. Enterprise Client (DDoS-focused) 
    ddos_data = df[df['Attack_Type'] == 'DDoS'].copy()
    normal_data_enterprise = df[df['Attack_Type'] == 'Normal'].sample(n=len(ddos_data), random_state=43).copy()
    
    silos['enterprise'] = pd.concat([ddos_data, normal_data_enterprise], ignore_index=True)
    silos['enterprise']['client_id'] = 'enterprise'
    
    # 3. University Client (Mixed for diversity)
    # Sample from all attack types but smaller amounts
    c2_uni = df[df['Attack_Type'] == 'C2'].sample(n=10000, random_state=44).copy()
    ddos_uni = df[df['Attack_Type'] == 'DDoS'].sample(n=10000, random_state=45).copy()
    normal_uni = df[df['Attack_Type'] == 'Normal'].sample(n=20000, random_state=46).copy()
    
    silos['university'] = pd.concat([c2_uni, ddos_uni, normal_uni], ignore_index=True)
    silos['university']['client_id'] = 'university'
    
    # 4. Datacenter Client (Mostly normal with few attacks)
    normal_dc = df[df['Attack_Type'] == 'Normal'].sample(n=35000, random_state=47).copy()
    c2_dc = df[df['Attack_Type'] == 'C2'].sample(n=2500, random_state=48).copy()
    ddos_dc = df[df['Attack_Type'] == 'DDoS'].sample(n=2500, random_state=49).copy()
    
    silos['datacenter'] = pd.concat([normal_dc, c2_dc, ddos_dc], ignore_index=True)
    silos['datacenter']['client_id'] = 'datacenter'
    
    # Save silos
    output_dir = PROJECT_ROOT / "federated-learning" / "client" / "data"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for silo_name, silo_data in silos.items():
        # Convert to federated client format
        client_data = silo_data.copy()
        
        # Map Attack_Type to label (0=Normal, 1=Attack)
        client_data['label'] = (client_data['Attack_Type'] != 'Normal').astype(int)
        
        # Select relevant features (match existing client format)
        # Dynamically select feature columns (exclude metadata)
        exclude_cols = {'Attack_Type', 'label', 'flow_id', 'Label'}
        feature_cols = [col for col in client_data.columns if col not in exclude_cols]
        
        # Create client-specific CSV with all available features
        client_csv = client_data[feature_cols + ['label']].copy()
        
        # Generate flow IDs
        client_csv['flow_id'] = [f"{silo_name}_flow_{i}" for i in range(len(client_csv))]
        
        # Save
        output_file = output_dir / f"client_{silo_name}_data.csv"
        client_csv.to_csv(output_file, index=False)
        
        print(f"✅ Created {silo_name} silo: {len(client_csv)} samples")
        print(f"   - Attack distribution: {client_data['Attack_Type'].value_counts().to_dict()}")
        print(f"   - Label distribution: {client_csv['label'].value_counts().to_dict()}")
        print(f"   - Saved to: {output_file}")
        print()
    
    print("🎉 Federated learning silos created successfully!")
    
    # Create summary
    print("\n📋 Silo Summary:")
    print("-" * 60)
    for silo_name, silo_data in silos.items():
        total = len(silo_data)
        attacks = (silo_data['Attack_Type'] != 'Normal').sum()
        normal = (silo_data['Attack_Type'] == 'Normal').sum()
        
        print(f"{silo_name:12} | Total: {total:6} | Normal: {normal:5} | Attacks: {attacks:5}")
    
    print("-" * 60)
    print("🔐 Privacy: Raw data never leaves client premises")
    print("🧠 Learning: Only model weights are shared")
    print("🎯 Focus: Each client specializes in different attack patterns")

if __name__ == "__main__":
    create_federated_silos()
