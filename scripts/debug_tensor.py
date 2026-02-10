#!/usr/bin/env python3
"""
Debug tensor creation for behavioral fingerprinting
"""

import torch
import numpy as np

def debug_tensor_creation():
    """Debug the tensor creation process"""
    print("🔍 Debug Tensor Creation")
    print("=" * 40)
    
    # Test DDoS pattern
    splt_len = [1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500]
    splt_iat = [0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001]
    
    print(f"📊 Original splt_len: {splt_len}")
    print(f"📊 Original splt_iat: {splt_iat}")
    
    # Method 1: Original approach
    try:
        combined_data = splt_len + splt_iat
        tensor1 = torch.tensor([combined_data], dtype=torch.float32).reshape(1, 2, len(splt_len))
        print(f"✅ Method 1 - Tensor shape: {tensor1.shape}")
        print(f"📊 First 5 packet lengths: {tensor1[0, 0, :5].tolist()}")
        
        # Test fingerprint creation
        packet_lengths = tensor1[0, :5].cpu().numpy() if tensor1.dim() >= 2 else tensor1[:5].cpu().numpy()
        print(f"🔍 Extracted packet lengths: {packet_lengths}")
        
    except Exception as e:
        print(f"❌ Method 1 failed: {e}")
    
    # Method 2: Fixed approach
    try:
        combined_len = splt_len[:10]
        combined_iat = splt_iat[:10]
        
        tensor2 = torch.tensor([combined_len, combined_iat], dtype=torch.float32).unsqueeze(0)
        print(f"✅ Method 2 - Tensor shape: {tensor2.shape}")
        print(f"📊 First 5 packet lengths: {tensor2[0, 0, :5].tolist()}")
        
        # Test fingerprint creation
        packet_lengths = tensor2[0, :5].cpu().numpy() if tensor2.dim() >= 2 else tensor2[:5].cpu().numpy()
        print(f"🔍 Extracted packet lengths: {packet_lengths}")
        
    except Exception as e:
        print(f"❌ Method 2 failed: {e}")
    
    # Method 3: Direct approach
    try:
        tensor3 = torch.tensor([[splt_len, splt_iat]], dtype=torch.float32)
        print(f"✅ Method 3 - Tensor shape: {tensor3.shape}")
        print(f"📊 First 5 packet lengths: {tensor3[0, 0, :5].tolist()}")
        
        # Test fingerprint creation
        packet_lengths = tensor3[0, 0, :5].cpu().numpy()
        print(f"🔍 Extracted packet lengths: {packet_lengths}")
        
        # Create fingerprint
        fingerprint_parts = []
        for length in packet_lengths:
            signed_length = int(length)
            fingerprint_parts.append(f"{signed_length:+d}")
        
        behavioral_hash = "_".join(fingerprint_parts)
        print(f"🔑 Behavioral Hash: {behavioral_hash}")
        
    except Exception as e:
        print(f"❌ Method 3 failed: {e}")

if __name__ == "__main__":
    debug_tensor_creation()
