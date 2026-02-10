#!/usr/bin/env python3
"""
Zero-IP Behavioral Fingerprinting Live Demo
Simulates the complete detection pipeline with Redis integration
"""

import redis
import json
import time
import torch
import numpy as np
from typing import Dict, List, Tuple

class ZeroIPDemo:
    def __init__(self):
        # Connect to Redis
        try:
            self.redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
            self.redis_client.ping()
            print("✅ Connected to Redis")
        except Exception as e:
            print(f"❌ Redis connection failed: {e}")
            self.redis_client = None
    
    def create_behavioral_fingerprint(self, splt_tensor: torch.Tensor) -> str:
        """Create behavioral fingerprint from SPLT tensor"""
        try:
            if splt_tensor is None or splt_tensor.numel() == 0:
                return "unknown_pattern"
            
            # Extract first 5 packet lengths from the first dimension (packet lengths)
            # Tensor shape should be [1, 2, 10] where dimension 0 = packet_lengths, 1 = inter_arrival_times
            packet_lengths = splt_tensor[0, 0, :5].cpu().numpy()  # First 5 packet lengths
            
            # Ensure we have exactly 5 values
            if len(packet_lengths) < 5:
                packet_lengths = np.pad(packet_lengths, (0, 5 - len(packet_lengths)), 'constant')
            
            # Create behavioral fingerprint string
            fingerprint_parts = []
            for length in packet_lengths:
                signed_length = int(length)
                fingerprint_parts.append(f"{signed_length:+d}")
            
            behavioral_hash = "_".join(fingerprint_parts)
            return behavioral_hash
            
        except Exception as e:
            return f"error_pattern_{hash(str(splt_tensor)) % 10000}"
    
    def check_behavioral_pattern(self, behavioral_hash: str) -> Tuple[bool, str]:
        """Check if behavioral pattern exists in Redis"""
        if self.redis_client is None:
            return False, "redis_unavailable"
        
        try:
            pattern_info = self.redis_client.get(f"pattern:{behavioral_hash}")
            
            if pattern_info:
                return True, pattern_info
            else:
                return False, "unknown_pattern"
                
        except Exception as e:
            return False, f"error_checking_pattern: {e}"
    
    def store_malicious_pattern(self, behavioral_hash: str, attack_type: str, confidence: float, flow_id: str) -> bool:
        """Store malicious behavioral pattern in Redis"""
        if self.redis_client is None:
            return False
        
        try:
            pattern_metadata = {
                "attack_type": attack_type,
                "confidence": float(confidence),
                "flow_id": flow_id,
                "first_seen": time.time(),
                "pattern_hash": behavioral_hash
            }
            
            # Store pattern with 1-hour expiry using SETEX
            metadata_json = json.dumps(pattern_metadata)
            success = self.redis_client.setex(
                f"pattern:{behavioral_hash}", 
                3600,  # 1 hour TTL
                metadata_json
            )
            
            # Also store in pattern index for analytics
            self.redis_client.sadd("pattern_index", behavioral_hash)
            self.redis_client.expire("pattern_index", 86400)  # 24 hours for index
            
            return bool(success)
            
        except Exception as e:
            print(f"❌ Error storing pattern: {e}")
            return False
    
    def simulate_detection(self, flow_data: Dict) -> Dict:
        """Simulate the complete detection pipeline"""
        print(f"\n🔍 Analyzing flow: {flow_data['flow_id']}")
        print(f"📍 Source IP: {flow_data['src_ip']}")
        
        # Create SPLT tensor
        splt_len = flow_data.get('splt_len', [])
        splt_iat = flow_data.get('splt_iat', [])
        
        if len(splt_len) < 5 or len(splt_iat) < 5:
            print("❌ Insufficient SPLT data")
            return {"error": "Insufficient SPLT data"}
        
        # Create tensor (packet_lengths, inter_arrival_times)
        # Ensure we have exactly 10 values for proper tensor creation
        combined_len = splt_len[:10]  # Take first 10 packet lengths
        combined_iat = splt_iat[:10]  # Take first 10 inter-arrival times
        
        # Pad if needed
        while len(combined_len) < 10:
            combined_len.append(0)
        while len(combined_iat) < 10:
            combined_iat.append(0)
        
        # Create tensor: [1, 2, 10] where 2 = [packet_lengths, inter_arrival_times]
        splt_tensor = torch.tensor([combined_len, combined_iat], dtype=torch.float32).unsqueeze(0)
        
        # Create behavioral fingerprint
        behavioral_hash = self.create_behavioral_fingerprint(splt_tensor)
        print(f"🔑 Behavioral Hash: {behavioral_hash}")
        
        # Check if pattern exists
        is_known_pattern, pattern_info = self.check_behavioral_pattern(behavioral_hash)
        
        # Simulate AI detection
        confidence = self.simulate_ai_detection(flow_data)
        label = "malicious" if confidence >= 0.6 else "benign"
        
        print(f"🤖 AI Detection: {label} (confidence: {confidence:.2f})")
        
        # Apply Zero-IP logic
        if is_known_pattern:
            print("🚨 KNOWN MALICIOUS PATTERN DETECTED!")
            print("⚡ Instant blocking triggered!")
            score = 1.0
            severity = "CRITICAL"
            reasons = ["known_malicious_pattern"]
            
            # Get pattern details
            try:
                pattern_details = json.loads(pattern_info)
                pattern_metadata = {
                    "behavioral_hash": behavioral_hash,
                    "pattern_first_seen": pattern_details.get("first_seen"),
                    "original_attack_type": pattern_details.get("attack_type"),
                    "pattern_confidence": pattern_details.get("confidence")
                }
                print(f"📊 Pattern first seen: {pattern_details.get('first_seen')}")
                print(f"🎯 Original attack type: {pattern_details.get('attack_type')}")
            except:
                pattern_metadata = {"behavioral_hash": behavioral_hash, "pattern_info": pattern_info}
        
        elif label == "malicious" and confidence >= 0.7:
            print("💾 New malicious pattern detected and stored!")
            success = self.store_malicious_pattern(behavioral_hash, "unknown_attack", confidence, flow_data['flow_id'])
            if success:
                print("✅ Pattern stored successfully")
            else:
                print("❌ Failed to store pattern")
            
            score = confidence
            severity = "HIGH"
            reasons = ["new_malicious_pattern_stored"]
            pattern_metadata = {"behavioral_hash": behavioral_hash, "new_pattern": True}
        
        else:
            print("✅ Benign or low-confidence flow")
            score = confidence
            severity = "LOW"
            reasons = ["low_risk"]
            pattern_metadata = {"behavioral_hash": behavioral_hash, "pattern_status": "benign_or_low_confidence"}
        
        return {
            "flow_id": flow_data['flow_id'],
            "label": label,
            "confidence": score,
            "severity": severity,
            "reasons": reasons,
            "metadata": pattern_metadata,
            "behavioral_hash": behavioral_hash
        }
    
    def simulate_ai_detection(self, flow_data: Dict) -> float:
        """Simulate AI detection confidence"""
        # Simple heuristic based on flow characteristics
        confidence = 0.1  # Base confidence
        
        # High packet rate increases suspicion
        if flow_data.get('pps', 0) > 500:
            confidence += 0.3
        
        # Low entropy (repetitive) increases suspicion
        if flow_data.get('avg_entropy', 0) < 3.0:
            confidence += 0.2
        
        # High SYN count increases suspicion
        if flow_data.get('syn_count', 0) > 20:
            confidence += 0.2
        
        # Large packet size with low variance increases suspicion
        if flow_data.get('avg_packet_size', 0) > 1000 and flow_data.get('std_packet_size', 0) < 50:
            confidence += 0.2
        
        return min(confidence, 0.95)  # Cap at 95%
    
    def create_attack_flow(self, flow_id: str, src_ip: str, attack_type: str) -> Dict:
        """Create a malicious flow with specific attack pattern"""
        patterns = {
            "ddos": {
                "splt_len": [1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500],
                "splt_iat": [0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001, 0.001],
                "total_packets": 1000,
                "total_bytes": 1500000,
                "avg_packet_size": 1500,
                "std_packet_size": 0,
                "duration": 1.0,
                "pps": 1000,
                "avg_entropy": 1.0,
                "syn_count": 100,
                "fin_count": 0
            },
            "botnet": {
                "splt_len": [64, 128, 256, 512, 1024, 64, 128, 256, 512, 1024],
                "splt_iat": [0.1, 0.2, 0.4, 0.8, 1.6, 0.1, 0.2, 0.4, 0.8, 1.6],
                "total_packets": 500,
                "total_bytes": 250000,
                "avg_packet_size": 500,
                "std_packet_size": 350,
                "duration": 10.0,
                "pps": 50,
                "avg_entropy": 6.5,
                "syn_count": 10,
                "fin_count": 5
            },
            "port_scan": {
                "splt_len": [40, 40, 40, 40, 40, 40, 40, 40, 40, 40],
                "splt_iat": [0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01],
                "total_packets": 100,
                "total_bytes": 4000,
                "avg_packet_size": 40,
                "std_packet_size": 0,
                "duration": 1.0,
                "pps": 100,
                "avg_entropy": 0.5,
                "syn_count": 100,
                "fin_count": 0
            }
        }
        
        pattern = patterns.get(attack_type, patterns["ddos"])
        
        return {
            "flow_id": flow_id,
            "src_ip": src_ip,
            **pattern
        }
    
    def run_demo(self):
        """Run the complete Zero-IP demo"""
        print("🔥 Zero-IP Behavioral Fingerprinting Live Demo")
        print("=" * 60)
        
        if not self.redis_client:
            print("❌ Redis not available. Please start Redis first.")
            return
        
        # Step 1: Attacker from 192.168.1.100 uses DDoS pattern
        print("\n📍 Step 1: Attacker from 192.168.1.100 using DDoS pattern")
        print("-" * 50)
        
        attack_flow = self.create_attack_flow("attack-001", "192.168.1.100", "ddos")
        result1 = self.simulate_detection(attack_flow)
        
        # Step 2: Attacker changes IP to 192.168.1.200 but uses SAME pattern
        print("\n📍 Step 2: Attacker changes IP to 192.168.1.200 (VPN/Proxy)")
        print("🎭 Attacker thinks changing IP will evade detection...")
        print("-" * 50)
        
        time.sleep(2)  # Simulate time gap
        
        attacker_flow_new_ip = self.create_attack_flow("attack-002", "192.168.1.200", "ddos")
        result2 = self.simulate_detection(attacker_flow_new_ip)
        
        # Step 3: Try different attack pattern
        print("\n📍 Step 3: Attacker tries different pattern (Port Scan)")
        print("🎭 Testing if different pattern gets through...")
        print("-" * 50)
        
        time.sleep(2)
        
        port_scan_flow = self.create_attack_flow("attack-003", "192.168.1.200", "port_scan")
        result3 = self.simulate_detection(port_scan_flow)
        
        # Summary
        print("\n📊 Demo Summary")
        print("=" * 60)
        
        print(f"🎯 Attack 1 (192.168.1.100): {result1['label']} - {result1['severity']}")
        print(f"🎯 Attack 2 (192.168.1.200): {result2['label']} - {result2['severity']}")
        print(f"🎯 Attack 3 (Port Scan): {result3['label']} - {result3['severity']}")
        
        print(f"\n🔑 Behavioral Hashes:")
        print(f"  Attack 1: {result1['behavioral_hash']}")
        print(f"  Attack 2: {result2['behavioral_hash']}")
        print(f"  Attack 3: {result3['behavioral_hash']}")
        
        # Check pattern statistics
        pattern_count = self.redis_client.scard("pattern_index")
        print(f"\n📈 Total patterns stored: {pattern_count}")
        
        # Show stored patterns
        if pattern_count > 0:
            print("\n🔍 Stored Patterns:")
            patterns = list(self.redis_client.smembers("pattern_index"))[:5]
            for pattern in patterns:
                pattern_info = self.redis_client.get(f"pattern:{pattern}")
                if pattern_info:
                    try:
                        details = json.loads(pattern_info)
                        print(f"  🔑 {pattern} -> {details.get('attack_type', 'unknown')}")
                    except:
                        print(f"  🔑 {pattern} -> unknown")
        
        print("\n🎉 Zero-IP Demo Complete!")
        print("🛡️ Key Benefits Demonstrated:")
        print("  ✅ Attack patterns are fingerprinted regardless of IP")
        print("  ✅ New IPs using old patterns are blocked instantly")
        print("  ✅ Behavioral signatures are more reliable than IP addresses")
        print("  ✅ Attackers cannot evade detection by changing IP/VPN")

def main():
    """Main function"""
    print("🛡️ ZeroTrust-AI Zero-IP Behavioral Fingerprinting")
    print("=" * 60)
    print("This demo demonstrates the power of behavioral pattern blocking")
    print("without requiring IP addresses.")
    
    demo = ZeroIPDemo()
    demo.run_demo()

if __name__ == "__main__":
    main()
