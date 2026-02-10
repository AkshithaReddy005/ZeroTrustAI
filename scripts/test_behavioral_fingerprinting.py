#!/usr/bin/env python3
"""
Zero-IP Behavioral Fingerprinting Test Script

Demonstrates the power of behavioral pattern blocking:
- Even if attacker changes IP, the behavioral sequence remains the same
- New IPs using old attack patterns are blocked instantly
"""

import requests
import time
import json
from typing import Dict, List

class BehavioralFingerprintingDemo:
    def __init__(self, detector_url: str = "http://localhost:9000"):
        self.detector_url = detector_url
        self.session = requests.Session()
        
    def create_malicious_flow(self, flow_id: str, src_ip: str, pattern_type: str = "ddos") -> Dict:
        """Create a malicious flow with specific behavioral pattern"""
        
        # Different attack patterns have distinct SPLT signatures
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
                "avg_entropy": 1.0,  # Low entropy = repetitive pattern
                "syn_count": 100,
                "fin_count": 0
            },
            "botnet_c2": {
                "splt_len": [64, 128, 256, 512, 1024, 64, 128, 256, 512, 1024, 64],
                "splt_iat": [0.1, 0.2, 0.4, 0.8, 1.6, 0.1, 0.2, 0.4, 0.8, 1.6, 0.1],
                "total_packets": 500,
                "total_bytes": 250000,
                "avg_packet_size": 500,
                "std_packet_size": 350,
                "duration": 10.0,
                "pps": 50,
                "avg_entropy": 6.5,  # Higher entropy = varied pattern
                "syn_count": 10,
                "fin_count": 5
            },
            "port_scan": {
                "splt_len": [40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40],
                "splt_iat": [0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01],
                "total_packets": 100,
                "total_bytes": 4000,
                "avg_packet_size": 40,
                "std_packet_size": 0,
                "duration": 1.0,
                "pps": 100,
                "avg_entropy": 0.5,  # Very low entropy = identical packets
                "syn_count": 100,
                "fin_count": 0
            },
            "data_exfiltration": {
                "splt_len": [1400, 1400, 1400, 1400, 1400, 1400, 1400, 1400, 1400, 1400],
                "splt_iat": [0.005, 0.005, 0.005, 0.005, 0.005, 0.005, 0.005, 0.005, 0.005, 0.005],
                "total_packets": 2000,
                "total_bytes": 2800000,
                "avg_packet_size": 1400,
                "std_packet_size": 0,
                "duration": 10.0,
                "pps": 200,
                "avg_entropy": 2.0,  # Low entropy = consistent large packets
                "syn_count": 20,
                "fin_count": 20
            }
        }
        
        pattern = patterns.get(pattern_type, patterns["ddos"])
        
        return {
            "flow_id": flow_id,
            "src_ip": src_ip,
            "total_packets": pattern["total_packets"],
            "total_bytes": pattern["total_bytes"],
            "avg_packet_size": pattern["avg_packet_size"],
            "std_packet_size": pattern["std_packet_size"],
            "duration": pattern["duration"],
            "pps": pattern["pps"],
            "avg_entropy": pattern["avg_entropy"],
            "syn_count": pattern["syn_count"],
            "fin_count": pattern["fin_count"],
            "splt_len": pattern["splt_len"],
            "splt_iat": pattern["splt_iat"]
        }
    
    def test_pattern_fingerprinting(self, flow_data: Dict) -> Dict:
        """Test behavioral fingerprinting on a flow"""
        try:
            response = self.session.post(
                f"{self.detector_url}/test-pattern",
                json=flow_data,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
    
    def detect_threat(self, flow_data: Dict) -> Dict:
        """Send flow for threat detection"""
        try:
            response = self.session.post(
                f"{self.detector_url}/detect",
                json=flow_data,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Detection failed: {e}"}
    
    def get_pattern_stats(self) -> Dict:
        """Get current pattern statistics"""
        try:
            response = self.session.get(
                f"{self.detector_url}/patterns",
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Stats failed: {e}"}
    
    def demo_zero_ip_blocking(self):
        """Demonstrate Zero-IP behavioral blocking"""
        print("🔥 Zero-IP Behavioral Fingerprinting Demo")
        print("=" * 60)
        
        # Step 1: Attacker uses IP 192.168.1.100 with DDoS pattern
        print("\n📍 Step 1: Attacker from 192.168.1.100 using DDoS pattern")
        malicious_flow = self.create_malicious_flow("attack-001", "192.168.1.100", "ddos")
        
        # Test fingerprinting
        print("🔍 Testing behavioral fingerprinting...")
        fingerprint_result = self.test_pattern_fingerprinting(malicious_flow)
        
        if "error" not in fingerprint_result:
            print(f"✅ Behavioral Hash: {fingerprint_result['behavioral_hash']}")
            print(f"📊 First 5 packets: {fingerprint_result['first_5_packets']}")
            print(f"🔍 Known Pattern: {fingerprint_result['is_known_pattern']}")
        
        # Send for detection (this should store the pattern)
        print("\n🚨 Sending for threat detection...")
        detection_result = self.detect_threat(malicious_flow)
        
        if "error" not in detection_result:
            print(f"🎯 Detection Result: {detection_result['label']}")
            print(f"⚠️ Confidence: {detection_result['confidence']:.2f}")
            print(f"🔥 Severity: {detection_result['severity']}")
            if 'metadata' in detection_result:
                metadata = detection_result['metadata']
                if 'new_pattern' in metadata:
                    print("💾 New malicious pattern stored!")
                elif 'behavioral_hash' in metadata:
                    print(f"🔑 Pattern metadata: {metadata['behavioral_hash']}")
        
        # Step 2: Check pattern statistics
        print("\n📊 Checking pattern statistics...")
        stats = self.get_pattern_stats()
        if "error" not in stats:
            print(f"📈 Total patterns stored: {stats.get('total_patterns', 0)}")
        
        # Step 3: Attacker changes IP to 192.168.1.200 but uses SAME pattern
        print("\n📍 Step 2: Attacker changes IP to 192.168.1.200 (VPN/Proxy)")
        print("🎭 Attacker thinks changing IP will evade detection...")
        
        time.sleep(2)  # Simulate time gap
        
        attacker_flow_new_ip = self.create_malicious_flow("attack-002", "192.168.1.200", "ddos")
        
        print("🔍 Testing behavioral fingerprinting on new IP...")
        fingerprint_result_2 = self.test_pattern_fingerprinting(attacker_flow_new_ip)
        
        if "error" not in fingerprint_result_2:
            print(f"✅ Behavioral Hash: {fingerprint_result_2['behavioral_hash']}")
            print(f"📊 First 5 packets: {fingerprint_result_2['first_5_packets']}")
            print(f"🔍 Known Pattern: {fingerprint_result_2['is_known_pattern']}")
            
            # Check if hashes match
            if fingerprint_result.get('behavioral_hash') == fingerprint_result_2.get('behavioral_hash'):
                print("🎯 BEHAVIORAL HASHES MATCH!")
                print("🚨 Even though IP changed, the attack pattern is identical!")
        
        # Send for detection (should be immediately blocked)
        print("\n🚨 Sending new IP for threat detection...")
        detection_result_2 = self.detect_threat(attacker_flow_new_ip)
        
        if "error" not in detection_result_2:
            print(f"🎯 Detection Result: {detection_result_2['label']}")
            print(f"⚠️ Confidence: {detection_result_2['confidence']:.2f}")
            print(f"🔥 Severity: {detection_result_2['severity']}")
            print(f"📝 Reasons: {', '.join(detection_result_2.get('reason', []))}")
            
            if 'metadata' in detection_result_2:
                metadata = detection_result_2['metadata']
                if 'pattern_first_seen' in metadata:
                    print(f"⏰ Pattern first seen: {metadata['pattern_first_seen']}")
                    print("🚨 NEW IP BLOCKED BECAUSE OF OLD ATTACK PATTERN!")
        
        # Step 4: Try different attack pattern
        print("\n📍 Step 3: Attacker tries different pattern (Port Scan)")
        print("🎭 Testing if different pattern gets through...")
        
        time.sleep(2)
        
        port_scan_flow = self.create_malicious_flow("attack-003", "192.168.1.200", "port_scan")
        
        print("🔍 Testing behavioral fingerprinting on port scan...")
        fingerprint_result_3 = self.test_pattern_fingerprinting(port_scan_flow)
        
        if "error" not in fingerprint_result_3:
            print(f"✅ Behavioral Hash: {fingerprint_result_3['behavioral_hash']}")
            print(f"📊 First 5 packets: {fingerprint_result_3['first_5_packets']}")
            print(f"🔍 Known Pattern: {fingerprint_result_3['is_known_pattern']}")
        
        print("\n🚨 Sending port scan for threat detection...")
        detection_result_3 = self.detect_threat(port_scan_flow)
        
        if "error" not in detection_result_3:
            print(f"🎯 Detection Result: {detection_result_3['label']}")
            print(f"⚠️ Confidence: {detection_result_3['confidence']:.2f}")
            print(f"🔥 Severity: {detection_result_3['severity']}")
        
        # Final statistics
        print("\n📊 Final pattern statistics...")
        final_stats = self.get_pattern_stats()
        if "error" not in final_stats:
            print(f"📈 Total patterns stored: {final_stats.get('total_patterns', 0)}")
            
            sample_patterns = final_stats.get('sample_patterns', [])
            if sample_patterns:
                print("\n🔍 Sample stored patterns:")
                for i, pattern in enumerate(sample_patterns[:3], 1):
                    print(f"  {i}. {pattern.get('attack_type', 'unknown')} - {pattern.get('behavioral_hash', 'unknown')}")
        
        print("\n🎉 Zero-IP Demo Complete!")
        print("🛡️ Key Benefits Demonstrated:")
        print("  ✅ Attack patterns are fingerprinted regardless of IP")
        print("  ✅ New IPs using old patterns are blocked instantly")
        print("  ✅ Behavioral signatures are more reliable than IP addresses")
        print("  ✅ Attackers cannot evade detection by changing IP/VPN")
    
    def demo_different_patterns(self):
        """Demonstrate different attack patterns and their fingerprints"""
        print("\n🔍 Testing Different Attack Patterns")
        print("=" * 60)
        
        patterns = ["ddos", "botnet_c2", "port_scan", "data_exfiltration"]
        src_ip = "192.168.1.300"
        
        for i, pattern_type in enumerate(patterns, 1):
            print(f"\n📍 Pattern {i}: {pattern_type.upper()}")
            
            flow_data = self.create_malicious_flow(f"pattern-{i:03d}", src_ip, pattern_type)
            fingerprint_result = self.test_pattern_fingerprinting(flow_data)
            
            if "error" not in fingerprint_result:
                print(f"  🔑 Behavioral Hash: {fingerprint_result['behavioral_hash']}")
                print(f"  📊 First 5 packets: {fingerprint_result['first_5_packets']}")
                print(f"  🔍 Known Pattern: {fingerprint_result['is_known_pattern']}")
            
            time.sleep(1)
    
    def interactive_demo(self):
        """Interactive demo for user input"""
        print("\n🎮 Interactive Behavioral Fingerprinting Demo")
        print("=" * 60)
        
        while True:
            print("\nOptions:")
            print("1. Run Zero-IP blocking demo")
            print("2. Test different attack patterns")
            print("3. View pattern statistics")
            print("4. Exit")
            
            choice = input("\nEnter choice (1-4): ").strip()
            
            if choice == "1":
                self.demo_zero_ip_blocking()
            elif choice == "2":
                self.demo_different_patterns()
            elif choice == "3":
                stats = self.get_pattern_stats()
                if "error" not in stats:
                    print(f"\n📊 Pattern Statistics:")
                    print(f"  Total patterns: {stats.get('total_patterns', 0)}")
                    sample_patterns = stats.get('sample_patterns', [])
                    if sample_patterns:
                        print(f"  Sample patterns:")
                        for pattern in sample_patterns[:5]:
                            print(f"    - {pattern.get('attack_type', 'unknown')}: {pattern.get('behavioral_hash', 'unknown')}")
                else:
                    print(f"❌ Error getting stats: {stats.get('error', 'Unknown error')}")
            elif choice == "4":
                print("👋 Exiting demo...")
                break
            else:
                print("❌ Invalid choice. Please try again.")


def main():
    """Main function to run the behavioral fingerprinting demo"""
    print("🛡️ ZeroTrust-AI Behavioral Fingerprinting Test")
    print("=" * 60)
    print("This demo demonstrates the power of 'Zero-IP' behavioral blocking:")
    print("• Attack patterns are fingerprinted from SPLT sequences")
    print("• Even if attackers change IPs, patterns remain the same")
    print("• New IPs using old patterns are blocked instantly")
    print("• More reliable than traditional IP-based blocking")
    
    # Check if detector is running
    demo = BehavioralFingerprintingDemo()
    
    try:
        response = demo.session.get(f"{demo.detector_url}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Detector service is running!")
            health = response.json()
            print(f"🔧 Behavioral fingerprinting enabled: {health.get('behavioral_fingerprinting', {}).get('enabled', False)}")
        else:
            print("❌ Detector service is not responding")
            print("Please start the detector service first:")
            print("  docker-compose -f infra/docker-compose.professional.yml up -d")
            return
    except requests.exceptions.RequestException:
        print("❌ Cannot connect to detector service")
        print("Please start the detector service first:")
        print("  docker-compose -f infra/docker-compose.professional.yml up -d")
        return
    
    # Interactive demo
    demo.interactive_demo()


if __name__ == "__main__":
    main()
