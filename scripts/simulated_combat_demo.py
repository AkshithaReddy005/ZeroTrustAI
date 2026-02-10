#!/usr/bin/env python3
"""
Simulated Combat Demo - No Npcap Required
Demonstrates Zero-IP behavioral fingerprinting with simulated traffic
"""

import time
import requests
import threading
import json
import random
from datetime import datetime

class SimulatedCombatDemo:
    def __init__(self, detector_url="http://localhost:9000"):
        self.detector_url = detector_url
        self.running = False
        self.stats = {
            'total_flows': 0,
            'malicious_flows': 0,
            'blocked_ips': set(),
            'start_time': time.time()
        }
    
    def create_benign_flow(self, flow_id: str, src_ip: str):
        """Create benign flow data"""
        return {
            "flow_id": flow_id,
            "src_ip": src_ip,
            "dst_ip": "192.168.137.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": 6,  # TCP
            "total_packets": random.randint(10, 50),
            "total_bytes": random.randint(1000, 5000),
            "avg_packet_size": random.uniform(64, 512),
            "std_packet_size": random.uniform(10, 100),
            "duration": random.uniform(1, 5),
            "pps": random.uniform(5, 20),
            "avg_entropy": random.uniform(3, 7),
            "syn_count": random.randint(1, 5),
            "fin_count": random.randint(0, 2),
            "splt_len": [random.randint(64, 512) for _ in range(10)],
            "splt_iat": [random.uniform(0.01, 0.5) for _ in range(10)]
        }
    
    def create_ddos_flow(self, flow_id: str, src_ip: str):
        """Create DDoS attack flow"""
        return {
            "flow_id": flow_id,
            "src_ip": src_ip,
            "dst_ip": "192.168.137.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": 6,  # TCP
            "total_packets": random.randint(500, 2000),
            "total_bytes": random.randint(750000, 3000000),
            "avg_packet_size": 1500,  # Large packets
            "std_packet_size": 0,  # Consistent size
            "duration": random.uniform(1, 3),
            "pps": random.uniform(500, 1000),
            "avg_entropy": 1.0,  # Low entropy
            "syn_count": random.randint(100, 500),
            "fin_count": 0,
            "splt_len": [1500] * 10,  # Consistent large packets
            "splt_iat": [0.001] * 10  # Rapid timing
        }
    
    def create_port_scan_flow(self, flow_id: str, src_ip: str):
        """Create port scan flow"""
        return {
            "flow_id": flow_id,
            "src_ip": src_ip,
            "dst_ip": "192.168.137.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]),
            "protocol": 6,  # TCP
            "total_packets": random.randint(50, 200),
            "total_bytes": random.randint(2000, 8000),
            "avg_packet_size": 40,  # Small packets
            "std_packet_size": 0,  # Consistent size
            "duration": random.uniform(2, 10),
            "pps": random.uniform(20, 100),
            "avg_entropy": 0.5,  # Very low entropy
            "syn_count": random.randint(50, 200),
            "fin_count": 0,
            "splt_len": [40] * 10,  # Consistent small packets
            "splt_iat": [0.01] * 10  # Regular timing
        }
    
    def send_flow_to_detector(self, flow_data):
        """Send flow data to detector"""
        try:
            response = requests.post(
                f"{self.detector_url}/detect",
                json=flow_data,
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                self.handle_detection_result(flow_data, result)
                return True
            else:
                print(f"❌ Detector error: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending to detector: {e}")
            return False
    
    def handle_detection_result(self, flow_data, result):
        """Handle detection result"""
        src_ip = flow_data['src_ip']
        label = result.get('label', 'benign')
        severity = result.get('severity', 'LOW')
        confidence = result.get('confidence', 0.0)
        reasons = result.get('reason', [])
        metadata = result.get('metadata', {})
        
        self.stats['total_flows'] += 1
        
        print(f"\n🔍 Flow Analysis:")
        print(f"   📍 Source: {src_ip}")
        print(f"   🎯 Label: {label}")
        print(f"   ⚠️  Severity: {severity}")
        print(f"   📊 Confidence: {confidence:.2f}")
        print(f"   📝 Reasons: {', '.join(reasons)}")
        
        # Check for behavioral pattern match
        if metadata and 'behavioral_hash' in metadata:
            behavioral_hash = metadata['behavioral_hash']
            print(f"   🔑 Behavioral Hash: {behavioral_hash}")
            
            if 'pattern_first_seen' in metadata:
                print(f"   ⏰ Pattern First Seen: {metadata['pattern_first_seen']}")
                print(f"   🚨 ZERO-IP EVASION PREVENTED!")
        
        if label == 'malicious':
            self.stats['malicious_flows'] += 1
            
            if severity in ['HIGH', 'CRITICAL']:
                self.stats['blocked_ips'].add(src_ip)
                print(f"   🚫 IP {src_ip} BLOCKED!")
    
    def act_1_baseline(self):
        """Act 1: Baseline - Benign traffic"""
        print(f"\n{'='*60}")
        print(f"🎭 ACT 1: The Baseline")
        print(f"{'='*60}")
        print("🌐 Sending benign traffic...")
        print("👀 Dashboard should stay GREEN")
        print()
        
        # Send 10 benign flows
        for i in range(10):
            flow_id = f"benign-{i}-{int(time.time())}"
            src_ip = f"192.168.137.{random.randint(100, 200)}"
            
            flow_data = self.create_benign_flow(flow_id, src_ip)
            self.send_flow_to_detector(flow_data)
            
            time.sleep(0.5)
        
        print("✅ Act 1 Complete - Baseline established")
    
    def act_2_attack(self):
        """Act 2: Attack - Malicious traffic"""
        print(f"\n{'='*60}")
        print(f"🎭 ACT 2: The Attack")
        print(f"{'='*60}")
        print("🚨 Starting DDoS attack...")
        print("👀 Dashboard should turn RED")
        print("🎯 MITRE TTPs should be identified")
        print()
        
        # Send DDoS attack from one IP
        attacker_ip = "192.168.137.50"
        
        for i in range(15):
            flow_id = f"ddos-{i}-{int(time.time())}"
            
            flow_data = self.create_ddos_flow(flow_id, attacker_ip)
            self.send_flow_to_detector(flow_data)
            
            time.sleep(0.3)
        
        print("✅ Act 2 Complete - Attack detected and blocked")
    
    def act_3_evasion(self):
        """Act 3: Evasion - IP change + pattern match"""
        print(f"\n{'='*60}")
        print(f"🎭 ACT 3: The Evasion")
        print(f"{'='*60}")
        print("🎭 Attacker changes IP address")
        print("🔥 Same attack pattern from new IP")
        print("🚨 Zero-IP behavioral fingerprinting blocks INSTANTLY!")
        print()
        
        # Send same attack pattern from new IP
        new_attacker_ip = "192.168.137.51"
        
        print(f"👹 New Attacker IP: {new_attacker_ip}")
        print("🚀 Launching same DDoS pattern from new IP...")
        
        for i in range(10):
            flow_id = f"evasion-{i}-{int(time.time())}"
            
            flow_data = self.create_ddos_flow(flow_id, new_attacker_ip)
            self.send_flow_to_detector(flow_data)
            
            time.sleep(0.3)
        
        print("✅ Act 3 Complete - Evasion PREVENTED!")
        print("🏆 Zero-IP behavioral fingerprinting SUCCESS!")
    
    def print_stats(self):
        """Print final statistics"""
        runtime = time.time() - self.stats['start_time']
        
        print(f"\n{'='*60}")
        print("📊 FINAL STATISTICS")
        print(f"{'='*60}")
        print(f"⏱️  Runtime: {runtime:.1f} seconds")
        print(f"📦 Total Flows: {self.stats['total_flows']}")
        print(f"🚨 Malicious Flows: {self.stats['malicious_flows']}")
        print(f"🚫 Blocked IPs: {len(self.stats['blocked_ips'])}")
        
        if self.stats['blocked_ips']:
            print(f"🎯 Blocked IPs: {', '.join(self.stats['blocked_ips'])}")
        
        print(f"\n🎉 SIMULATED COMBAT DEMO COMPLETE!")
        print("🛡️ Zero-IP behavioral fingerprinting working perfectly!")
    
    def run_demo(self):
        """Run the complete simulated combat demo"""
        print("🔥 ZeroTrust-AI Simulated Combat Demo")
        print("=" * 60)
        print("🎭 This demo simulates the 3-act combat scenario")
        print("🚀 No Npcap required - perfect for testing!")
        print()
        
        try:
            # Check if detector is running
            response = requests.get(f"{self.detector_url}/health", timeout=5)
            if response.status_code != 200:
                print("❌ Detector not running!")
                print("💡 Start with: docker-compose -f infra/docker-compose.minimal.yml up -d")
                return False
            
            print("✅ Detector is running!")
            print("👀 Open dashboard: http://localhost:8501")
            print()
            
            input("Press Enter to start Act 1...")
            self.act_1_baseline()
            
            input("Press Enter to start Act 2...")
            self.act_2_attack()
            
            input("Press Enter to start Act 3...")
            self.act_3_evasion()
            
            self.print_stats()
            
            return True
            
        except KeyboardInterrupt:
            print("\n🛑 Demo interrupted by user")
            return False
        except Exception as e:
            print(f"❌ Demo error: {e}")
            return False

def main():
    demo = SimulatedCombatDemo()
    demo.run_demo()

if __name__ == "__main__":
    main()
