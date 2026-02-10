#!/usr/bin/env python3
"""
API Attack Script for ZeroTrust-AI Demo
Sends attack data directly to detector API
"""

import time
import requests
import json
import random
import argparse
import numpy as np

class APIAttacker:
    def __init__(self, target_ip, attacker_ip="192.168.1.7"):
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip
        self.api_url = f"http://{target_ip}:9000/detect"
        
    def create_flow_features(self, attack_type="benign"):
        """Create flow features for detection"""
        
        if attack_type == "benign":
            # Normal traffic patterns (more realistic)
            packets = random.randint(20, 100)
            total_bytes = packets * random.randint(64, 512)  # Realistic packet sizes
            duration = random.uniform(5.0, 30.0)  # Longer duration
            
            return {
                "flow_id": f"flow_{int(time.time())}_{random.randint(1000, 9999)}",
                "total_packets": packets,
                "total_bytes": total_bytes,
                "avg_packet_size": total_bytes / packets,
                "std_packet_size": random.uniform(10, 50),  # Lower variation
                "duration": duration,
                "pps": packets / duration,
                "avg_entropy": random.uniform(4.0, 7.0),  # Higher entropy for normal traffic
                "syn_count": random.randint(0, 1),  # Fewer SYN packets
                "fin_count": random.randint(0, 1),
                "splt_len": [random.randint(64, 800) for _ in range(5)],  # Variable packet sizes
                "splt_iat": [random.uniform(0.01, 0.5) for _ in range(5)]  # Variable timing
            }
        
        elif attack_type == "ddos":
            # DDoS attack patterns - large packets, high frequency
            packets = 1000  # High packet count
            total_bytes = 1500000  # Large total bytes (1500 bytes * 1000)
            duration = 1.0  # Very short duration
            
            return {
                "flow_id": f"ddos_{int(time.time())}_{random.randint(1000, 9999)}",
                "total_packets": packets,
                "total_bytes": total_bytes,
                "avg_packet_size": total_bytes / packets,  # 1500 bytes
                "std_packet_size": 50.0,  # Consistent large packets
                "duration": duration,
                "pps": packets / duration,  # 1000 packets per second
                "avg_entropy": random.uniform(1.0, 2.0),  # Low entropy (repeated packets)
                "syn_count": packets,  # All SYN packets
                "fin_count": 0,
                "splt_len": [1500, 1500, 1500, 1500, 1500],  # Consistent large packets
                "splt_iat": [0.001, 0.001, 0.001, 0.001, 0.001]  # Very fast
            }
        
        elif attack_type == "scan":
            # Port scan patterns
            packets = 20
            total_bytes = 1280  # 64 bytes * 20 packets
            duration = 2.0
            
            return {
                "flow_id": f"scan_{int(time.time())}_{random.randint(1000, 9999)}",
                "total_packets": packets,
                "total_bytes": total_bytes,
                "avg_packet_size": total_bytes / packets,
                "std_packet_size": 10.0,  # Consistent small packets
                "duration": duration,
                "pps": packets / duration,
                "avg_entropy": random.uniform(4.0, 7.0),
                "syn_count": packets,  # All SYN packets
                "fin_count": 0,
                "splt_len": [64, 64, 64, 64, 64],  # Small packets
                "splt_iat": [0.1, 0.1, 0.1, 0.1, 0.1]  # Slower rate
            }
    
    def send_attack(self, attack_type, duration=30, rate=5):
        """Send attack data to detector API"""
        print(f"🚨 Starting {attack_type.upper()} Attack")
        print(f"🎯 Target: {self.api_url}")
        print(f"⏱️  Duration: {duration}s")
        print(f"📊 Rate: {rate} requests/second")
        
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Create flow features
                flow_data = self.create_flow_features(attack_type)
                
                # Send to detector API
                response = requests.post(
                    self.api_url,
                    json=flow_data,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                request_count += 1
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("label") == "malicious":
                        print(f"🚨 MALICIOUS DETECTED! Confidence: {result.get('confidence', 0):.2f}")
                        if "behavioral_hash" in result:
                            print(f"🔑 Behavioral Hash: {result['behavioral_hash']}")
                else:
                    print(f"❌ API Error: {response.status_code}")
                
                # Control rate
                time.sleep(1.0 / rate)
                
                if request_count % 10 == 0:
                    print(f"📦 Sent {request_count} requests...")
                    
            except Exception as e:
                print(f"❌ Error sending request: {e}")
                time.sleep(1)
        
        print(f"✅ Attack completed: {request_count} requests sent")
    
    def benign_traffic(self, duration=30, rate=2):
        """Send benign traffic"""
        self.send_attack("benign", duration, rate)
    
    def ddos_attack(self, duration=30, rate=10):
        """Send DDoS attack"""
        self.send_attack("ddos", duration, rate)
    
    def port_scan(self, duration=20, rate=5):
        """Send port scan attack"""
        self.send_attack("scan", duration, rate)

def main():
    parser = argparse.ArgumentParser(description="ZeroTrust-AI API Attacker")
    parser.add_argument("--target", "-t", required=True, help="Target IP address")
    parser.add_argument("--attacker", "-a", default="10.161.123.32", help="Attacker IP")
    parser.add_argument("--attack", choices=["ddos", "benign", "scan"], 
                       required=True, help="Attack type")
    parser.add_argument("--duration", "-d", default=30, help="Attack duration in seconds")
    parser.add_argument("--rate", "-r", default=5, help="Requests per second")
    
    args = parser.parse_args()
    
    attacker = APIAttacker(args.target, args.attacker)
    
    print(f"🎭 ZeroTrust-AI API Attacker")
    print(f"🎯 Target: {args.target}")
    print(f"👹 Attacker: {args.attacker}")
    print(f"⚔️  Attack Type: {args.attack}")
    print(f"⏱️  Duration: {args.duration}s")
    print("=" * 50)
    
    try:
        if args.attack == "ddos":
            attacker.ddos_attack(args.duration, args.rate)
        elif args.attack == "benign":
            attacker.benign_traffic(args.duration, args.rate)
        elif args.attack == "scan":
            attacker.port_scan(args.duration, args.rate)
        
    except KeyboardInterrupt:
        print("\n🛑 Attack stopped by user")

if __name__ == "__main__":
    main()
