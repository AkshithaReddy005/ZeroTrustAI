#!/usr/bin/env python3
"""
Attack Simulator for ZeroTrust-AI Combat Demo
Creates realistic attack traffic for testing the live sniffer
"""

import time
import socket
import threading
import random
import argparse
from scapy.all import IP, TCP, UDP, ICMP, send, sr1
import sys

class AttackSimulator:
    def __init__(self, target_ip, target_port=80, attacker_ip="192.168.137.50"):
        self.target_ip = target_ip
        self.target_port = target_port
        self.attacker_ip = attacker_ip
        self.running = False
        
    def ddos_attack(self, duration=30, packets_per_second=100):
        """Simulate DDoS attack with large packets"""
        print(f"🚨 Starting DDoS Attack: {packets_per_second} packets/sec for {duration}s")
        print(f"🎯 Target: {self.target_ip}:{self.target_port}")
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration and self.running:
            try:
                # Create large packets (1500 bytes) for DDoS
                packet = IP(dst=self.target_ip, src=self.attacker_ip) / \
                         TCP(dport=self.target_port, sport=random.randint(1024, 65535)) / \
                         b"A" * 1400  # Large payload
                
                send(packet, verbose=0)
                packet_count += 1
                
                # Control packet rate
                time.sleep(1.0 / packets_per_second)
                
                if packet_count % 100 == 0:
                    print(f"📦 Sent {packet_count} packets...")
                    
            except Exception as e:
                print(f"❌ Error sending packet: {e}")
                break
        
        print(f"✅ DDoS attack completed: {packet_count} packets sent")
    
    def port_scan_attack(self, duration=20):
        """Simulate port scan attack"""
        print(f"🔍 Starting Port Scan Attack for {duration}s")
        print(f"🎯 Target: {self.target_ip}")
        
        start_time = time.time()
        ports_scanned = 0
        
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        while time.time() - start_time < duration and self.running:
            try:
                for port in common_ports:
                    if not self.running:
                        break
                    
                    # Create SYN packet for port scanning
                    packet = IP(dst=self.target_ip, src=self.attacker_ip) / \
                             TCP(dport=port, sport=random.randint(1024, 65535), flags="S")
                    
                    send(packet, verbose=0)
                    ports_scanned += 1
                    
                    # Small delay between scans
                    time.sleep(0.1)
                    
                    if ports_scanned % 50 == 0:
                        print(f"🔍 Scanned {ports_scanned} ports...")
                
                # Add delay between full scans
                time.sleep(2)
                
            except Exception as e:
                print(f"❌ Error scanning port: {e}")
                break
        
        print(f"✅ Port scan completed: {ports_scanned} ports scanned")
    
    def botnet_c2_attack(self, duration=25):
        """Simulate botnet C2 communication"""
        print(f"🤖 Starting Botnet C2 Attack for {duration}s")
        print(f"🎯 Target: {self.target_ip}")
        
        start_time = time.time()
        packet_count = 0
        
        # Variable packet sizes for C2 communication
        c2_patterns = [
            (64, 0.1),   # Small packets, frequent
            (128, 0.2),  # Medium packets, less frequent
            (256, 0.4),  # Larger packets, even less frequent
            (512, 0.8),  # Large packets, rare
            (1024, 1.6)  # Very large packets, very rare
        ]
        
        while time.time() - start_time < duration and self.running:
            try:
                # Random C2 pattern
                size, delay = random.choice(c2_patterns)
                
                packet = IP(dst=self.target_ip, src=self.attacker_ip) / \
                         TCP(dport=self.target_port, sport=random.randint(1024, 65535)) / \
                         b"C2_DATA" * (size // 8)
                
                send(packet, verbose=0)
                packet_count += 1
                
                time.sleep(delay)
                
                if packet_count % 50 == 0:
                    print(f"🤖 Sent {packet_count} C2 packets...")
                    
            except Exception as e:
                print(f"❌ Error sending C2 packet: {e}")
                break
        
        print(f"✅ Botnet C2 attack completed: {packet_count} packets sent")
    
    def data_exfiltration_attack(self, duration=30):
        """Simulate data exfiltration attack"""
        print(f"💾 Starting Data Exfiltration Attack for {duration}s")
        print(f"🎯 Target: {self.target_ip}")
        
        start_time = time.time()
        packet_count = 0
        data_exfiltrated = 0
        
        while time.time() - start_time < duration and self.running:
            try:
                # Create packets with data payload
                data_chunk = f"STOLEN_DATA_{packet_count:06d}" * 50  # ~800 bytes
                packet = IP(dst=self.target_ip, src=self.attacker_ip) / \
                         TCP(dport=self.target_port, sport=random.randint(1024, 65535)) / \
                         data_chunk.encode()
                
                send(packet, verbose=0)
                packet_count += 1
                data_exfiltrated += len(data_chunk)
                
                # Steady exfiltration rate
                time.sleep(0.05)
                
                if packet_count % 100 == 0:
                    print(f"💾 Exfiltrated {data_exfiltrated} bytes in {packet_count} packets...")
                    
            except Exception as e:
                print(f"❌ Error exfiltrating data: {e}")
                break
        
        print(f"✅ Data exfiltration completed: {data_exfiltrated} bytes in {packet_count} packets")
    
    def benign_traffic(self, duration=30):
        """Simulate benign traffic"""
        print(f"🌐 Starting Benign Traffic for {duration}s")
        print(f"🎯 Target: {self.target_ip}")
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration and self.running:
            try:
                # Normal web browsing patterns
                packet_sizes = [64, 128, 256, 512, 1024, 1500]
                size = random.choice(packet_sizes)
                
                packet = IP(dst=self.target_ip, src=self.attacker_ip) / \
                         TCP(dport=self.target_port, sport=random.randint(1024, 65535)) / \
                         b"HTTP_REQUEST" * (size // 13)
                
                send(packet, verbose=0)
                packet_count += 1
                
                # Random delays like real browsing
                time.sleep(random.uniform(0.1, 2.0))
                
                if packet_count % 20 == 0:
                    print(f"🌐 Sent {packet_count} benign packets...")
                    
            except Exception as e:
                print(f"❌ Error sending benign packet: {e}")
                break
        
        print(f"✅ Benign traffic completed: {packet_count} packets sent")
    
    def stop(self):
        """Stop the attack simulator"""
        self.running = False

def main():
    parser = argparse.ArgumentParser(description="ZeroTrust-AI Attack Simulator")
    parser.add_argument("--target", "-t", required=True, help="Target IP address")
    parser.add_argument("--port", "-p", default=80, help="Target port")
    parser.add_argument("--attacker", "-a", default="192.168.137.50", help="Attacker IP")
    parser.add_argument("--attack", choices=["ddos", "scan", "botnet", "exfil", "benign"], 
                       required=True, help="Attack type")
    parser.add_argument("--duration", "-d", default=30, help="Attack duration in seconds")
    parser.add_argument("--rate", "-r", default=100, help="Packets per second for DDoS")
    
    args = parser.parse_args()
    
    simulator = AttackSimulator(args.target, args.port, args.attacker)
    simulator.running = True
    
    print(f"🎭 ZeroTrust-AI Attack Simulator")
    print(f"🎯 Target: {args.target}:{args.port}")
    print(f"👹 Attacker: {args.attacker}")
    print(f"⚔️  Attack Type: {args.attack}")
    print(f"⏱️  Duration: {args.duration}s")
    print("=" * 50)
    
    try:
        if args.attack == "ddos":
            simulator.ddos_attack(args.duration, args.rate)
        elif args.attack == "scan":
            simulator.port_scan_attack(args.duration)
        elif args.attack == "botnet":
            simulator.botnet_c2_attack(args.duration)
        elif args.attack == "exfil":
            simulator.data_exfiltration_attack(args.duration)
        elif args.attack == "benign":
            simulator.benign_traffic(args.duration)
        
    except KeyboardInterrupt:
        print("\n🛑 Attack stopped by user")
        simulator.stop()

if __name__ == "__main__":
    main()
