#!/usr/bin/env python3
"""
Attack Simulator - Generates malicious-looking traffic patterns
"""
import socket
import json
import time
import random

RECEIVER_IP = "192.168.0.154"  # Laptop B
PORT = 9999

def send_flow(flow_data):
    """Send a single flow to the receiver"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((RECEIVER_IP, PORT))
        s.send(json.dumps(flow_data).encode())
        s.close()
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def generate_ddos_attack():
    """Generate DDoS attack pattern - high volume, small packets, fast bursts"""
    return {
        "src_ip": f"192.168.0.{random.randint(100, 200)}",
        "dst_ip": "192.168.0.1",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "protocol": 6,
        "process": "malware.exe",
        "duration": 0.05,  # Very short duration
        "total_packets": 1500,  # High packet count
        "total_bytes": 60000,  # Small packets
        "splt_len": [random.randint(40, 60) for _ in range(20)],  # Small, consistent
        "splt_iat": [random.uniform(0.1, 2) for _ in range(20)],  # Fast bursts
        "attack_type": "DDoS"
    }

def generate_c2_beacon():
    """Generate C2 beacon pattern - regular intervals, consistent size"""
    beacon_size = 350
    beacon_interval = 10000  # Exactly 10 seconds
    
    return {
        "src_ip": "192.168.0.177",
        "dst_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "src_port": random.randint(49152, 65535),
        "dst_port": 443,
        "protocol": 6,
        "process": "svchost.exe",
        "duration": 120,
        "total_packets": 12,
        "total_bytes": 4200,
        "splt_len": [beacon_size + random.randint(-5, 5) for _ in range(20)],  # Very consistent
        "splt_iat": [beacon_interval + random.uniform(-100, 100) for _ in range(20)],  # Regular intervals
        "attack_type": "C2"
    }

def generate_normal_traffic():
    """Generate normal traffic for comparison"""
    return {
        "src_ip": "192.168.0.177",
        "dst_ip": random.choice(["8.8.8.8", "1.1.1.1", "142.250.185.46"]),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([80, 443]),
        "protocol": 6,
        "process": "chrome.exe",
        "duration": random.uniform(5, 30),
        "total_packets": random.randint(20, 100),
        "total_bytes": random.randint(5000, 50000),
        "splt_len": [random.randint(100, 1400) for _ in range(20)],
        "splt_iat": [random.uniform(50, 800) for _ in range(20)],
        "attack_type": "Normal"
    }

def main():
    print("=" * 60)
    print("ATTACK SIMULATOR")
    print("=" * 60)
    print(f"Target: {RECEIVER_IP}:{PORT}")
    print()
    print("Generating attack patterns...")
    print("🔴 DDoS attacks - high volume, small packets")
    print("🔴 C2 beacons - regular intervals, consistent size")
    print("🟢 Normal traffic - for comparison")
    print()
    
    count = 0
    
    try:
        while True:
            # Send mix of traffic
            if count % 5 == 0:
                # DDoS attack
                flow = generate_ddos_attack()
                if send_flow(flow):
                    count += 1
                    print(f"[{count:04d}] 🔴 DDoS attack sent")
                time.sleep(1)
                
            elif count % 7 == 0:
                # C2 beacon
                flow = generate_c2_beacon()
                if send_flow(flow):
                    count += 1
                    print(f"[{count:04d}] 🔴 C2 beacon sent")
                time.sleep(1)
                
            else:
                # Normal traffic
                flow = generate_normal_traffic()
                if send_flow(flow):
                    count += 1
                    print(f"[{count:04d}] 🟢 Normal traffic sent")
                time.sleep(2)
                
    except KeyboardInterrupt:
        print(f"\n✅ Sent {count} flows")
        print("Simulator stopped.")

if __name__ == "__main__":
    main()
