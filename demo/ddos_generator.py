#!/usr/bin/env python3
"""
Real DDoS Traffic Generator - Sends actual DDoS attack patterns
"""
import socket
import json
import time
import random
import threading

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

def generate_ddos_flow():
    """Generate real DDoS attack flow"""
    return {
        "src_ip": "192.168.0.177",
        "dst_ip": "192.168.0.1",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "protocol": 6,
        "process": "ddos.exe",
        "duration": 0.01,  # Very short
        "total_packets": 2000,  # High volume
        "total_bytes": 80000,  # Small packets
        "splt_len": [random.randint(40, 60) for _ in range(20)],  # Very small, consistent
        "splt_iat": [random.uniform(0.01, 1) for _ in range(20)],  # Extremely fast
        "attack_type": "DDoS"
    }

def generate_c2_flow():
    """Generate real C2 beacon flow"""
    beacon_size = 400
    beacon_interval = 8000  # 8 seconds
    
    return {
        "src_ip": "192.168.0.177",
        "dst_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "src_port": random.randint(49152, 65535),
        "dst_port": 443,
        "protocol": 6,
        "process": "svchost.exe",
        "duration": 60,
        "total_packets": 8,
        "total_bytes": 3200,
        "splt_len": [beacon_size + random.randint(-2, 2) for _ in range(20)],  # Extremely consistent
        "splt_iat": [beacon_interval + random.uniform(-50, 50) for _ in range(20)],  # Very regular
        "attack_type": "C2"
    }

def ddos_attack():
    """Continuous DDoS attack generator"""
    count = 0
    while True:
        flow = generate_ddos_flow()
        if send_flow(flow):
            count += 1
            print(f"[DDOS-{count:04d}] 🔴 DDoS attack sent")
        time.sleep(0.1)  # Very fast

def c2_attack():
    """Continuous C2 beacon generator"""
    count = 0
    while True:
        flow = generate_c2_flow()
        if send_flow(flow):
            count += 1
            print(f"[C2-{count:04d}] 🔴 C2 beacon sent")
        time.sleep(8)  # Regular beacon interval

def main():
    print("=" * 60)
    print("REAL ATTACK GENERATOR")
    print("=" * 60)
    print(f"Target: {RECEIVER_IP}:{PORT}")
    print()
    print("🔴 Starting DDoS attacks - high volume, small packets, fast bursts")
    print("🔴 Starting C2 beacons - regular intervals, consistent size")
    print("Press Ctrl+C to stop")
    print()
    
    # Start both attacks in parallel
    ddos_thread = threading.Thread(target=ddos_attack, daemon=True)
    c2_thread = threading.Thread(target=c2_attack, daemon=True)
    
    ddos_thread.start()
    c2_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n✅ Attack generator stopped")

if __name__ == "__main__":
    main()
