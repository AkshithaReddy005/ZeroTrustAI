#!/usr/bin/env python3
"""
ZeroTrust-AI Real-Time Demo
Shows simulated threats in the web interface for testing
"""

import requests
import time
import random
from datetime import datetime

def generate_realistic_threat():
    """Generate realistic threat events for demonstration"""
    attack_types = ['botnet', 'data_exfiltration', 'port_scanning', 'malware']
    severities = ['high', 'medium', 'low']
    
    # Random IP addresses
    source_ip = f"192.168.1.{random.randint(100, 200)}"
    dest_ip = f"10.0.0.{random.randint(1, 50)}"
    
    # Generate threat
    threat = {
        "flow_id": f"{source_ip}:{random.randint(1000, 9999)}→{dest_ip}:{random.choice([80, 443, 22, 3389])}/TCP",
        "label": "malicious" if random.random() > 0.3 else "benign",
        "confidence": round(random.uniform(0.6, 0.99), 2),
        "severity": random.choice(severities),
        "reason": random.choice([
            ["tcn_malicious", "ae_anomalous"],
            ["anomalous_flow", "high_entropy"],
            ["suspicious_timing", "unusual_pattern"],
            ["c2_communication", "regular_beaconing"]
        ]),
        "attack_type": random.choice(attack_types),
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "blocked": random.choice([True, False]),
        "timestamp": datetime.now().isoformat()
    }
    
    return threat

def main():
    print("🚀 ZeroTrust-AI Real-Time Demo")
    print("📊 Sending simulated threats to dashboard...")
    print("🌐 Open http://localhost:9000 to see live updates")
    print("⚠️ Press Ctrl+C to stop")
    print()
    
    # First, ensure WebSocket server is running
    try:
        response = requests.get("http://localhost:9000", timeout=5)
        if response.status_code == 200:
            print("✅ WebSocket server is running")
        else:
            print("❌ WebSocket server not responding. Start it first:")
            print("   python services/detector/app/websocket_server.py")
            return
    except requests.exceptions.RequestException:
        print("❌ Cannot connect to WebSocket server. Start it first:")
        print("   python services/detector/app/websocket_server.py")
        return
    
    # Generate and send threats
    threat_count = 0
    try:
        while True:
            # Generate threat
            threat = generate_realistic_threat()
            
            # Send to WebSocket server
            try:
                response = requests.post(
                    "http://localhost:9000/detect",
                    json=threat,
                    timeout=5
                )
                if response.status_code == 200:
                    threat_count += 1
                    print(f"🚨 Threat #{threat_count}: {threat['attack_type']} from {threat['source_ip']}")
                    print(f"   Severity: {threat['severity']}, Confidence: {threat['confidence']:.0%}")
                    if threat['blocked']:
                        print(f"   ✅ AUTO-BLOCKED: {threat['flow_id']}")
                else:
                    print(f"   ⚠️ Failed to send: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"❌ Connection error: {e}")
            
            # Random delay between threats (1-5 seconds)
            time.sleep(random.uniform(1, 5))
            
    except KeyboardInterrupt:
        print(f"\n🛑 Demo stopped. Sent {threat_count} simulated threats.")
        print("📊 Dashboard will continue to show the threats.")

if __name__ == "__main__":
    main()
