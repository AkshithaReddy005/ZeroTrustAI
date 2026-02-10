#!/usr/bin/env python3
"""
ZeroTrust-AI Real-Time Demo
Publishes simulated threat EVENTS to the dashboard (Phase 6).
This does NOT perform detection or ML inference.
"""

import requests
import time
import random
from datetime import datetime

API_BASE = "http://localhost:9000"

def generate_threat_event():
    """Generate a dashboard-ready threat event with MITRE mapping"""

    attack_scenarios = [
        ("botnet", "Command and Control", "T1071"),
        ("data_exfiltration", "Exfiltration", "T1041"),
        ("reconnaissance", "Reconnaissance", "T1046"),
        ("web_attack", "Initial Access", "T1190"),
        ("malware", "Execution", "T1059"),
    ]

    attack_type, tactic, technique = random.choice(attack_scenarios)

    src_ip = f"192.168.1.{random.randint(100,200)}"
    dst_ip = f"10.0.0.{random.randint(1,50)}"

    return {
        "flow_id": f"{src_ip}:{random.randint(1000,9999)}->{dst_ip}:443/TCP",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "attack_type": attack_type,
        "severity": random.choice(["low", "medium", "high"]),
        "confidence": round(random.uniform(0.6, 0.99), 2),
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "blocked": random.choice([True, False]),
        "timestamp": datetime.utcnow().isoformat()
    }

def main():
    print("🚀 ZeroTrust-AI Dashboard Demo")
    print("📊 Sending threat EVENTS to /threats")
    print("🌐 Open http://localhost:9000")
    print("⛔ Ctrl+C to stop\n")

    # sanity check
    try:
        requests.get(API_BASE, timeout=3)
        print("✅ Backend reachable\n")
    except Exception:
        print("❌ Backend not reachable")
        return

    count = 0
    try:
        while True:
            event = generate_threat_event()

            r = requests.post(
                f"{API_BASE}/threats",
                json=event,
                timeout=5
            )

            if r.status_code in (200, 201):
                count += 1
                print(f"🚨 Event #{count}: {event['attack_type']} | {event['source_ip']}")
            else:
                print(f"⚠️ Failed: {r.status_code}")

            time.sleep(random.uniform(1.5, 4))

    except KeyboardInterrupt:
        print(f"\n🛑 Stopped. Sent {count} events.")

if __name__ == "__main__":
    main()
