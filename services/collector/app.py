import os
import time
import random
import requests
from datetime import datetime

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")
INTERVAL_MS = int(os.getenv("EMIT_INTERVAL_MS", "1000"))
EMIT_THREATS = os.getenv("EMIT_THREATS", "0").lower() in {"1", "true", "yes"}

THREATS = [
    ("Port Scan", "HIGH"),
    ("Malware C2", "MEDIUM"),
    ("SQL Injection", "LOW"),
]

SRC_PREFIX = "203.0.113."


def emit_flow():
    flow = {
        "flow_id": f"flow-{random.randint(1000,9999)}",
        "total_packets": random.randint(10, 500),
        "total_bytes": random.randint(1_000, 200_000),
        "avg_packet_size": random.uniform(200, 1500),
        "std_packet_size": random.uniform(10, 300),
        "duration": random.uniform(0.01, 3.0),
        "pps": random.uniform(10, 1000),
        "avg_entropy": random.uniform(2.0, 7.9),
        "syn_count": random.randint(0, 20),
        "fin_count": random.randint(0, 10),
    }
    try:
        requests.post(f"{API_BASE}/events/flow", json=flow, timeout=3)
    except Exception:
        pass


def emit_threat():
    ttype, sev = random.choice(THREATS)
    threat = {
        "flow_id": f"flow-{random.randint(1000,9999)}",
        "label": "malicious" if sev != "LOW" else "benign",
        "confidence": round(random.uniform(0.6, 0.99), 2),
        "anomaly_score": round(random.uniform(0.1, 1.0), 2),
        "severity": sev,
        "reason": [ttype, "heuristic_match"],
    }
    try:
        requests.post(f"{API_BASE}/events/threat", json=threat, timeout=3)
    except Exception:
        pass


def main():
    print(f"Collector posting to {API_BASE} every {INTERVAL_MS} ms")
    if not EMIT_THREATS:
        print("Auto threat emission disabled (EMIT_THREATS=0). Threats will only be processed when manually sent to the API.")
    while True:
        emit_flow()
        # Only emit synthetic threats if explicitly enabled
        if EMIT_THREATS and random.random() > 0.5:
            emit_threat()
        time.sleep(INTERVAL_MS / 1000.0)


if __name__ == "__main__":
    main()
