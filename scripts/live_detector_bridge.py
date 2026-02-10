#!/usr/bin/env python3
"""
Bridge: Generate flows, run detection via services/detector/app/main.py, and post results to
services/detector/app/websocket_server.py (/detect) for real-time dashboard streaming.

- Detector API: http://localhost:9001 (uvicorn main:app)
- WebSocket Server API: http://localhost:9000 (websocket_server.py)
"""
import time
import random
import requests
from typing import Dict, Any
from datetime import datetime

DETECTOR = "http://localhost:9001"
WS = "http://localhost:9000"

SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

SRC_NETS = [
    "10.",
    "172.16.",
    "192.168.",
    "203.0.113.",
]
DST_NETS = [
    "198.51.100.",
    "192.0.2.",
    "8.8.8.",
    "1.1.1.",
]


def rand_ip(prefixes):
    p = random.choice(prefixes)
    return f"{p}{random.randint(0,255)}.{random.randint(0,255)}"


def wait_for_service(url: str, timeout: int = 60) -> None:
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=3)
            if r.ok:
                return
        except Exception:
            pass
        time.sleep(1)
    raise TimeoutError(f"Service not ready: {url}")


def generate_flow(i: int) -> Dict[str, Any]:
    # Mix benign and malicious-looking traffic characteristics
    if random.random() < 0.35:
        # Malicious-ish profile (e.g., high PPS, SYN flood)
        return {
            "flow_id": f"flow-mal-{i}",
            "total_packets": random.randint(2000, 12000),
            "total_bytes": random.randint(200_000, 5_000_000),
            "avg_packet_size": random.uniform(60, 400),
            "std_packet_size": random.uniform(120, 600),
            "duration": random.uniform(0.05, 1.5),
            "pps": random.uniform(800, 50000),
            "avg_entropy": random.uniform(6.0, 8.0),
            "syn_count": random.randint(20, 400),
            "fin_count": random.randint(0, 5),
        }
    else:
        # Benign-ish profile
        return {
            "flow_id": f"flow-ben-{i}",
            "total_packets": random.randint(50, 800),
            "total_bytes": random.randint(10_000, 1_500_000),
            "avg_packet_size": random.uniform(200, 1200),
            "std_packet_size": random.uniform(10, 200),
            "duration": random.uniform(0.2, 8.0),
            "pps": random.uniform(5, 400),
            "avg_entropy": random.uniform(2.0, 7.0),
            "syn_count": random.randint(0, 12),
            "fin_count": random.randint(0, 10),
        }


def main():
    print("[bridge] Waiting for detector and websocket server...")
    try:
        wait_for_service(f"{DETECTOR}/health")
        wait_for_service(f"{WS}/metrics")
    except Exception as e:
        print("[bridge] Service wait failed:", e)
        return

    print("[bridge] Services detected. Starting live forwarding loop...")
    i = 0
    while True:
        i += 1
        flow = generate_flow(i)
        try:
            # Run detection
            dr = requests.post(f"{DETECTOR}/detect", json=flow, timeout=5)
            if not dr.ok:
                print(f"[bridge] Detector POST failed: {dr.status_code} {dr.text}")
                time.sleep(0.5)
                continue
            det = dr.json()

            # Compose threat for WS broadcast
            sev = SEV_MAP.get(det.get("severity", "MEDIUM"), "medium")
            threat = {
                "flow_id": det.get("flow_id", flow.get("flow_id")),
                "label": det.get("label", "benign"),
                "confidence": float(det.get("confidence", 0.5)),
                "severity": sev,
                "reason": det.get("reason", []),
                "timestamp": datetime.now().isoformat(),
                "attack_type": None,
                "source_ip": rand_ip(SRC_NETS),
                "destination_ip": rand_ip(DST_NETS),
                "blocked": False,
            }

            wr = requests.post(f"{WS}/detect", json=threat, timeout=5)
            if not wr.ok:
                print(f"[bridge] WS /detect failed: {wr.status_code} {wr.text}")
            else:
                print(f"[bridge] forwarded {threat['flow_id']} -> {threat['label']} ({sev})")
        except Exception as e:
            print("[bridge] error:", e)

        time.sleep(0.5)


if __name__ == "__main__":
    main()