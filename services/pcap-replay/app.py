import os
import glob
import time
import socket
import struct
import dpkt
import requests
import random
import csv
import json
from typing import Tuple, Dict

from math import log1p

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")
FILE_GLOB = os.getenv("FILE_GLOB", "/data/raw/*.pcap")
THROTTLE_MS = int(os.getenv("THROTTLE_MS", "25"))
CSV_PATH = os.getenv("CSV_PATH", "c:\\Users\\shrey\\Desktop\\techs\\ZeroTrustAI\\data\\processed\\splt_features_labeled.csv")
USE_CSV = os.getenv("USE_CSV", "true").lower() == "true"


def inet_to_str(inet: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    total = float(len(data))
    from math import log2
    return -sum((c / total) * log2(c / total) for c in counts.values())


def flow_key(ip, l4) -> Tuple[str, str, int, int, str]:
    proto = 'TCP' if isinstance(l4, dpkt.tcp.TCP) else 'UDP' if isinstance(l4, dpkt.udp.UDP) else str(ip.p)
    src = inet_to_str(ip.src)
    dst = inet_to_str(ip.dst)
    sport = getattr(l4, 'sport', 0)
    dport = getattr(l4, 'dport', 0)
    return (src, dst, sport, dport, proto)


def post_flow_event(flow_id: str, agg: Dict):
    payload = {
        "flow_id": flow_id,
        "total_packets": agg.get("total_packets", 0),
        "total_bytes": agg.get("total_bytes", 0),
        "avg_packet_size": agg.get("avg_packet_size", 0),
        "std_packet_size": agg.get("std_packet_size", 0),
        "duration": agg.get("duration", 0.0001),
        "pps": agg.get("pps", 0),
        "avg_entropy": agg.get("avg_entropy", 0),
        "syn_count": agg.get("syn_count", 0),
        "fin_count": agg.get("fin_count", 0),
        "splt_len": agg.get("splt_len", []),
        "splt_iat": agg.get("splt_iat", []),
        "source_ip": agg.get("src_ip", ""),
        "destination_ip": agg.get("dst_ip", ""),
    }
    try:
        requests.post(f"{API_BASE}/events/flow", json=payload, timeout=3)
    except Exception:
        pass


def post_threat_event(flow_id: str, agg: Dict, row_label: str):
    # Determine label and severity based on CSV label or random injection
    is_malicious = (str(row_label).strip() == "1")
    if not is_malicious and random.random() < 0.1:  # 10% random malicious injection
        is_malicious = True

    severity = random.choice(["low", "medium", "high", "critical"]) if is_malicious else "low"
    confidence = round(random.uniform(0.6, 0.99), 2) if is_malicious else round(random.uniform(0.1, 0.4), 2)
    label = "malicious" if is_malicious else "benign"

    attack_types = ["DDoS", "Port Scan", "Brute Force", "Data Exfiltration", "Command & Control", "Web Attack", "Malware C2", "Reconnaissance"]
    attack_type = random.choice(attack_types) if is_malicious else "Normal Traffic"

    reasons = []
    if is_malicious:
        reasons = ["High packet rate", "Unusual destination port", "Large payload entropy", "Suspicious timing pattern"]
        random.shuffle(reasons)
        reasons = reasons[:2]
    else:
        reasons = ["Normal protocol behavior", "Standard port usage", "Low entropy payload"]

    payload = {
        "flow_id": flow_id,
        "label": label,
        "confidence": confidence,
        "severity": severity,
        "reason": reasons,
        "attack_type": attack_type,
        "source_ip": agg.get("src_ip", ""),
        "destination_ip": agg.get("dst_ip", ""),
        "blocked": is_malicious and severity in ("high", "critical"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
    }
    try:
        requests.post(f"{API_BASE}/events/threat", json=payload, timeout=3)
    except Exception:
        pass


def process_csv():
    if not os.path.exists(CSV_PATH):
        print(f"CSV not found: {CSV_PATH}")
        return
    print(f"Replaying CSV: {CSV_PATH}")
    with open(CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            flow_id = row.get("flow_id", f"csv-{i}")
            agg = {
                "src_ip": row.get("src_ip", ""),
                "dst_ip": row.get("dst_ip", ""),
                "total_packets": int(row.get("total_packets", 0)),
                "total_bytes": int(row.get("total_bytes", 0)),
                "avg_packet_size": float(row.get("avg_packet_size", 0)) if row.get("avg_packet_size") else (int(row.get("total_bytes", 0)) / max(int(row.get("total_packets", 1)), 1)),
                "std_packet_size": round(random.uniform(10, 200), 2),
                "duration": float(row.get("duration", 0.0001)),
                "pps": float(row.get("pps", 0)),
                "avg_entropy": float(row.get("avg_entropy", 0)),
                "syn_count": int(row.get("syn_count", 0)),
                "fin_count": int(row.get("fin_count", 0)),
                "splt_len": [float(row.get(f"splt_len_{j}", 0)) for j in range(1, 21)],
                "splt_iat": [float(row.get(f"splt_iat_{j}", 0)) for j in range(1, 21)],
            }
            post_flow_event(flow_id, agg)
            post_threat_event(flow_id, agg, row.get("label", "0"))
            time.sleep(THROTTLE_MS / 1000.0)
    print("CSV replay complete. Sleeping...")
    while True:
        time.sleep(60)


def process_pcap(path: str):
    flows: Dict[str, Dict] = {}
    with open(path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                l4 = ip.data
                key = flow_key(ip, l4)
                fid = f"{key[0]}:{key[2]}->{key[1]}:{key[3]}/{key[4]}"
                rec = flows.setdefault(
                    fid,
                    {
                        "count": 0,
                        "bytes": 0,
                        "first_ts": ts,
                        "last_ts": ts,
                        "entropy_sum": 0.0,
                        "syn": 0,
                        "fin": 0,
                        "splt_len": [],
                        "splt_iat": [],
                        "last_pkt_ts": None,
                        "client_ip": key[0],
                    },
                )
                rec["count"] += 1
                rec["bytes"] += len(buf)
                rec["last_ts"] = ts

                # SPLT capture (first 20)
                if len(rec.get("splt_len", [])) < 20:
                    # Direction: + for client->server (flow initiator), - for reverse
                    src = inet_to_str(ip.src)
                    direction = 1.0 if src == rec.get("client_ip") else -1.0
                    rec["splt_len"].append(direction * log1p(len(buf)))
                    last_pkt_ts = rec.get("last_pkt_ts")
                    if last_pkt_ts is None:
                        rec["splt_iat"].append(0.0)
                    else:
                        rec["splt_iat"].append(max(0.0, ts - float(last_pkt_ts)))
                    rec["last_pkt_ts"] = ts
                payload = b""
                if isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    payload = l4.data or b""
                rec["entropy_sum"] += shannon_entropy(payload)
                if isinstance(l4, dpkt.tcp.TCP):
                    flags = l4.flags
                    if flags & dpkt.tcp.TH_SYN:
                        rec["syn"] += 1
                    if flags & dpkt.tcp.TH_FIN:
                        rec["fin"] += 1

                # Throttle emits to simulate near-real-time
                if rec["count"] % 10 == 0:
                    post_flow_event(fid, rec)
                    time.sleep(THROTTLE_MS / 1000.0)
            except Exception:
                continue
    # Final flush
    for fid, rec in flows.items():
        post_flow_event(fid, rec)


def main():
    if USE_CSV:
        process_csv()
        return
    files = sorted(glob.glob(FILE_GLOB))
    if not files:
        print(f"No PCAPs found for glob: {FILE_GLOB}. Waiting...")
        while not files:
            time.sleep(2)
            files = sorted(glob.glob(FILE_GLOB))
    print(f"Replaying {len(files)} PCAP(s)")
    for p in files:
        print(f"Processing {p}")
        process_pcap(p)
    print("Replay complete. Sleeping...")
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
