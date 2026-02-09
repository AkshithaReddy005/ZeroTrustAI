#!/usr/bin/env python3
"""
Lightweight SPLT extraction without NFStream (uses only dpkt).
- Reads PCAP files from data/raw/
- Extracts first 20 signed, log-scaled packet lengths and inter-arrival times per flow
- Computes flow duration, packet/byte counts
- Minimal TLS metadata detection (record layer version and ECH heuristic)
- Writes data/processed/splt_features.csv

Requirements:
  pip install pandas numpy dpkt

Usage:
  python scripts/extract_splt_lite.py
"""
import os
import sys
import math
import pathlib
from typing import List, Dict, Any

RAW_DIR = pathlib.Path("data/raw")
PROC_DIR = pathlib.Path("data/processed")
OUT_CSV = PROC_DIR / "splt_features.csv"


def ensure_dirs():
    PROC_DIR.mkdir(parents=True, exist_ok=True)


def try_imports():
    try:
        import pandas as pd  # noqa: F401
        import numpy as np  # noqa: F401
        import dpkt  # noqa: F401
    except Exception as e:
        print("Missing dependencies. Install with: pip install pandas numpy dpkt")
        raise


def list_pcaps() -> List[pathlib.Path]:
    pcaps: List[pathlib.Path] = []
    for root, _, files in os.walk(RAW_DIR):
        for fn in files:
            if fn.lower().endswith((".pcap", ".pcapng")):
                pcaps.append(pathlib.Path(root) / fn)
    return sorted(pcaps)


# Minimal TLS parsing helpers
TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1


def parse_tls_metadata(payload: bytes) -> Dict[str, Any]:
    meta = {
        "tls_version": None,
        "tls_cipher": None,
        "ech_detected": False,
    }
    try:
        if len(payload) < 5:
            return meta
        content_type = payload[0]
        if content_type != TLS_HANDSHAKE:
            return meta
        rec_version = payload[1:3]
        hs_type = payload[5] if len(payload) > 5 else None
        if hs_type == TLS_CLIENT_HELLO:
            if b"\xfe\r" in payload or b"encrypted_client_hello" in payload:
                meta["ech_detected"] = True
            if rec_version == b"\x03\x03":
                meta["tls_version"] = "TLS1.2_or_1.3"
            elif rec_version == b"\x03\x04":
                meta["tls_version"] = "TLS1.3"
            elif rec_version == b"\x03\x01":
                meta["tls_version"] = "TLS1.0"
            elif rec_version == b"\x03\x02":
                meta["tls_version"] = "TLS1.1"
            else:
                meta["tls_version"] = f"0x{rec_version.hex()}"
    except Exception:
        pass
    return meta


def log_scaled_len(length: int) -> float:
    sign = 1.0 if length >= 0 else -1.0
    return sign * math.log1p(abs(length))


def extract_from_pcap(pcap_path: pathlib.Path) -> List[Dict[str, Any]]:
    import dpkt

    rows: List[Dict[str, Any]] = []

    def flow_key_5tuple(src: str, sport: int, dst: str, dport: int, proto: int) -> str:
        return f"{src}:{sport}->{dst}:{dport}/{proto}"

    per_flow = {}
    try:
        with open(pcap_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            last_ts_per_flow = {}
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if not hasattr(ip, 'p'):
                        continue
                    proto = ip.p
                    l4 = ip.data
                    src = dpkt.utils.inet_to_str(ip.src)
                    dst = dpkt.utils.inet_to_str(ip.dst)
                    sport = getattr(l4, 'sport', 0)
                    dport = getattr(l4, 'dport', 0)
                    key = flow_key_5tuple(src, sport, dst, dport, proto)

                    rec = per_flow.setdefault(key, {
                        'lens': [],
                        'iat': [],
                        'first_ts': ts,
                        'last_ts': ts,
                        'total_packets': 0,
                        'total_bytes': 0,
                        'tls_version': None,
                        'tls_cipher': None,
                        'ech_detected': False,
                        'src': src, 'dst': dst, 'sport': sport, 'dport': dport, 'proto': proto,
                        'initiator': None,
                    })
                    if rec['initiator'] is None:
                        rec['initiator'] = src
                    direction_sign = 1 if src == rec['initiator'] else -1

                    payload = b""
                    if hasattr(l4, 'data') and isinstance(l4.data, (bytes, bytearray)):
                        payload = l4.data
                    elif hasattr(l4, 'data') and hasattr(l4.data, 'pack'):
                        try:
                            payload = bytes(l4.data)
                        except Exception:
                            payload = b""

                    length = direction_sign * len(payload)
                    rec['lens'].append(log_scaled_len(length))

                    last_ts = last_ts_per_flow.get(key)
                    if last_ts is not None:
                        rec['iat'].append(max(ts - last_ts, 0.0))
                    last_ts_per_flow[key] = ts

                    rec['last_ts'] = ts
                    rec['total_packets'] += 1
                    rec['total_bytes'] += len(buf)

                    if rec['tls_version'] is None and payload:
                        meta = parse_tls_metadata(payload)
                        if meta.get('tls_version'):
                            rec['tls_version'] = meta['tls_version']
                        rec['ech_detected'] = rec['ech_detected'] or bool(meta.get('ech_detected'))
                except Exception:
                    continue
    except Exception as e:
        print(f"Failed to read {pcap_path}: {e}")
        return rows

    for key, rec in per_flow.items():
        lens = (rec['lens'] + [0.0] * 20)[:20]
        iat = (rec['iat'] + [0.0] * 20)[:20]
        duration = max(rec['last_ts'] - rec['first_ts'], 0.0)
        row = {
            'pcap_file': os.path.basename(pcap_path),
            'flow_id': key,
            'src_ip': rec['src'], 'dst_ip': rec['dst'],
            'src_port': rec['sport'], 'dst_port': rec['dport'],
            'protocol': rec['proto'],
            'duration': duration,
            'total_packets': rec['total_packets'],
            'total_bytes': rec['total_bytes'],
            'tls_version': rec['tls_version'] or '',
            'tls_cipher': rec['tls_cipher'] or '',
            'ech_detected': int(bool(rec['ech_detected'])),
        }
        for i in range(20):
            row[f'splt_len_{i+1}'] = float(lens[i])
            row[f'splt_iat_{i+1}'] = float(iat[i])
        rows.append(row)

    return rows


def main():
    try_imports()
    import pandas as pd

    ensure_dirs()
    pcaps = list_pcaps()
    if not pcaps:
        print(f"No PCAP files found under {RAW_DIR}. Place PCAPs and retry.")
        sys.exit(1)

    all_rows: List[Dict[str, Any]] = []
    for idx, p in enumerate(pcaps, 1):
        print(f"[{idx}/{len(pcaps)}] Extracting SPLT from {p}")
        rows = extract_from_pcap(p)
        print(f"  -> {len(rows)} flows")
        if rows:
            all_rows.extend(rows)

    if not all_rows:
        print("No flows extracted.")
        sys.exit(2)

    df = pd.DataFrame(all_rows)
    base_cols = ['flow_id','src_ip','dst_ip','src_port','dst_port','protocol','duration','total_packets','total_bytes','tls_version','tls_cipher','ech_detected']
    splt_cols = [f'splt_len_{i}' for i in range(1,21)] + [f'splt_iat_{i}' for i in range(1,21)]
    cols = base_cols + splt_cols
    df = df[cols]

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_CSV, index=False)
    print(f"Wrote {OUT_CSV} with {len(df)} flows")


if __name__ == '__main__':
    main()
