#!/usr/bin/env python3
"""
Day 3–4: NFStream SPLT Feature Extraction (TLS 1.3 focus)
- Reads PCAP files from data/raw/
- Extracts SPLT (Sequence of Packet Lengths and Times) per flow (first 20 each)
- Computes flow duration, packet/byte counts
- Attempts to capture TLS handshake metadata (version, cipher suites) and ECH presence (best-effort)
- Applies log-scaling to packet lengths: log1p(abs(len)) with sign of direction (+ client->server, - server->client)
- Writes data/processed/splt_features.csv

Requirements:
  pip install nfstream pandas numpy dpkt

Usage:
  python scripts/extract_splt_nfstream.py
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
        import nfstream  # noqa: F401
        import pandas as pd  # noqa: F401
        import numpy as np  # noqa: F401
    except Exception as e:
        print("Missing dependencies. Install with: pip install nfstream pandas numpy dpkt")
        raise


def list_pcaps() -> List[pathlib.Path]:
    pcaps: List[pathlib.Path] = []
    for root, _, files in os.walk(RAW_DIR):
        for fn in files:
            if fn.lower().endswith((".pcap", ".pcapng")):
                pcaps.append(pathlib.Path(root) / fn)
    return sorted(pcaps)


# Best-effort TLS parsing helpers (very lightweight, not full TLS)
TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1


def parse_tls_metadata(payload: bytes) -> Dict[str, Any]:
    """Return minimal TLS handshake metadata if present in payload."""
    meta: Dict[str, Any] = {
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
        # TLS version field (record layer) at bytes [1:3]
        rec_version = payload[1:3]
        # Handshake header starts at byte 5
        hs_type = payload[5] if len(payload) > 5 else None
        # TLS 1.3 uses record version 0x0303 but negotiates 0x0304 in supported_versions
        if hs_type == TLS_CLIENT_HELLO:
            # Heuristic: look for ECH extension codepoint 0xFE0D in payload
            if b"\xfe\r" in payload or b"encrypted_client_hello" in payload:
                meta["ech_detected"] = True
            # Roughly tag tls_version
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
    # signed by direction (positive for fwd, negative for bwd)
    sign = 1.0 if length >= 0 else -1.0
    return sign * math.log1p(abs(length))


def extract_from_pcap(pcap_path: pathlib.Path) -> List[Dict[str, Any]]:
    from nfstream import NFStreamer
    import dpkt

    rows: List[Dict[str, Any]] = []

    # NFStream will decode flows; to derive SPLT we need packet sequences. We'll do a parallel pass
    # using dpkt to collect per-flow first 20 packet lengths and IATs.
    # Flow key: (src, sport, dst, dport, proto)

    def flow_key_5tuple(src: str, sport: int, dst: str, dport: int, proto: int) -> str:
        return f"{src}:{sport}->{dst}:{dport}/{proto}"

    # Build per-flow packet sequences via dpkt
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
                        'lens': [],  # signed lengths
                        'iat': [],   # inter-arrival time deltas
                        'first_ts': ts,
                        'last_ts': ts,
                        'total_packets': 0,
                        'total_bytes': 0,
                        'tls_version': None,
                        'tls_cipher': None,
                        'ech_detected': False,
                        'src': src, 'dst': dst, 'sport': sport, 'dport': dport, 'proto': proto,
                    })
                    # Direction sign: client->server positive, server->client negative heuristic:
                    # assume initiator is the first sender (src of first packet)
                    initiator = rec.get('initiator')
                    if initiator is None:
                        rec['initiator'] = src
                        initiator = src
                    direction_sign = 1 if src == initiator else -1

                    payload = b""
                    if hasattr(l4, 'data') and isinstance(l4.data, (bytes, bytearray)):
                        payload = l4.data
                    elif hasattr(l4, 'data') and hasattr(l4.data, 'pack'):
                        # dpkt objects sometimes
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

                    # Heuristic TLS metadata capture (first packets only)
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

    # Now use NFStream for aggregated flow stats and TLS meta
    try:
        streamer = NFStreamer(
            source=str(pcap_path),
            statistical_analysis=True,
            splt_analysis=False,
            n_dissections=0,
        )
        for flow in streamer:
            try:
                fid = flow_key_5tuple(flow.src_ip, int(flow.src_port), flow.dst_ip, int(flow.dst_port), int(flow.protocol))
                seq = per_flow.get(fid, None)
                if seq is None:
                    continue
                # Do not depend on NFStream TLS dissection; use dpkt-derived metadata instead.
                tls_meta = {
                    "tls_version": seq.get("tls_version"),
                    "tls_cipher": None,
                    "ech_detected": bool(seq.get("ech_detected")),
                }
                row = {
                    "pcap_file": pcap_path.name,
                    "flow_id": fid,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": int(flow.src_port),
                    "dst_port": int(flow.dst_port),
                    "protocol": int(flow.protocol),
                    "duration": float(flow.bidirectional_duration_ms) / 1000.0 if getattr(flow, "bidirectional_duration_ms", None) else float(flow.duration) if getattr(flow, "duration", None) else 0.0,
                    "total_packets": int(getattr(flow, "bidirectional_packets", 0) or 0),
                    "total_bytes": int(getattr(flow, "bidirectional_bytes", 0) or 0),
                    "tls_version": tls_meta.get("tls_version"),
                    "tls_cipher": tls_meta.get("tls_cipher"),
                    "ech_detected": int(bool(tls_meta.get("ech_detected"))),
                }
                lens = (seq['lens'] + [0.0] * 20)[:20]
                iat = (seq['iat'] + [0.0] * 20)[:20]
                for i in range(20):
                    row[f'splt_len_{i+1}'] = float(lens[i])
                    row[f'splt_iat_{i+1}'] = float(iat[i])
                rows.append(row)
            except Exception:
                continue
    except Exception as e:
        print(f"Failed to process {pcap_path}: {e}")

    return rows


def main():
    try_imports()
    import pandas as pd

    ensure_dirs()
    pcaps = list_pcaps()
    if not pcaps:
        print(f"No PCAP files found under {RAW_DIR}. Place CSE-CIC-IDS2018 PCAPs and retry.")
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
    # Reorder columns
    base_cols = ['pcap_file','flow_id','src_ip','dst_ip','src_port','dst_port','protocol','duration','total_packets','total_bytes','tls_version','tls_cipher','ech_detected']
    splt_cols = [f'splt_len_{i}' for i in range(1,21)] + [f'splt_iat_{i}' for i in range(1,21)]
    cols = base_cols + splt_cols
    df = df[cols]

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_CSV, index=False)
    print(f"Wrote {OUT_CSV} with {len(df)} flows")


if __name__ == '__main__':
    main()
