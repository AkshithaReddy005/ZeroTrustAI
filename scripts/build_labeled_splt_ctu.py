#!/usr/bin/env python3
"""Build a labeled SPLT dataset by joining SPLT flows with CTU Argus binetflow labels.

Inputs:
- data/processed/splt_features.csv
- data/labels/capture20110810.binetflow

Output:
- data/processed/splt_features_labeled.csv

Label mapping:
- malicious if Label contains 'Botnet' or 'Malware' or 'C2' (case-insensitive)
- benign otherwise

Join strategy (best-effort):
- join on a canonical 5-tuple ignoring direction:
  (proto, min(src,dst), min(sport,dport), max(src,dst), max(sport,dport))

This is a pragmatic approach for demo/training. For rigorous research-grade labeling,
include timestamps in SPLT extraction and join by (5-tuple + time overlap).
"""

import pathlib
import pandas as pd

SPLT_IN = pathlib.Path("data/processed/splt_features.csv")
BINET_IN = pathlib.Path("data/labels/capture20110810.binetflow")
OUT = pathlib.Path("data/processed/splt_features_labeled.csv")

NERIS_PCAP_NAME = "botnet-capture-20110810-neris.pcap"


def proto_norm(x: str) -> str:
    x = str(x).strip().lower()
    if x in {"6", "tcp"}:
        return "tcp"
    if x in {"17", "udp"}:
        return "udp"
    return x


def canonical_key(proto: str, a_ip: str, a_port: int, b_ip: str, b_port: int) -> str:
    a_ip = str(a_ip)
    b_ip = str(b_ip)
    a_port = int(a_port)
    b_port = int(b_port)
    if (a_ip, a_port) <= (b_ip, b_port):
        return f"{proto}|{a_ip}|{a_port}|{b_ip}|{b_port}"
    return f"{proto}|{b_ip}|{b_port}|{a_ip}|{a_port}"


def label_to_binary(lbl: str) -> int:
    s = str(lbl).lower()
    return 1 if ("botnet" in s or "malware" in s or "c2" in s) else 0


def main():
    if not SPLT_IN.exists():
        raise FileNotFoundError(SPLT_IN)
    if not BINET_IN.exists():
        raise FileNotFoundError(BINET_IN)

    print(f"Loading SPLT: {SPLT_IN}")
    splt = pd.read_csv(SPLT_IN)

    # Prepare SPLT canonical keys
    splt["proto_n"] = splt["protocol"].map(proto_norm)
    splt["key"] = splt.apply(
        lambda r: canonical_key(r["proto_n"], r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"]),
        axis=1,
    )
    # Only label the Neris PCAP using CTU binetflow; other PCAPs are treated as benign background.
    if "pcap_file" in splt.columns:
        neris_mask = splt["pcap_file"].astype(str) == NERIS_PCAP_NAME
    else:
        neris_mask = pd.Series([True] * len(splt))

    splt_keys = set(splt.loc[neris_mask, "key"].astype(str).tolist())
    print(f"SPLT rows={len(splt)} neris_rows={int(neris_mask.sum())} unique_neris_keys={len(splt_keys)}")

    # Stream binetflow in chunks and only keep keys that exist in SPLT
    print(f"Streaming binetflow labels: {BINET_IN}")
    key_to_y = {}
    usecols = ["Proto", "SrcAddr", "Sport", "DstAddr", "Dport", "Label"]
    chunksize = 200_000

    for i, chunk in enumerate(
        pd.read_csv(
            BINET_IN,
            usecols=usecols,
            chunksize=chunksize,
            low_memory=True,
        )
    ):
        # Drop malformed rows (should be rare, but prevents NaN port conversions)
        chunk = chunk.dropna(subset=["Proto", "SrcAddr", "Sport", "DstAddr", "Dport", "Label"])
        if chunk.empty:
            continue

        # Ensure ports are integers
        chunk["Sport"] = pd.to_numeric(chunk["Sport"], errors="coerce").astype("Int64")
        chunk["Dport"] = pd.to_numeric(chunk["Dport"], errors="coerce").astype("Int64")
        chunk = chunk.dropna(subset=["Sport", "Dport"])
        if chunk.empty:
            continue
        chunk["Sport"] = chunk["Sport"].astype(int)
        chunk["Dport"] = chunk["Dport"].astype(int)

        chunk["proto_n"] = chunk["Proto"].map(proto_norm)
        chunk["key"] = chunk.apply(
            lambda r: canonical_key(r["proto_n"], r["SrcAddr"], r["Sport"], r["DstAddr"], r["Dport"]),
            axis=1,
        )
        # Filter to keys we care about
        chunk = chunk[chunk["key"].isin(splt_keys)]
        if not chunk.empty:
            ys = chunk["Label"].map(label_to_binary).astype(int)
            for k, y in zip(chunk["key"].tolist(), ys.tolist()):
                prev = key_to_y.get(k, 0)
                if y > prev:
                    key_to_y[k] = y

        if (i + 1) % 5 == 0:
            print(f"  processed_chunks={i+1} labeled_keys={len(key_to_y)}")

    print(f"Total labeled keys matched: {len(key_to_y)}")

    # Default benign for non-Neris PCAPs
    splt["label"] = 0
    # Apply CTU labels only to Neris flows
    splt.loc[neris_mask, "label"] = splt.loc[neris_mask, "key"].map(key_to_y).fillna(0).astype(int)
    splt.drop(columns=["proto_n", "key"], inplace=True)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    splt.to_csv(OUT, index=False)

    pos = int(splt["label"].sum())
    total = int(len(splt))
    print(f"Wrote {OUT} with labeled flows. positives={pos} total={total} pos_rate={pos/max(total,1):.6f}")


if __name__ == "__main__":
    main()
