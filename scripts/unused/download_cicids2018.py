#!/usr/bin/env python3
"""
Day 2: Dataset Acquisition helper
- Organizes folders data/raw and data/processed
- Optionally downloads CSE-CIC-IDS2018 from provided URLs list (text file)
- Verifies presence of PCAP files and prints a summary

Usage:
  python scripts/download_cicids2018.py --urls urls.txt
  python scripts/download_cicids2018.py  # just ensure folders

Notes:
- The CSE-CIC-IDS2018 dataset is large and spread across multiple archives. You must supply
  direct download URLs (one per line) via --urls to automate downloading, or download manually
  and place PCAPs under data/raw/.
"""
import argparse
import os
import sys
import time
import pathlib
import shutil
from urllib.parse import urlparse

try:
    import requests
except Exception:
    requests = None

RAW_DIR = pathlib.Path("data/raw")
PROC_DIR = pathlib.Path("data/processed")
TMP_DIR = pathlib.Path("data/tmp")


def ensure_dirs():
    for d in (RAW_DIR, PROC_DIR, TMP_DIR):
        d.mkdir(parents=True, exist_ok=True)


def safe_filename_from_url(url: str) -> str:
    path = urlparse(url).path
    name = os.path.basename(path)
    return name or f"download-{int(time.time())}"


def download(url: str, dest_path: pathlib.Path, chunk=1 << 20):
    if requests is None:
        print("requests not available. Install with: pip install requests", file=sys.stderr)
        sys.exit(1)
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        got = 0
        with open(dest_path, "wb") as f:
            for part in r.iter_content(chunk_size=chunk):
                if not part:
                    continue
                f.write(part)
                got += len(part)
                if total:
                    pct = got * 100 // total
                    print(f"  downloading {dest_path.name}: {pct}% ({got}/{total} bytes)", end="\r")
        print()


def maybe_extract(archive_path: pathlib.Path):
    lower = archive_path.name.lower()
    try:
        if lower.endswith((".zip",)):
            import zipfile
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(RAW_DIR)
            return True
        if lower.endswith((".tar.gz", ".tgz")):
            import tarfile
            with tarfile.open(archive_path, 'r:gz') as tf:
                tf.extractall(RAW_DIR)
            return True
    except Exception as e:
        print(f"Failed to extract {archive_path}: {e}")
    return False


def find_pcaps(directory: pathlib.Path):
    exts = (".pcap", ".pcapng")
    for root, _, files in os.walk(directory):
        for fn in files:
            if fn.lower().endswith(exts):
                yield pathlib.Path(root) / fn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--urls", type=str, default=None, help="Text file with one dataset URL per line")
    args = ap.parse_args()

    ensure_dirs()

    if args.urls:
        url_path = pathlib.Path(args.urls)
        if not url_path.exists():
            print(f"URLs file not found: {args.urls}", file=sys.stderr)
            sys.exit(1)
        for line in url_path.read_text().splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            fname = safe_filename_from_url(url)
            tmp = TMP_DIR / fname
            if not tmp.exists():
                print(f"Downloading: {url}")
                try:
                    download(url, tmp)
                except Exception as e:
                    print(f"  failed: {e}")
                    continue
            # Try to extract, else move to raw
            if not maybe_extract(tmp):
                dest = RAW_DIR / fname
                if not dest.exists():
                    shutil.move(str(tmp), str(dest))

    pcaps = list(find_pcaps(RAW_DIR))
    print(f"Found {len(pcaps)} PCAP files under {RAW_DIR}")
    for p in pcaps[:10]:
        print(f"  - {p}")
    if not pcaps:
        print("Place CSE-CIC-IDS2018 PCAPs under data/raw/ (or pass --urls)")


if __name__ == "__main__":
    main()
