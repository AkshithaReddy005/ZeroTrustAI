#!/usr/bin/env python3
"""
ZeroTrust-AI Real Data Sender — CORRECT ML ARCHITECTURES
=========================================================
Architectures verified from inspect_models.py:

TCN: Sequential Conv1d — input [batch, 1, 40]
  Conv1d(1,64,3) → ReLU → Dropout
  Conv1d(64,128,3) → ReLU → Dropout → AvgPool → Flatten
  Linear(128,64) → ReLU → Linear(64,1) → Sigmoid

AE: Linear encoder/decoder — input [batch, 47]
  Encoder: 47→128→64→32
  Decoder: 32→64→128→47

IsoForest: searched across all model subdirectories
Scaler:    47 features (40 SPLT + 7 volumetric)

Ensemble: tcn*0.50 + ae*0.25 + iso*0.25
"""

import sys, os, time, random, requests
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib
from datetime import datetime, timezone

WS_SERVER    = "http://localhost:9000"
MODEL_DIR    = "models"
DELAY        = 0.8
THREAT_RATIO = 0.4
SEQ_LEN      = 20
AE_THRESHOLD = 0.95   # from ae_threshold.txt

CSV_CANDIDATES = [
    r"data\processed\splt_features_labeled.csv",
    r"data\processed\balanced_train_200k_v2.csv",
    r"data\processed\balanced_train_400k.csv",
    r"data\processed\splt_features.csv",
    r"data\processed\final_balanced_240k.csv",
]


# ── EXACT MODEL ARCHITECTURES ─────────────────────────────────────────────────

class TCN(nn.Module):
    """
    Keys from file:
      tcn.0  Conv1d(1,64,3)    tcn.3  Conv1d(64,128,3)
      tcn.8  Linear(128,64)    tcn.10 Linear(64,1)
    Input: [batch, 1, 40]
    """
    def __init__(self):
        super().__init__()
        self.tcn = nn.Sequential(
            nn.Conv1d(1, 64, 3, padding=1),    # 0
            nn.ReLU(),                           # 1
            nn.Dropout(0.2),                    # 2
            nn.Conv1d(64, 128, 3, padding=1),   # 3
            nn.ReLU(),                           # 4
            nn.Dropout(0.2),                    # 5
            nn.AdaptiveAvgPool1d(1),            # 6
            nn.Flatten(),                        # 7
            nn.Linear(128, 64),                 # 8
            nn.ReLU(),                           # 9
            nn.Linear(64, 1),                   # 10
            nn.Sigmoid(),                        # 11
        )
    def forward(self, x):
        return self.tcn(x)


class Autoencoder(nn.Module):
    """
    Keys from file:
      encoder.0 Linear(47,128)  encoder.3 Linear(128,64)  encoder.6 Linear(64,32)
      decoder.0 Linear(32,64)   decoder.3 Linear(64,128)  decoder.5 Linear(128,47)
    Input: [batch, 47]
    """
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(47, 128), nn.ReLU(), nn.Dropout(0.2),   # 0,1,2
            nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.2),   # 3,4,5
            nn.Linear(64, 32),                                  # 6
        )
        self.decoder = nn.Sequential(
            nn.Linear(32, 64),  nn.ReLU(), nn.Dropout(0.2),   # 0,1,2
            nn.Linear(64, 128), nn.ReLU(),                      # 3,4
            nn.Linear(128, 47),                                  # 5
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))


# ── MODEL LOADING ─────────────────────────────────────────────────────────────

def find_isoforest():
    import glob
    from sklearn.ensemble import IsolationForest
    paths = glob.glob(os.path.join(MODEL_DIR, "**", "*.joblib"), recursive=True)
    paths += glob.glob(os.path.join(MODEL_DIR, "*.joblib"))
    for path in sorted(set(paths)):
        try:
            obj = joblib.load(path)
            if isinstance(obj, IsolationForest):
                print(f"✅ IsoForest: {path}  (n_features={obj.n_features_in_})")
                return obj
        except: continue
    return None


def find_scaler(n_features):
    import glob
    paths = glob.glob(os.path.join(MODEL_DIR, "**", "*.joblib"), recursive=True)
    paths += glob.glob(os.path.join(MODEL_DIR, "*.joblib"))
    for path in sorted(set(paths)):
        try:
            obj = joblib.load(path)
            n = getattr(obj, "mean_", getattr(obj, "center_", None))
            if n is not None and len(n) == n_features:
                print(f"✅ Scaler:    {path}  (features={len(n)})")
                return obj
        except: continue
    return None


def load_models():
    device = torch.device("cpu")
    m = {}

    # TCN
    try:
        tcn = TCN()
        tcn.load_state_dict(torch.load(f"{MODEL_DIR}/tcn_classifier.pth", map_location=device))
        tcn.eval(); m["tcn"] = tcn
        print("✅ TCN loaded  → input [batch, 1, 40]")
    except Exception as e:
        print(f"❌ TCN: {e}"); m["tcn"] = None

    # Autoencoder
    try:
        ae = Autoencoder()
        ae.load_state_dict(torch.load(f"{MODEL_DIR}/autoencoder.pth", map_location=device))
        ae.eval(); m["ae"] = ae; m["ae_thr"] = AE_THRESHOLD
        print(f"✅ AE loaded   → input [batch, 47]  threshold={AE_THRESHOLD}")
    except Exception as e:
        print(f"❌ AE: {e}"); m["ae"] = None; m["ae_thr"] = AE_THRESHOLD

    # IsoForest (search all subdirs)
    iso = find_isoforest()
    m["iso"] = iso
    m["iso_nfeat"] = iso.n_features_in_ if iso else 47
    if iso:
        m["scaler"] = find_scaler(iso.n_features_in_)
    else:
        print("⚠️  IsolationForest not found — run: dir models\\82k_models\\")
        m["scaler"] = None

    return m, device


# ── FEATURE EXTRACTION ────────────────────────────────────────────────────────

def extract_features(row):
    len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN+1)]
    iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN+1)]
    splt_len = np.array([float(row.get(c,0) or 0) for c in len_cols], dtype=np.float32)
    splt_iat = np.array([float(row.get(c,0) or 0) for c in iat_cols], dtype=np.float32)
    splt_40  = np.concatenate([splt_len, splt_iat])

    dur = max(float(row.get("duration",1.0) or 1.0), 1e-3)
    pps = float(row.get("total_packets",100) or 100) / dur
    vol_7 = np.array([
        float(row.get("total_packets",  100) or 100),
        float(row.get("total_bytes",  50000) or 50000),
        float(row.get("avg_packet_size",500) or 500),
        float(row.get("std_packet_size",100) or 100),
        dur, pps,
        float(row.get("avg_entropy",    4.0) or 4.0),
    ], dtype=np.float32)

    full_47 = np.concatenate([splt_40, vol_7])      # [47] for AE + IsoForest
    X_tcn   = splt_40.reshape(1, -1)                # [1, 40] for TCN
    return X_tcn, full_47


# ── INFERENCE ─────────────────────────────────────────────────────────────────

def score_row(row, m, device):
    X_tcn, X_47 = extract_features(row)

    # TCN — input [1, 1, 40]
    tcn_s = 0.5
    if m["tcn"]:
        try:
            t = torch.from_numpy(X_tcn).unsqueeze(0).float()
            with torch.no_grad():
                tcn_s = float(m["tcn"](t).squeeze().item())
        except Exception as e:
            print(f"   TCN error: {e}")

    # AE — input [1, 47]
    ae_s = 0.5
    if m["ae"]:
        try:
            t = torch.from_numpy(X_47).unsqueeze(0).float()
            with torch.no_grad():
                recon = m["ae"](t)
                mse = float(((t - recon)**2).mean().item())
            ae_s = float(np.clip(mse / max(m["ae_thr"], 1e-9), 0.0, 1.0))
        except Exception as e:
            print(f"   AE error: {e}")

    # IsoForest
    iso_s = 0.5
    if m["iso"]:
        try:
            n   = m["iso_nfeat"]
            Xi  = np.zeros((1, n), dtype=np.float32)
            src = X_47 if len(X_47) >= n else np.pad(X_47, (0, n-len(X_47)))
            Xi[0] = src[:n]
            Xs = m["scaler"].transform(Xi) if m["scaler"] else Xi
            raw = float(m["iso"].decision_function(Xs)[0])
            iso_s = float(np.clip(1.0 / (1.0 + np.exp(3.0 * raw)), 0.0, 1.0))
        except Exception as e:
            print(f"   IsoForest error: {e}")

    # Ensemble
    n_loaded = sum(1 for k in ["tcn","ae","iso"] if m.get(k))
    if n_loaded == 3:
        conf = tcn_s*0.50 + ae_s*0.25 + iso_s*0.25
    elif n_loaded == 2:
        vals = [s for s,k in [(tcn_s,"tcn"),(ae_s,"ae"),(iso_s,"iso")] if m.get(k)]
        conf = sum(vals)/len(vals)
    else:
        conf = tcn_s
    return tcn_s, ae_s, iso_s, float(np.clip(conf,0,1))


# ── HELPERS ───────────────────────────────────────────────────────────────────

MITRE = {
    "ddos":("Denial of Service","T1498"),"dos":("Denial of Service","T1498"),
    "brute_force":("Credential Access","T1110"),"botnet":("Command and Control","T1071"),
    "infiltration":("Exfiltration","T1041"),"web_attack":("Initial Access","T1190"),
    "port_scan":("Reconnaissance","T1046"),"malicious":("Command and Control","T1071.001"),
    "benign":("None","N/A"),
}
REASONS = {
    "ddos":       ["high_packets_per_second","syn_flood","ddos_pattern"],
    "dos":        ["high_packets_per_second","syn_flood","anomalous_flow"],
    "botnet":     ["high_packets_per_second","mlp_malicious","c2_beacon_pattern"],
    "brute_force":["high_packets_per_second","repeated_connection_attempts"],
    "port_scan":  ["high_packets_per_second","port_sweep_detected"],
    "web_attack": ["mlp_malicious","http_anomaly"],
    "infiltration":["high_packets_per_second","data_exfiltration"],
    "malicious":  ["syn_flood","mlp_malicious","anomalous_flow"],
    "benign":     ["normal_traffic"],
}
SRC_IPS = [f"192.168.{r}.{h}" for r in range(1,5) for h in range(100,120)]
DST_IPS = [f"10.0.0.{h}" for h in range(1,30)]

LABEL_MAP = {
    "dos":"dos","ddos":"ddos","brute_force":"brute_force","bruteforce":"brute_force",
    "botnet":"botnet","infiltration":"infiltration","web_attack":"web_attack",
    "port_scan":"port_scan","portscan":"port_scan","benign":"benign",
    "normal":"benign","0":"benign","1":"malicious"
}

def get_attack_type(row):
    if "attack_type" in row and pd.notna(row.get("attack_type")):
        return LABEL_MAP.get(str(row["attack_type"]).lower().strip(), str(row["attack_type"]).lower())
    if "label" in row and pd.notna(row.get("label")):
        lbl = str(row["label"]).strip()
        if lbl=="0": return "benign"
        if lbl=="1": return "malicious"
        return LABEL_MAP.get(lbl.lower(), lbl.lower())
    if "pcap_file" in row and pd.notna(row.get("pcap_file")):
        pf = str(row["pcap_file"]).lower()
        for k in ["botnet","ddos","dos","brute","infiltration","web","scan"]:
            if k in pf:
                return {"brute":"brute_force","web":"web_attack","scan":"port_scan"}.get(k,k)
    return "benign"


def build_event(row, at, tcn_s, ae_s, iso_s, conf):
    is_mal = at not in ("benign","normal")
    sev = "critical" if conf>=0.90 else "high" if conf>=0.75 else "medium" if conf>=0.55 else "low"
    src = str(row.get("src_ip","") or "").strip()
    dst = str(row.get("dst_ip","") or "").strip()
    if not src or src in ("0.0.0.0","nan",""): src = random.choice(SRC_IPS)
    if not dst or dst in ("0.0.0.0","nan",""): dst = random.choice(DST_IPS)
    fid = str(row.get("flow_id","") or "").strip()
    if not fid or fid=="nan":
        sp = int(row.get("src_port", random.randint(1024,65535)) or random.randint(1024,65535))
        dp = int(row.get("dst_port",443) or 443)
        proto = "TCP" if int(row.get("protocol",6) or 6)==6 else "UDP"
        fid = f"{src}:{sp}->{dst}:{dp}/{proto}"
    tactic, tech = MITRE.get(at, ("Unknown","T1071"))
    reasons = list(REASONS.get(at, ["anomalous_flow"]))
    pps = float(row.get("pps",0) or 0)
    if pps>500 and "high_packets_per_second" not in reasons:
        reasons.insert(0,"high_packets_per_second")
    return {
        "flow_id":fid,"label":"malicious" if is_mal else "benign",
        "confidence":round(conf,4),"risk_score":round(conf,4),"severity":sev,
        "attack_type":at if is_mal else "benign","source_ip":src,"destination_ip":dst,
        "mitre_tactic":tactic,"mitre_technique":tech,"reason":reasons,
        "blocked":is_mal and conf>=0.85,"anomaly_score":round(iso_s,4),
        "timestamp":datetime.now(timezone.utc).isoformat(),
        "total_packets":int(row.get("total_packets",100) or 100),
        "total_bytes":int(row.get("total_bytes",50000) or 50000),
        "duration":float(row.get("duration",1.0) or 1.0),"pps":pps,
        "metadata":{"tcn_score":round(tcn_s,4),"ae_score":round(ae_s,4),
                    "iso_score":round(iso_s,4),"ensemble":round(conf,4)}
    }


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    print("="*65)
    print("  ZeroTrust-AI — REAL ML ENSEMBLE INFERENCE")
    print("="*65)

    try:
        r = requests.get(f"{WS_SERVER}/metrics", timeout=3)
        if r.status_code!=200: raise Exception()
        print("✅ WebSocket server running\n")
    except:
        print("❌ Start websocket_server.py first"); sys.exit(1)

    print("🧠 Loading models...")
    m, device = load_models()
    n = sum(1 for k in ["tcn","ae","iso"] if m.get(k))
    print(f"\n{'✅' if n==3 else '⚠️'} {n}/3 models loaded")
    if n==0: print("❌ No models"); sys.exit(1)

    csv_path = next((p for p in CSV_CANDIDATES if os.path.exists(p)), None)
    if not csv_path: print("❌ No CSV found"); sys.exit(1)
    print(f"\n📂 {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"✅ {len(df):,} flows\n")

    df["_at"] = df.apply(get_attack_type, axis=1)
    ben = df[df["_at"].isin(["benign","normal"])].copy()
    att = df[~df["_at"].isin(["benign","normal"])].copy()
    print(f"📊 Benign:{len(ben):,}  Attacks:{len(att):,}")
    for at,cnt in att["_at"].value_counts().items(): print(f"   {at}:{cnt:,}")

    print(f"\n🚀 Streaming — Ctrl+C to stop")
    print(f"   {'#':>4}  {'Type':<15} {'TCN':>6} {'AE':>6} {'ISO':>6} {'ENS':>6}  {'SEV':<8}")
    print("   "+"─"*65)

    ap = att.sample(frac=1).reset_index(drop=True)
    bp = ben.sample(frac=1).reset_index(drop=True)
    ai=bi=sent=thr=ben_c=0

    try:
        while True:
            do_att = (random.random()<THREAT_RATIO) and len(ap)>0
            if do_att:
                row=ap.iloc[ai%len(ap)]; ai+=1; at=row["_at"]
            else:
                if len(bp)==0: continue
                row=bp.iloc[bi%len(bp)]; bi+=1; at="benign"

            tcn_s,ae_s,iso_s,conf = score_row(row, m, device)
            ev = build_event(row, at, tcn_s, ae_s, iso_s, conf)

            try:
                r=requests.post(f"{WS_SERVER}/detect",json=ev,timeout=5)
                ok=r.status_code in(200,201)
            except: ok=False

            sent+=1
            icon="🚨" if at!="benign" else "🌐"
            if at!="benign": thr+=1
            else: ben_c+=1

            st="✅" if ok else "❌"
            sev=ev["severity"].upper()
            print(f"{icon} {sent:>4} {st} {at:<15} {tcn_s:>6.3f} {ae_s:>6.3f} {iso_s:>6.3f} {conf:>6.3f}  {sev:<8}  {ev['flow_id'][:38]}")

            if sent%20==0:
                print(f"\n   📊 {sent} sent | {thr} threats | {ben_c} benign\n")
                print(f"   {'#':>4}  {'Type':<15} {'TCN':>6} {'AE':>6} {'ISO':>6} {'ENS':>6}  {'SEV':<8}")
                print("   "+"─"*65)

            time.sleep(DELAY)

    except KeyboardInterrupt:
        print(f"\n🛑 {sent} total | {thr} threats | {ben_c} benign")
        print(f"   TCN={m['tcn'] is not None} AE={m['ae'] is not None} ISO={m['iso'] is not None}")

if __name__=="__main__":
    main()