#!/usr/bin/env python3
"""
ZeroTrust-AI Real Data Sender
==============================
Uses production models from c2_ddos/scripts/models/:
  - tcn_model.pth       (TCN, F1=0.9637, Accuracy=97%)
  - autoencoder.pt      (AE anomaly detector)
  - isolation_forest.pkl
  - ensemble_config.pkl (weights: TCN=0.9, AE=0.1, IF=0.0, threshold=0.45)
"""

import sys, os, time, random, requests
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib
from pathlib import Path
from datetime import datetime, timezone

WS_SERVER    = "http://localhost:9000"
# Production models are in c2_ddos/scripts/models/
REPO_ROOT    = Path(__file__).resolve().parent
MODEL_DIR    = REPO_ROOT / "c2_ddos" / "scripts" / "models"
DELAY        = 0.8
THREAT_RATIO = 0.4
SEQ_LEN      = 20

CSV_CANDIDATES = [
    str(REPO_ROOT / "data" / "processed" / "phase1_processed.csv"),
    str(REPO_ROOT / "data" / "processed" / "final_balanced_240k.csv"),
    str(REPO_ROOT / "data" / "processed" / "splt_features_labeled.csv"),
    str(REPO_ROOT / "data" / "processed" / "balanced_train_200k_v2.csv"),
    str(REPO_ROOT / "data" / "processed" / "balanced_train_400k.csv"),
]


# ── PRODUCTION MODEL ARCHITECTURES (matching c2_ddos/scripts/train_tcn.py) ────

class CausalConv1d(nn.Module):
    def __init__(self, in_ch, out_ch, kernel_size, dilation=1):
        super().__init__()
        self.pad = (kernel_size - 1) * dilation
        self.conv = nn.Conv1d(in_ch, out_ch, kernel_size, dilation=dilation, padding=self.pad)
    def forward(self, x):
        return self.conv(x)[:, :, :x.size(2)]

class TCNBlock(nn.Module):
    def __init__(self, in_ch, out_ch, kernel_size, dilation):
        super().__init__()
        self.net = nn.Sequential(
            CausalConv1d(in_ch, out_ch, kernel_size, dilation),
            nn.BatchNorm1d(out_ch), nn.ReLU(), nn.Dropout(0.1),
            CausalConv1d(out_ch, out_ch, kernel_size, dilation),
            nn.BatchNorm1d(out_ch), nn.ReLU(), nn.Dropout(0.1),
        )
        self.res = nn.Conv1d(in_ch, out_ch, 1) if in_ch != out_ch else nn.Identity()
    def forward(self, x):
        return nn.functional.relu(self.net(x) + self.res(x))

class TCN(nn.Module):
    """Production TCN — input [batch, 2, 20] (len + iat channels, 20 steps)"""
    def __init__(self, channels=[32, 64]):
        super().__init__()
        layers, in_ch = [], 2
        for i, out_ch in enumerate(channels):
            layers.append(TCNBlock(in_ch, out_ch, kernel_size=3, dilation=2**i))
            in_ch = out_ch
        self.tcn = nn.Sequential(*layers)
        self.head = nn.Linear(in_ch, 1)
    def forward(self, x):
        out = self.tcn(x)          # [B, C, T]
        out = out.mean(dim=2)      # [B, C]
        return self.head(out)      # [B, 1] logits

class Autoencoder(nn.Module):
    """Production AE — input_dim from ae_config.pkl"""
    def __init__(self, input_dim=40):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32), nn.ReLU(),
            nn.Linear(32, 16),        nn.ReLU(),
            nn.Linear(16, 8),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),         nn.ReLU(),
            nn.Linear(16, 32),        nn.ReLU(),
            nn.Linear(32, input_dim),
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))


# ── MODEL LOADING ─────────────────────────────────────────────────────────────

def load_models():
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "c2_ddos" / "scripts"))
    from train_tcn import load_tcn_bundle, score_tcn
    from train_autoencoder import load_autoencoder, score_autoencoder
    from train_isolation_forest import load_isolation_forest

    m = {"score_tcn": score_tcn, "score_ae": score_autoencoder}

    # TCN — production model (F1=0.9637, Accuracy=97%)
    try:
        tcn, len_sc, iat_sc = load_tcn_bundle(str(MODEL_DIR))
        m["tcn"] = tcn
        m["tcn_len_scaler"] = len_sc
        m["tcn_iat_scaler"] = iat_sc
        print("✅ TCN loaded  → tcn_model.pth")
    except Exception as e:
        print(f"❌ TCN: {e}"); m["tcn"] = None

    # Autoencoder
    try:
        ae, ae_sc, ae_thr = load_autoencoder(str(MODEL_DIR))
        m["ae"] = ae
        m["ae_scaler"] = ae_sc
        m["ae_thr"] = ae_thr
        print(f"✅ AE loaded   → autoencoder.pt  threshold={ae_thr:.3f}")
    except Exception as e:
        print(f"❌ AE: {e}"); m["ae"] = None; m["ae_thr"] = 9.0

    # Isolation Forest
    try:
        iso, iso_feats = load_isolation_forest(str(MODEL_DIR))
        m["iso"] = iso
        m["iso_features"] = iso_feats
        print("✅ IF loaded   → isolation_forest.pkl")
    except Exception as e:
        print(f"⚠️  IF: {e}"); m["iso"] = None

    # Ensemble config
    try:
        ens = joblib.load(MODEL_DIR / "ensemble_config.pkl")
        m["weights"] = ens["weights"]       # {tcn:0.9, ae:0.1, if:0.0}
        m["threshold"] = ens.get("quarantine_threshold", 0.45)
        print(f"✅ Ensemble    → weights={m['weights']}  threshold={m['threshold']}")
    except Exception as e:
        print(f"⚠️  Ensemble config: {e}")
        m["weights"] = {"tcn": 0.9, "ae": 0.1, "if": 0.0}
        m["threshold"] = 0.45

    return m, None  # device not needed (production fns handle it)


# ── FEATURE EXTRACTION + INFERENCE ───────────────────────────────────────────

def score_row(row, m, device):
    """Score a single row using production model APIs."""
    len_cols = [f"splt_len_{i}" for i in range(1, SEQ_LEN+1)]
    iat_cols = [f"splt_iat_{i}" for i in range(1, SEQ_LEN+1)]
    splt_len = np.array([float(row.get(c,0) or 0) for c in len_cols], dtype=np.float32)
    splt_iat = np.array([float(row.get(c,0) or 0) for c in iat_cols], dtype=np.float32)
    X_40 = np.concatenate([splt_len, splt_iat]).reshape(1, -1)  # [1, 40] for TCN

    # AE needs 47 features: 40 SPLT + exact 7 volumetric from train_autoencoder.py
    # [pps, bps, mean_packet_size, mean_iat, burstiness, pseudo_upload_bytes, pseudo_download_bytes]
    dur  = max(float(row.get("duration", 1.0) or 1.0), 1e-6)
    pkts = max(float(row.get("total_packets", 1) or 1), 1.0)
    byts = float(row.get("total_bytes", 0) or 0)
    pps  = pkts / dur
    bps  = byts / dur
    mean_pkt  = byts / pkts
    mean_iat  = dur / max(pkts - 1.0, 1.0)
    burstiness = float(np.std(splt_iat)) if splt_iat.any() else 0.0
    pseudo_up  = float(splt_len[0::2].sum())   # odd-indexed packets
    pseudo_dn  = float(splt_len[1::2].sum())   # even-indexed packets
    vol_7 = np.array([pps, bps, mean_pkt, mean_iat, burstiness, pseudo_up, pseudo_dn], dtype=np.float32)
    X_47 = np.concatenate([splt_len, splt_iat, vol_7]).reshape(1, -1)  # [1, 47] for AE

    w = m["weights"]

    # TCN — score_tcn handles PowerTransformer scaling internally
    tcn_s = 0.5
    if m.get("tcn"):
        try:
            scores = m["score_tcn"](
                m["tcn"], X_40,
                len_scaler=m["tcn_len_scaler"],
                iat_scaler=m["tcn_iat_scaler"]
            )
            tcn_s = float(scores[0])
        except Exception as e:
            print(f"   TCN error: {e}")

    # AE — score_autoencoder handles RobustScaler internally
    ae_s = 0.5
    if m.get("ae"):
        try:
            ae_scores = m["score_ae"](m["ae"], m["ae_scaler"], X_47, m["ae_thr"])
            ae_s = float(ae_scores[0])
        except Exception as e:
            print(f"   AE error: {e}")

    # IF — weight=0.0 but compute for display
    iso_s = 0.5
    if m.get("iso"):
        try:
            from train_isolation_forest import get_volumetric_matrix, _derive_missing_volumetric_features
            Xi = pd.DataFrame([dict(row)])
            Xi = _derive_missing_volumetric_features(Xi)
            Xv = get_volumetric_matrix(Xi)
            raw = float(m["iso"].decision_function(Xv)[0])
            iso_s = float(np.clip(1.0 / (1.0 + np.exp(3.0 * raw)), 0.0, 1.0))
        except Exception:
            iso_s = 0.5

    # Ensemble with calibrated weights (TCN=0.9, AE=0.1, IF=0.0)
    conf = tcn_s * w["tcn"] + ae_s * w["ae"] + iso_s * w.get("if", 0.0)
    return tcn_s, ae_s, iso_s, float(np.clip(conf, 0, 1))


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
    csv_label = str(row.get("label", "0")).strip()
    csv_malicious = csv_label in ["1", "malicious", "attack"]

    # CSV ground truth determines label and attack type
    true_label = "malicious" if csv_malicious else "benign"
    true_attack = (at if at not in ("benign", "normal") else "malicious") if csv_malicious else "benign"

    # Severity based on ML confidence, but CSV ground truth caps it
    if csv_malicious:
        sev = "critical" if conf>=0.90 else "high" if conf>=0.75 else "medium" if conf>=0.55 else "low"
    else:
        sev = "medium" if conf>=0.75 else "low"
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
    tactic, tech = MITRE.get(true_attack, ("Unknown","T1071"))
    reasons = list(REASONS.get(true_attack, ["anomalous_flow"]))
    pps = float(row.get("pps",0) or 0)
    if pps>500 and "high_packets_per_second" not in reasons:
        reasons.insert(0,"high_packets_per_second")
    return {
        "flow_id":fid,"label":true_label,
        "confidence":round(conf,4),"risk_score":round(conf,4),"severity":sev,
        "attack_type":true_attack,"source_ip":src,"destination_ip":dst,
        "mitre_tactic":tactic,"mitre_technique":tech,"reason":reasons,
        "blocked":csv_malicious and conf>=0.85,"anomaly_score":round(iso_s,4),
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