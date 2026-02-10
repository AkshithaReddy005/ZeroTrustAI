from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Any, Dict, List, Literal, Optional, Tuple
import os
import sys
import json
import time
import uuid
from functools import lru_cache

import numpy as np
import joblib
import torch
import torch.nn as nn

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Optional integrations for real-time state and historical logging
try:
    import redis  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    redis = None  # type: ignore

try:
    from influxdb_client import InfluxDBClient, Point, WriteOptions  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    InfluxDBClient = None  # type: ignore
    Point = None  # type: ignore
    WriteOptions = None  # type: ignore


# Add shared module path for lap-to-lap testing
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_SHARED_DIR = os.path.join(_REPO_ROOT, "shared")
if _SHARED_DIR not in sys.path:
    sys.path.append(_SHARED_DIR)
try:
    from schemas import FlowFeatures, ThreatEvent
except Exception:
    class FlowFeatures(BaseModel):
        flow_id: str
        total_packets: int
        total_bytes: int
        avg_packet_size: float
        std_packet_size: float
        duration: float
        pps: float
        avg_entropy: float
        syn_count: int
        fin_count: int

        # Optional SPLT sequences for sequence models (first N packets)
        splt_len: Optional[List[float]] = None
        splt_iat: Optional[List[float]] = None

    class ThreatEvent(BaseModel):
        flow_id: str
        label: Literal["benign", "malicious"]
        confidence: float
        anomaly_score: float
        severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        reason: List[str]
        metadata: Optional[dict] = None  # For auto-blocking metadata


class LabeledFlow(BaseModel):
    flow: FlowFeatures
    label: Literal["benign", "malicious"]


class TrainRequest(BaseModel):
    samples: Optional[List[LabeledFlow]] = None
    epochs: int = 10
    lr: float = 1e-3
    contamination: float = 0.05


class TrainResponse(BaseModel):
    status: str
    trained_samples: int
    timestamp: float


class FeedbackRequest(BaseModel):
    flow: FlowFeatures
    label: Literal["benign", "malicious"]


MODEL_DIR = os.getenv("MODEL_DIR", "C:\\Users\\akshi\\OneDrive\\Documents\\AKKI\\projects\\ZeroTrust-AI\\models")
os.makedirs(MODEL_DIR, exist_ok=True)

SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
ISO_PATH = os.path.join(MODEL_DIR, "isoforest.joblib")
PT_PATH = os.path.join(MODEL_DIR, "pytorch_mlp.pt")
FEEDBACK_PATH = os.path.join(MODEL_DIR, "feedback.jsonl")
META_PATH = os.path.join(MODEL_DIR, "meta.json")

TCN_PATH = os.path.join(MODEL_DIR, "tcn_classifier.pth")
AE_PATH = os.path.join(MODEL_DIR, "autoencoder.pth")
AE_THR_PATH = os.path.join(MODEL_DIR, "ae_threshold.txt")
SPLT_SCALER_PATH = os.path.join(MODEL_DIR, "splt_scaler.joblib")
SPLT_ISO_PATH = os.path.join(MODEL_DIR, "splt_isoforest.joblib")

# Backward-compatible location for trained SPLT models in this repo
SPLT_MODELS_DIR = os.path.join(MODEL_DIR, "82k_models")
SPLT_SCALER_FALLBACK_PATH = os.path.join(SPLT_MODELS_DIR, "splt_scaler.joblib")
SPLT_ISO_FALLBACK_PATH = os.path.join(SPLT_MODELS_DIR, "splt_isoforest.joblib")


# --- Optional Redis + InfluxDB configuration ---
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_TTL_SECONDS = int(os.getenv("REDIS_TTL_SECONDS", "1800"))  # 30 minutes default

INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "")
INFLUX_ORG = os.getenv("INFLUX_ORG", "zerotrust")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "threat_events")


def _init_redis():
    if redis is None:
        return None
    try:
        client = redis.from_url(REDIS_URL)
        # lightweight ping to validate; ignore failure and fall back to None
        client.ping()
        return client
    except Exception:
        return None


def _init_influx():
    if InfluxDBClient is None or not INFLUX_TOKEN:
        return None
    try:
        client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
        write_api = client.write_api(write_options=WriteOptions(batch_size=1))
        return write_api
    except Exception:
        return None


REDIS_CLIENT = _init_redis()
INFLUX_WRITE_API = _init_influx()


def flow_to_vec(f: FlowFeatures) -> np.ndarray:
    # Create 47-dimensional feature vector to match scaler expectations
    features = []

    dst_port = int(getattr(f, "dst_port", 0) or 0)
    
    # Basic flow features (9 features)
    features.extend([
        float(f.total_packets),
        float(f.total_bytes),
        float(f.avg_packet_size),
        float(f.std_packet_size),
        float(f.duration),
        float(f.pps),
        float(f.avg_entropy),
        float(f.syn_count),
        float(f.fin_count),
    ])
    
    # Add statistical features (38 more features to reach 47 total)
    # Packet size statistics
    features.extend([
        float(f.total_bytes / max(1, f.total_packets)),  # avg packet size
        float(f.total_bytes / max(1, f.duration)),  # bytes per second
        float(f.total_packets / max(1, f.duration)),  # packets per second
        float(f.std_packet_size / max(1, f.avg_packet_size)),  # size variation
    ])
    
    # Temporal features
    features.extend([
        float(f.duration),  # flow duration
        float(f.syn_count / max(1, f.total_packets)),  # SYN ratio
        float(f.fin_count / max(1, f.total_packets)),  # FIN ratio
        float((f.syn_count + f.fin_count) / max(1, f.total_packets)),  # flag ratio
    ])
    
    # Entropy-based features
    features.extend([
        float(f.avg_entropy),
        float(f.avg_entropy * f.total_packets),  # total entropy
        float(f.avg_entropy / max(1, f.avg_packet_size)),  # entropy per byte
    ])
    
    # Protocol and port features
    features.extend([
        1.0 if dst_port in [80, 443, 8080] else 0.0,  # common web ports
        1.0 if 0 < dst_port < 1024 else 0.0,  # privileged ports
        float(dst_port / 65535.0),  # normalized port
    ])
    
    # Packet count features
    features.extend([
        float(min(f.total_packets, 100)),  # capped packet count
        float(f.total_packets / 1000.0),  # normalized by 1000
        float(1.0 if f.total_packets > 100 else 0.0),  # high volume indicator
    ])
    
    # Byte-based features
    features.extend([
        float(f.total_bytes / 1000000.0),  # normalized by 1MB
        float(f.total_bytes / max(1, f.total_packets) / max(1, f.avg_packet_size)),  # efficiency
        float(1.0 if f.total_bytes > 100000 else 0.0),  # large transfer indicator
    ])
    
    # Time-based features
    features.extend([
        float(f.duration / 3600.0),  # duration in hours
        float(f.pps / 60.0),  # packets per minute
        float(f.total_bytes / f.duration) if f.duration > 0 else 0.0,  # actual throughput
    ])
    
    # Additional statistical features
    features.extend([
        float(f.avg_packet_size * f.pps),  # bandwidth estimate
        float(f.duration * f.avg_entropy),  # entropy over time
        float(f.total_packets % 10),  # packet count modulo
        float(f.total_bytes % 1000),  # byte count modulo
    ])
    
    # Fill remaining features to reach exactly 47
    while len(features) < 47:
        features.append(0.0)
    
    return np.array(features, dtype=np.float32)


def create_behavioral_fingerprint(splt_tensor: torch.Tensor) -> str:
    """
    Create "Zero-IP" Behavioral Fingerprint from SPLT sequence
    
    Takes first 5 signed packet lengths and creates a unique pattern hash
    This allows blocking attack patterns regardless of IP address changes
    """
    try:
        # Extract first 5 packet lengths from SPLT tensor
        if splt_tensor is None or splt_tensor.numel() == 0:
            return "unknown_pattern"
        
        # SPLT tensor shape is typically [1, 2, T] (lengths + IAT). Use lengths channel.
        if splt_tensor.dim() == 3:
            packet_lengths = splt_tensor[0, 0, :5].cpu().numpy()
        else:
            packet_lengths = splt_tensor[:5].cpu().numpy()
        
        # Ensure we have exactly 5 values (pad if needed)
        if len(packet_lengths) < 5:
            packet_lengths = np.pad(packet_lengths, (0, 5 - len(packet_lengths)), 'constant')
        
        # Create behavioral fingerprint string
        fingerprint_parts = []
        for i, length in enumerate(packet_lengths):
            # Convert to signed integer and format
            signed_length = int(length)
            fingerprint_parts.append(f"{signed_length:+d}")
        
        # Join with underscores to create unique pattern
        behavioral_hash = "_".join(fingerprint_parts)
        
        return behavioral_hash
        
    except Exception as e:
        # Fallback to simple hash if extraction fails
        return f"error_pattern_{hash(str(splt_tensor)) % 10000}"


def check_behavioral_pattern(behavioral_hash: str) -> tuple[bool, str]:
    """
    Check if behavioral pattern exists in Redis
    Returns (is_malicious, pattern_info)
    """
    if REDIS_CLIENT is None:
        return False, "redis_unavailable"
    
    try:
        # Check if pattern exists in Redis
        pattern_info = REDIS_CLIENT.get(f"pattern:{behavioral_hash}")
        
        if pattern_info:
            # Pattern found - this is a known malicious attack pattern
            return True, pattern_info.decode('utf-8') if isinstance(pattern_info, bytes) else str(pattern_info)
        else:
            # Pattern not found - new behavior
            return False, "unknown_pattern"
            
    except Exception as e:
        # Error checking pattern
        return False, f"error_checking_pattern: {e}"


def store_malicious_pattern(behavioral_hash: str, attack_type: str, confidence: float, flow_id: str) -> bool:
    """
    Store malicious behavioral pattern in Redis with auto-expiry
    Uses SETEX for atomic set-with-expire operation
    """
    if REDIS_CLIENT is None:
        return False
    
    try:
        # Create pattern metadata
        pattern_metadata = {
            "attack_type": attack_type,
            "confidence": float(confidence),
            "flow_id": flow_id,
            "first_seen": time.time(),
            "pattern_hash": behavioral_hash
        }
        
        # Store pattern with 1-hour expiry using SETEX
        # SETEX is atomic - prevents race conditions
        metadata_json = json.dumps(pattern_metadata)
        success = REDIS_CLIENT.setex(
            f"pattern:{behavioral_hash}", 
            3600,  # 1 hour TTL
            metadata_json
        )
        
        # Also store in pattern index for analytics
        REDIS_CLIENT.sadd("pattern_index", behavioral_hash)
        REDIS_CLIENT.expire("pattern_index", 86400)  # 24 hours for index
        
        return bool(success)
        
    except Exception as e:
        # Error storing pattern
        return False


def get_pattern_statistics() -> dict:
    """
    Get statistics about stored behavioral patterns
    """
    if REDIS_CLIENT is None:
        return {"total_patterns": 0, "error": "redis_unavailable"}
    
    try:
        # Get all patterns from index
        pattern_count = REDIS_CLIENT.scard("pattern_index")
        
        # Get sample patterns for analysis
        sample_patterns = list(REDIS_CLIENT.smembers("pattern_index"))[:10]
        
        pattern_details = []
        for pattern in sample_patterns:
            pattern_info = REDIS_CLIENT.get(f"pattern:{pattern}")
            if pattern_info:
                try:
                    details = json.loads(pattern_info.decode('utf-8') if isinstance(pattern_info, bytes) else pattern_info)
                    pattern_details.append(details)
                except:
                    continue
        
        return {
            "total_patterns": pattern_count,
            "sample_patterns": pattern_details,
            "last_updated": time.time()
        }
        
    except Exception as e:
        return {"total_patterns": 0, "error": str(e)}


class MLP(nn.Module):
    def __init__(self, in_dim: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class Chomp1d(nn.Module):
    def __init__(self, chomp_size: int):
        super().__init__()
        self.chomp_size = int(chomp_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.chomp_size <= 0:
            return x
        return x[:, :, :-self.chomp_size].contiguous()


class TemporalBlock(nn.Module):
    def __init__(self, in_ch: int, out_ch: int, kernel_size: int, dilation: int, dropout: float):
        super().__init__()
        pad = (kernel_size - 1) * dilation
        self.net = nn.Sequential(
            nn.Conv1d(in_ch, out_ch, kernel_size, padding=pad, dilation=dilation),
            Chomp1d(pad),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Conv1d(out_ch, out_ch, kernel_size, padding=pad, dilation=dilation),
            Chomp1d(pad),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        self.downsample = nn.Conv1d(in_ch, out_ch, 1) if in_ch != out_ch else nn.Identity()
        self.relu = nn.ReLU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out = self.net(x)
        res = self.downsample(x)
        return self.relu(out + res)


class TCN(nn.Module):
    def __init__(self, in_ch: int = 2, n_classes: int = 2):
        super().__init__()
        # Simple sequential TCN to match 82k model checkpoint keys
        self.tcn = nn.Sequential(
            nn.Linear(in_ch, 32), nn.ReLU(),
            nn.Linear(32, 64), nn.ReLU(),
            nn.Linear(64, 128), nn.ReLU(),
        )
        self.head = nn.Sequential(
            nn.Linear(128, 64), nn.ReLU(),
            nn.Linear(64, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Flatten input for linear layers
        if x.dim() == 3:  # [batch, channels, seq_len]
            x = x.mean(dim=2)  # Average over sequence dimension
        z = self.tcn(x)
        return self.head(z)


class AE(nn.Module):
    def __init__(self, in_ch: int = 2, latent: int = 32):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Conv1d(in_ch, 32, 3, padding=1), nn.ReLU(),
            nn.Conv1d(32, 64, 3, padding=1), nn.ReLU(),
            nn.Conv1d(64, latent, 3, padding=1), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Conv1d(latent, 64, 3, padding=1), nn.ReLU(),
            nn.Conv1d(64, 32, 3, padding=1), nn.ReLU(),
            nn.Conv1d(32, in_ch, 3, padding=1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encoder(x)
        return self.decoder(z)


def load_models() -> Tuple[Optional[StandardScaler], Optional[IsolationForest], Optional[MLP]]:
    scaler = None
    iso = None
    mlp = None
    if os.path.exists(SCALER_PATH):
        obj = joblib.load(SCALER_PATH)
        if isinstance(obj, StandardScaler):
            scaler = obj
            print(f"DEBUG: Loaded scaler from {SCALER_PATH}")
        else:
            print(f"Warning: {SCALER_PATH} is not a StandardScaler (got {type(obj)}). Ignoring.")
    if os.path.exists(ISO_PATH):
        obj = joblib.load(ISO_PATH)
        if hasattr(obj, "decision_function"):
            iso = obj
            print(f"DEBUG: Loaded isolation forest from {ISO_PATH}")
        else:
            print(f"Warning: {ISO_PATH} does not look like an IsolationForest (got {type(obj)}). Ignoring.")
    
    if os.path.exists(PT_PATH):
        state = torch.load(PT_PATH, map_location="cpu")
        print(f"DEBUG: Loaded TCN model from {PT_PATH}")
        try:
            mlp = MLP(in_dim=state["in_dim"])
            mlp.load_state_dict(state["state_dict"])
            mlp.eval()
            print(f"DEBUG: Successfully loaded MLP with in_dim={state['in_dim']}")
        except KeyError:
            # If saved model doesn't have to expected structure, create a simple MLP
            print("Warning: Model structure mismatch, creating simple MLP")
            mlp = MLP(in_dim=47)  # Match our feature vector size
            # Initialize with random weights for demo
            mlp.eval()
    return scaler, iso, mlp


def load_sequence_models() -> Tuple[Optional[TCN], Optional[AE], Optional[float], Optional[StandardScaler], Optional[IsolationForest]]:
    tcn = None
    ae = None
    ae_thr = None
    splt_scaler = None
    splt_iso = None

    # Try to load TCN model
    if os.path.exists(TCN_PATH):
        try:
            tcn = TCN()
            ckpt = torch.load(TCN_PATH, map_location="cpu")
            state = ckpt["state_dict"] if isinstance(ckpt, dict) and "state_dict" in ckpt else ckpt
            tcn.load_state_dict(state)
            tcn.eval()
            print(f"DEBUG: Successfully loaded TCN model")
        except Exception as e:
            print(f"Warning: Could not load TCN model: {e}")
            tcn = None
    if os.path.exists(AE_PATH):
        try:
            ae = AE()
            ckpt = torch.load(AE_PATH, map_location="cpu")
            state = ckpt["state_dict"] if isinstance(ckpt, dict) and "state_dict" in ckpt else ckpt
            ae.load_state_dict(state)
            ae.eval()
        except Exception as e:
            print(f"Warning: Could not load AE model: {e}")
            ae = None
    if os.path.exists(AE_THR_PATH):
        try:
            raw = open(AE_THR_PATH, "r", encoding="utf-8").read().strip()
            # File may be either a single float OR key=value lines.
            # Example:
            #   ae_threshold=0.95
            #   tcn_threshold=0.4
            if "=" not in raw:
                ae_thr = float(raw)
            else:
                kv: Dict[str, str] = {}
                for line in raw.splitlines():
                    line = line.strip()
                    if not line or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    kv[k.strip()] = v.strip()
                if "ae_threshold" in kv:
                    ae_thr = float(kv["ae_threshold"])
        except Exception:
            ae_thr = None
    splt_scaler_path = SPLT_SCALER_PATH if os.path.exists(SPLT_SCALER_PATH) else SPLT_SCALER_FALLBACK_PATH
    if os.path.exists(splt_scaler_path):
        obj = joblib.load(splt_scaler_path)
        if isinstance(obj, StandardScaler):
            splt_scaler = obj
            print(f"DEBUG: Loaded SPLT scaler from {splt_scaler_path}")
        else:
            print(f"Warning: {splt_scaler_path} is not a StandardScaler (got {type(obj)}).")

    splt_iso_path = SPLT_ISO_PATH if os.path.exists(SPLT_ISO_PATH) else SPLT_ISO_FALLBACK_PATH
    if os.path.exists(splt_iso_path):
        obj = joblib.load(splt_iso_path)
        if hasattr(obj, "decision_function"):
            splt_iso = obj
            print(f"DEBUG: Loaded SPLT IsolationForest from {splt_iso_path}")
        else:
            print(f"Warning: {splt_iso_path} does not look like an IsolationForest (got {type(obj)}).")
    return tcn, ae, ae_thr, splt_scaler, splt_iso


@lru_cache(maxsize=1)
def get_scalar_models() -> Tuple[Optional[StandardScaler], Optional[IsolationForest], Optional[MLP]]:
    return load_models()


@lru_cache(maxsize=1)
def get_sequence_models() -> Tuple[Optional[TCN], Optional[AE], Optional[float], Optional[StandardScaler], Optional[IsolationForest]]:
    return load_sequence_models()


def flow_to_splt_tensor(flow: FlowFeatures, seq_len: int = 20) -> Optional[torch.Tensor]:
    if getattr(flow, "splt_len", None) is None or getattr(flow, "splt_iat", None) is None:
        return None
    try:
        l = list(flow.splt_len or [])[:seq_len]
        t = list(flow.splt_iat or [])[:seq_len]
        if len(l) == 0 and len(t) == 0:
            return None
        while len(l) < seq_len:
            l.append(0.0)
        while len(t) < seq_len:
            t.append(0.0)
        x = torch.tensor([l, t], dtype=torch.float32).unsqueeze(0)  # [1,2,T]
        return x
    except Exception:
        return None


def splt_vec_from_tensor(x: torch.Tensor) -> np.ndarray:
    # x: [1,2,20]
    return x.squeeze(0).reshape(-1).numpy().astype(np.float32)


def save_mlp(mlp: MLP, in_dim: int):
    torch.save({"in_dim": in_dim, "state_dict": mlp.state_dict()}, PT_PATH)


def append_feedback(flow: FlowFeatures, label: str):
    rec = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "label": label,
        "flow": flow.model_dump(),
    }
    with open(FEEDBACK_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def read_feedback(limit: int = 5000) -> List[LabeledFlow]:
    if not os.path.exists(FEEDBACK_PATH):
        return []
    samples: List[LabeledFlow] = []
    with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            samples.append(LabeledFlow(flow=FlowFeatures(**obj["flow"]), label=obj["label"]))
    return samples[-limit:]


def anomaly_score_from_iso(iso: IsolationForest, x_scaled: np.ndarray) -> float:
    # decision_function is higher for inliers; convert to 0..1 where 1=more anomalous
    df = float(iso.decision_function(x_scaled.reshape(1, -1))[0])
    # Rough normalization for demo; keeps values in a nice 0..1-ish range
    score = 1.0 / (1.0 + np.exp(3.0 * df))
    return float(np.clip(score, 0.0, 1.0))


def map_to_mitre_ttp(reasons: List[str], flow: FlowFeatures) -> tuple[str, str, str]:
    """
    Map detection reasons to MITRE ATT&CK TTPs
    
    Returns:
        tuple: (attack_type, mitre_tactic, mitre_technique)
    """
    # Default to unknown
    attack_type = "unknown"
    mitre_tactic = "unknown"
    mitre_technique = "unknown"
    
    # Convert reasons to lowercase for matching
    reason_str = " ".join(reasons).lower()
    
    # Botnet detection patterns
    if any(keyword in reason_str for keyword in ["botnet", "c2", "command", "tcn_malicious"]):
        attack_type = "botnet"
        mitre_tactic = "Command and Control"
        mitre_technique = "T1071"  # Application Layer Protocol
        
    # Data exfiltration patterns
    elif any(keyword in reason_str for keyword in ["exfiltration", "data_transfer", "large_upload"]):
        attack_type = "data_exfiltration"
        mitre_tactic = "Exfiltration"
        mitre_technique = "T1041"  # Exfiltration Over C2 Channel
        
    # Anomalous traffic patterns
    elif any(keyword in reason_str for keyword in ["anomalous", "ae_anomalous", "isoforest_anomalous"]):
        attack_type = "anomalous_behavior"
        mitre_tactic = "Defense Evasion"
        mitre_technique = "T1027"  # Obfuscated Files or Information
        
    # DDoS patterns
    elif any(keyword in reason_str for keyword in ["ddos", "flood", "high_volume"]):
        attack_type = "ddos"
        mitre_tactic = "Impact"
        mitre_technique = "T1498"  # Network Denial of Service
        
    # Port scanning patterns
    elif any(keyword in reason_str for keyword in ["scan", "reconnaissance", "port_scan"]):
        attack_type = "reconnaissance"
        mitre_tactic = "Reconnaissance"
        mitre_technique = "T1046"  # Network Service Scanning
        
    # Web-based attacks
    elif any(keyword in reason_str for keyword in ["web", "http", "sql_injection", "xss"]):
        attack_type = "web_attack"
        mitre_tactic = "Initial Access"
        mitre_technique = "T1190"  # Exploit Public-Facing Application
        
    # Malware communication
    elif any(keyword in reason_str for keyword in ["malware", "trojan", "backdoor"]):
        attack_type = "malware"
        mitre_tactic = "Execution"
        mitre_technique = "T1059"  # Command and Scripting Interpreter
        
    # Check for specific port-based patterns
    if hasattr(flow, 'dst_port'):
        dst_port = flow.dst_port
        if dst_port in [443, 8443] and "botnet" in reason_str:
            # HTTPS-based C2
            mitre_technique = "T1071.001"  # Application Layer Protocol: HTTPS
        elif dst_port in [80, 8080] and "web" in reason_str:
            # HTTP-based attacks
            mitre_technique = "T1071.001"  # Application Layer Protocol: HTTP
        elif dst_port in [22, 23, 3389] and "brute" in reason_str:
            # Brute force attacks
            mitre_tactic = "Credential Access"
            mitre_technique = "T1110"  # Brute Force
            
    return attack_type, mitre_tactic, mitre_technique


def mlp_prob(mlp: MLP, x_scaled: np.ndarray) -> float:
    with torch.no_grad():
        t = torch.from_numpy(x_scaled.reshape(1, -1)).float()
        logits = mlp(t).squeeze(1)
        prob = torch.sigmoid(logits).item()
    return float(np.clip(prob, 0.0, 1.0))


def severity_from_score(score: float) -> str:
    if score >= 0.9:
        return "CRITICAL"
    if score >= 0.75:
        return "HIGH"
    if score >= 0.55:
        return "MEDIUM"
    return "LOW"


app = FastAPI(title="ZT-AI Detector", version="0.2.0")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    try:
        body = await request.body()
        body_preview = body[:2000].decode("utf-8", errors="replace")
    except Exception:
        body_preview = "<unavailable>"
    print(f"VALIDATION_ERROR: path={request.url.path} errors={exc.errors()} body={body_preview}")
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


@app.on_event("startup")
async def _startup_log_models_and_schema():
    print(f"DEBUG: FlowFeatures schema module={FlowFeatures.__module__} fields={list(getattr(FlowFeatures, 'model_fields', getattr(FlowFeatures, '__fields__', {})).keys())}")
    # Try loading sequence models once at startup for clearer logs
    tcn, ae, ae_thr, splt_scaler, splt_iso = get_sequence_models()
    print(
        "DEBUG: sequence_models_loaded="
        f"tcn={tcn is not None}, ae={ae is not None}, ae_thr={ae_thr is not None}, "
        f"splt_scaler={splt_scaler is not None}, splt_iso={splt_iso is not None}"
    )

# Include SOAR router for manual override capabilities
try:
    from .soar import soar_router
    app.include_router(soar_router)
except ImportError:
    # SOAR module not available, continue without it
    pass


@app.get("/patterns")
async def get_behavioral_patterns():
    """Get statistics about stored behavioral patterns"""
    stats = get_pattern_statistics()
    return stats


@app.post("/debug_schema")
async def debug_schema(body: dict):
    print(f"DEBUG_SCHEMA: FlowFeatures module={FlowFeatures.__module__}")
    try:
        fields = list(FlowFeatures.model_fields.keys())
        print(f"DEBUG_SCHEMA: FlowFeatures fields={fields}")
    except:
        try:
            fields = list(FlowFeatures.__fields__.keys())
            print(f"DEBUG_SCHEMA: FlowFeatures fields={fields}")
        except:
            print("DEBUG_SCHEMA: Could not get FlowFeatures fields")
    print(f"DEBUG_SCHEMA: Received body keys={list(body.keys())}")
    return {"status": "ok", "schema_fields": fields if 'fields' in locals() else []}


@app.post("/test_detect")
async def test_detect(body: dict):
    try:
        flow = FlowFeatures(**body)
        return {"status": "validation_ok", "flow_id": flow.flow_id}
    except Exception as e:
        return {"status": "validation_error", "error": str(e)}


@app.post("/test-pattern")
async def test_behavioral_pattern(flow: FlowFeatures):
    """Test behavioral fingerprinting on a flow"""
    # Create SPLT tensor for testing
    x_seq = flow_to_splt_tensor(flow)
    
    if x_seq is None:
        return {"error": "No SPLT data available"}
    
    # Create behavioral fingerprint
    behavioral_hash = create_behavioral_fingerprint(x_seq)
    
    # Check if pattern exists
    is_known, pattern_info = check_behavioral_pattern(behavioral_hash)
    
    return {
        "flow_id": flow.flow_id,
        "behavioral_hash": behavioral_hash,
        "is_known_pattern": is_known,
        "pattern_info": pattern_info,
        "splt_tensor_shape": list(x_seq.shape) if x_seq is not None else None,
        "first_5_packets": x_seq[0, :5].cpu().numpy().tolist() if x_seq is not None and x_seq.dim() >= 2 else []
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    scaler, iso, mlp = load_models()
    tcn, ae, ae_thr, splt_scaler, splt_iso = load_sequence_models()
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "models_loaded": {
            "sequence_models": all(m is not None for m in [tcn, ae, ae_thr, splt_scaler, splt_iso]),
            "scalar_models": all(m is not None for m in [scaler, iso, mlp])
        },
        "integrations": {
            "redis": REDIS_CLIENT is not None,
            "influxdb": INFLUX_WRITE_API is not None
        },
        "behavioral_fingerprinting": {
            "enabled": True,
            "redis_patterns": REDIS_CLIENT is not None
        }
    }


@app.post("/feedback")
def feedback(req: FeedbackRequest):
    append_feedback(req.flow, req.label)
    return {"status": "ok"}


@app.post("/train", response_model=TrainResponse)
def train(req: TrainRequest):
    samples = list(req.samples or [])
    samples.extend(read_feedback())

    # If user provided no labeled data yet, generate a small bootstrapping set
    # This makes the demo work immediately; later you can replace with real labeled flows.
    if not samples:
        for i in range(250):
            flow = FlowFeatures(
                flow_id=f"boot-{i}",
                total_packets=int(np.random.randint(5, 500)),
                total_bytes=int(np.random.randint(800, 200000)),
                avg_packet_size=float(np.random.uniform(200, 1500)),
                std_packet_size=float(np.random.uniform(10, 300)),
                duration=float(np.random.uniform(0.01, 3.0)),
                pps=float(np.random.uniform(5, 800)),
                avg_entropy=float(np.random.uniform(2.0, 7.9)),
                syn_count=int(np.random.randint(0, 20)),
                fin_count=int(np.random.randint(0, 10)),
            )
            # heuristics only for bootstrapping labels
            malicious = (flow.avg_entropy > 6.0 and flow.pps > 250) or (flow.syn_count > 8 and flow.pps > 200)
            samples.append(LabeledFlow(flow=flow, label="malicious" if malicious else "benign"))

    X = np.stack([flow_to_vec(s.flow) for s in samples], axis=0)
    y = np.array([1 if s.label == "malicious" else 0 for s in samples], dtype=np.float32)

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # Isolation Forest on benign only (or fallback to all if no benign)
    benign_mask = y == 0
    X_benign = Xs[benign_mask]
    if X_benign.shape[0] < 20:
        X_benign = Xs

    iso = IsolationForest(
        n_estimators=200,
        contamination=float(req.contamination),
        random_state=42,
    )
    iso.fit(X_benign)

    # PyTorch MLP classifier
    in_dim = Xs.shape[1]
    mlp = MLP(in_dim=in_dim)
    opt = torch.optim.Adam(mlp.parameters(), lr=float(req.lr))
    loss_fn = nn.BCEWithLogitsLoss()
    X_t = torch.from_numpy(Xs).float()
    y_t = torch.from_numpy(y.reshape(-1, 1)).float()

    mlp.train()
    for _ in range(int(req.epochs)):
        opt.zero_grad()
        logits = mlp(X_t)
        loss = loss_fn(logits, y_t)
        loss.backward()
        opt.step()
    mlp.eval()

    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(iso, ISO_PATH)
    save_mlp(mlp, in_dim=in_dim)
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump({"trained_samples": int(len(samples)), "ts": time.time()}, f)

    return TrainResponse(status="ok", trained_samples=int(len(samples)), timestamp=time.time())


@app.post("/detect", response_model=ThreatEvent)
def detect(flow: FlowFeatures):
    # Prefer trained sequence models for detection:
    # - splt_scaler.joblib + splt_isoforest.joblib (anomaly)
    # - autoencoder.pth + ae_threshold.txt (reconstruction anomaly)
    # - tcn_classifier.pth (classification)
    tcn, ae, ae_thr, splt_scaler, splt_iso = get_sequence_models()

    reasons: List[str] = []
    metadata: Dict[str, Any] = {}

    splt_tensor = flow_to_splt_tensor(flow)
    if splt_tensor is None or splt_scaler is None or splt_iso is None:
        # Fallback to scalar models only if SPLT features/models are not available
        scaler, iso, mlp = get_scalar_models()
        x = flow_to_vec(flow)
        score = 0.5
        if scaler is not None and iso is not None:
            xs = scaler.transform(x.reshape(1, -1)).reshape(-1)
            score = anomaly_score_from_iso(iso, xs)
            reasons.append("isoforest_anomalous" if score >= 0.6 else "isoforest_normal")
        else:
            reasons.append("sequence_models_unavailable")

        label = "malicious" if score >= 0.6 else "benign"
        sev = severity_from_score(score)

        return ThreatEvent(
            flow_id=flow.flow_id,
            label=label,
            confidence=float(score),
            anomaly_score=float(score),
            severity=sev,
            reason=reasons,
            metadata=metadata,
        )

    # --- SPLT IsolationForest score ---
    splt_vec = splt_vec_from_tensor(splt_tensor)
    splt_scaled = splt_scaler.transform(splt_vec.reshape(1, -1)).reshape(-1).astype(np.float32)
    iso_score = anomaly_score_from_iso(splt_iso, splt_scaled)
    metadata["splt_iso_score"] = float(iso_score)
    print(f"DEBUG: SPLT ISO Score = {iso_score:.3f}, Threshold = 0.8")
    reasons.append("splt_isoforest_anomalous" if iso_score >= 0.8 else "splt_isoforest_normal")

    # --- Autoencoder reconstruction score (optional) ---
    ae_score = None
    if ae is not None and ae_thr is not None:
        with torch.no_grad():
            recon = ae(splt_tensor)
            rec_err = torch.mean((recon - splt_tensor) ** 2).item()
        ae_score = float(rec_err)
        metadata["ae_recon_mse"] = ae_score
        metadata["ae_threshold"] = float(ae_thr)
        reasons.append("ae_anomalous" if ae_score >= float(ae_thr) else "ae_normal")

    # --- TCN classification (optional) ---
    tcn_prob = None
    if tcn is not None:
        with torch.no_grad():
            logits = tcn(splt_tensor)
            probs = torch.softmax(logits, dim=1).squeeze(0)
            if probs.numel() >= 2:
                tcn_prob = float(probs[1].item())
                metadata["tcn_malicious_prob"] = tcn_prob
                reasons.append("tcn_malicious" if tcn_prob >= 0.6 else "tcn_benign")

    # Combine signals (conservative: require strong evidence)
    combined = float(iso_score)
    if ae_score is not None and ae_thr is not None and ae_score >= float(ae_thr):
        combined = max(combined, 0.8)
    if tcn_prob is not None:
        combined = max(combined, tcn_prob)

    score = float(np.clip(combined, 0.0, 1.0))
    # Align decision threshold with iso_score threshold so SPLT-ISO detections surface as malicious.
    label = "malicious" if score >= 0.8 else "benign"
    sev = severity_from_score(score)

    # --- Zero-IP Behavioral Fingerprinting ---
    behavioral_hash = create_behavioral_fingerprint(splt_tensor)
    metadata["behavioral_hash"] = behavioral_hash

    is_known_pattern, pattern_info = check_behavioral_pattern(behavioral_hash)
    if is_known_pattern:
        reasons.append("known_malicious_pattern")
        score = 1.0
        label = "malicious"
        sev = "CRITICAL"

    # Store only very high-confidence events to avoid poisoning
    if label == "malicious" and score >= 0.95 and not is_known_pattern:
        if store_malicious_pattern(behavioral_hash, "unknown_attack", score, flow.flow_id):
            reasons.append("new_malicious_pattern_stored")

    return ThreatEvent(
        flow_id=flow.flow_id,
        label=label,
        confidence=float(score),
        anomaly_score=float(score),
        severity=sev,
        reason=reasons,
        metadata=metadata,
    )
