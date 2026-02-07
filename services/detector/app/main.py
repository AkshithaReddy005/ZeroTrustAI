from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Literal, Optional, Tuple
import os
import sys
import json
import time
import uuid

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


# Add shared module path (mounted by docker-compose)
sys.path.append("/app/shared")
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

    class ThreatEvent(BaseModel):
        flow_id: str
        label: Literal["benign", "malicious"]
        confidence: float
        anomaly_score: float
        severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        reason: List[str]


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


MODEL_DIR = os.getenv("MODEL_DIR", "/models")
os.makedirs(MODEL_DIR, exist_ok=True)

SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
ISO_PATH = os.path.join(MODEL_DIR, "isoforest.joblib")
PT_PATH = os.path.join(MODEL_DIR, "pytorch_mlp.pt")
FEEDBACK_PATH = os.path.join(MODEL_DIR, "feedback.jsonl")
META_PATH = os.path.join(MODEL_DIR, "meta.json")


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
    # stable, simple numeric vector
    return np.array(
        [
            float(f.total_packets),
            float(f.total_bytes),
            float(f.avg_packet_size),
            float(f.std_packet_size),
            float(f.duration),
            float(f.pps),
            float(f.avg_entropy),
            float(f.syn_count),
            float(f.fin_count),
        ],
        dtype=np.float32,
    )


class MLP(nn.Module):
    def __init__(self, in_dim: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def load_models() -> Tuple[Optional[StandardScaler], Optional[IsolationForest], Optional[MLP]]:
    scaler = None
    iso = None
    mlp = None
    if os.path.exists(SCALER_PATH):
        scaler = joblib.load(SCALER_PATH)
    if os.path.exists(ISO_PATH):
        iso = joblib.load(ISO_PATH)
    if os.path.exists(PT_PATH):
        state = torch.load(PT_PATH, map_location="cpu")
        mlp = MLP(in_dim=state["in_dim"])
        mlp.load_state_dict(state["state_dict"])
        mlp.eval()
    return scaler, iso, mlp


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


@app.get("/health")
def health():
    scaler, iso, mlp = load_models()
    return {
        "status": "ok",
        "scaler": bool(scaler),
        "isolation_forest": bool(iso),
        "pytorch": bool(mlp),
        "model_dir": MODEL_DIR,
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
    scaler, iso, mlp = load_models()
    x = flow_to_vec(flow)

    reasons: List[str] = []
    # If models missing, require /train first (but still return something usable)
    if scaler is None or iso is None or mlp is None:
        score = 0.5
        reasons.append("model_not_trained")
        label = "malicious" if score >= 0.6 else "benign"
        return ThreatEvent(
            flow_id=flow.flow_id,
            label=label,
            confidence=float(score),
            anomaly_score=float(score),
            severity=severity_from_score(score),
            reason=reasons,
        )

    xs = scaler.transform(x.reshape(1, -1)).reshape(-1)
    a_score = anomaly_score_from_iso(iso, xs)
    p_mal = mlp_prob(mlp, xs)

    # Blend anomaly and classifier scores
    score = float(np.clip(0.55 * p_mal + 0.45 * a_score, 0.0, 1.0))

    if p_mal > 0.6:
        reasons.append("mlp_malicious")
    if a_score > 0.6:
        reasons.append("anomalous_flow")

    label = "malicious" if score >= 0.6 else "benign"
    sev = severity_from_score(score)

    # --- Optional Redis: real-time risk state with TTL (risk decay) ---
    if REDIS_CLIENT is not None and label == "malicious":
        try:
            # Use source IP as key if available; otherwise fall back to flow_id
            src_ip = getattr(flow, "src_ip", None)
            key = f"risk:{src_ip}" if src_ip else f"risk:{flow.flow_id}"
            doc = {
                "flow_id": flow.flow_id,
                "score": float(score),
                "severity": sev,
                "reasons": ",".join(reasons) or "low_risk",
                "ts": time.time(),
            }
            REDIS_CLIENT.hset(key, mapping={k: str(v) for k, v in doc.items()})
            REDIS_CLIENT.expire(key, REDIS_TTL_SECONDS)
        except Exception:
            # Best-effort only; detection must not fail if Redis is down
            pass

    # --- Optional InfluxDB: historical threat/time-series logging ---
    if INFLUX_WRITE_API is not None:
        try:
            # Attack type and MITRE TTP could be inferred from reasons; placeholder for now
            attack_type = "unknown"
            mitre_tactic = "unknown"
            mitre_technique = "unknown"

            fields = {
                "score": float(score),
                "anomaly_score": float(a_score),
                "confidence": float(score),
            }
            # Optionally include IPs if present on schema
            for attr in ("src_ip", "dst_ip"):
                if hasattr(flow, attr):
                    fields[attr] = getattr(flow, attr)

            p = (
                Point("threat_events")
                .tag("label", label)
                .tag("severity", sev)
                .tag("attack_type", attack_type)
                .tag("mitre_tactic", mitre_tactic)
                .tag("mitre_technique", mitre_technique)
            )
            for k, v in fields.items():
                # InfluxDB can handle float/string; cast conservatively
                if isinstance(v, (int, float)):
                    p = p.field(k, float(v))
                else:
                    p = p.field(k, str(v))

            INFLUX_WRITE_API.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=p)
        except Exception:
            # Best-effort logging; never break detection
            pass

    return ThreatEvent(
        flow_id=flow.flow_id,
        label=label,
        confidence=float(score),
        anomaly_score=float(a_score),
        severity=sev,
        reason=reasons or ["low_risk"],
    )
