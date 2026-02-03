from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import sys
from typing import List
import time
import uuid
import requests

# Add shared module path (mounted by docker-compose)
sys.path.append("/app/shared")
try:
    from schemas import FlowFeatures, ThreatEvent, Incident, PolicyDecision
except Exception:
    # Fallback minimal models if shared is not available in local runs
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
        label: str
        confidence: float
        anomaly_score: float
        severity: str
        reason: List[str]

    class Incident(BaseModel):
        incident_id: str
        threat: ThreatEvent
        actions: List[str]

    class PolicyDecision(BaseModel):
        flow_id: str
        allowed: bool
        risk_score: int
        risk_level: str
        required_auth: str

app = FastAPI(title="ZeroTrust-AI API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class HealthResponse(BaseModel):
    status: str
    version: str

@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(status="ok", version="0.1.0")

class ThreatSample(BaseModel):
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    status: str

@app.get("/samples/threats")
def get_sample_threats():
    # Placeholder data for initial dashboard wiring
    return [
        {"timestamp": "2026-01-25T12:00:00Z", "threat_type": "Port Scan", "source_ip": "203.0.113.42", "severity": "HIGH", "status": "Blocked"},
        {"timestamp": "2026-01-25T12:01:00Z", "threat_type": "Malware C2", "source_ip": "203.0.113.77", "severity": "MEDIUM", "status": "Quarantined"},
        {"timestamp": "2026-01-25T12:02:00Z", "threat_type": "SQL Injection", "source_ip": "203.0.113.15", "severity": "LOW", "status": "Monitoring"},
    ]

# In-memory event stores (POC)
EVENTS: List[dict] = []
INCIDENTS: List[dict] = []

@app.get("/events")
def list_events(limit: int = 100):
    return EVENTS[-limit:]

@app.post("/events/flow")
def add_flow_event(event: FlowFeatures):
    EVENTS.append({"type": "flow", "data": event.model_dump()})
    # Optional automatic detection on flows (disabled by default)
    if os.getenv("ENABLE_FLOW_DETECTION", "0").lower() in {"1", "true", "yes"}:
        detector_url = os.getenv("DETECTOR_URL", "http://localhost:9000")
        threat_obj = None
        try:
            r = requests.post(f"{detector_url}/detect", json=event.model_dump(), timeout=2)
            if r.ok:
                threat_obj = r.json()
        except Exception:
            threat_obj = None

        if threat_obj:
            EVENTS.append({"type": "threat", "data": threat_obj})
            if threat_obj.get("label") == "malicious":
                inc = {
                    "incident_id": str(uuid.uuid4()),
                    "threat": threat_obj,
                    "actions": ["blocked", "quarantined"],
                    "timestamp": time.time(),
                }
                INCIDENTS.append(inc)
    return {"status": "ok"}

@app.post("/events/threat")
def add_threat_event(event: ThreatEvent):
    EVENTS.append({"type": "threat", "data": event.model_dump()})
    if getattr(event, "label", None) == "malicious":
        inc = {
            "incident_id": str(uuid.uuid4()),
            "threat": event.model_dump(),
            "actions": ["blocked", "quarantined"],
            "timestamp": time.time(),
        }
        INCIDENTS.append(inc)
    return {"status": "ok"}

@app.get("/incidents")
def list_incidents():
    return INCIDENTS


class SimRequest(BaseModel):
    # Optional knobs to influence the synthetic flow
    intensity: float | None = None  # higher -> more packets/pps/entropy


@app.post("/simulate/request", response_model=PolicyDecision)
def simulate_request(req: SimRequest | None = None):
    import random

    intensity = float(req.intensity) if req and req.intensity is not None else 0.5
    intensity = max(0.0, min(1.0, intensity))

    # Craft a synthetic flow
    flow = FlowFeatures(
        flow_id=f"flow-sim-{uuid.uuid4().hex[:8]}",
        total_packets=int(10 + 200 * intensity + random.randint(0, 20)),
        total_bytes=int(5_000 + 150_000 * intensity + random.randint(0, 2_000)),
        avg_packet_size=400.0 + 800.0 * intensity,
        std_packet_size=20.0 + 200.0 * intensity,
        duration=max(0.02, 0.5 + 2.0 * intensity),
        pps=50.0 + 900.0 * intensity,
        avg_entropy=3.0 + 4.0 * intensity,
        syn_count=int(1 + 10 * intensity),
        fin_count=int(1 + 6 * intensity),
    )
    EVENTS.append({"type": "flow", "data": flow.model_dump()})

    # Run detector
    detector_url = os.getenv("DETECTOR_URL", "http://localhost:9000")
    threat_obj = None
    try:
        r = requests.post(f"{detector_url}/detect", json=flow.model_dump(), timeout=2)
        if r.ok:
            threat_obj = r.json()
    except Exception:
        threat_obj = None

    allowed = True
    risk_score = 30
    risk_level = "LOW"
    required_auth = "password_only"

    if threat_obj:
        EVENTS.append({"type": "threat", "data": threat_obj})
        label = threat_obj.get("label")
        score = float(threat_obj.get("confidence", 0.0))
        # Map score to risk 0..100
        risk_score = int(min(100, max(0, round(score * 100))))
        risk_level = "HIGH" if risk_score >= 80 else "MEDIUM" if risk_score >= 50 else "LOW"
        allowed = label != "malicious"
        required_auth = (
            "password_plus_2fa_plus_biometric" if risk_level == "HIGH" else
            "password_plus_2fa" if risk_level == "MEDIUM" else
            "password_only"
        )

        if label == "malicious":
            inc = {
                "incident_id": str(uuid.uuid4()),
                "threat": threat_obj,
                "actions": ["blocked", "quarantined"],
                "timestamp": time.time(),
            }
            INCIDENTS.append(inc)

    return PolicyDecision(
        flow_id=flow.flow_id,
        allowed=allowed,
        risk_score=risk_score,
        risk_level=risk_level,
        required_auth=required_auth,
    )

@app.post("/incidents")
def add_incident(incident: Incident):
    INCIDENTS.append(incident.model_dump())
    return {"status": "ok"}


# External policy check (from another computer)
class RequestMeta(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP" or "UDP"
    packet_lengths: List[int] | None = None  # optional signed lengths (+outbound, -inbound)
    iat: List[float] | None = None           # optional inter-arrival times


@app.post("/policy/check", response_model=PolicyDecision)
def policy_check(meta: RequestMeta):
    import random

    # Map RequestMeta to FlowFeatures required by the detector
    pl = meta.packet_lengths or []
    ia = meta.iat or []
    total_packets = max(len(pl), 1)
    total_bytes = int(sum(abs(x) for x in pl)) if pl else random.randint(3_000, 15_000)
    avg_size = (total_bytes / total_packets) if total_packets else 400.0
    std_size = 120.0 if not pl else 80.0  # simple placeholder
    duration = max(sum(ia), 0.02) if ia else 0.5
    pps = total_packets / max(duration, 0.001)
    avg_entropy = 3.5 + min(4.0, total_packets / 50.0)  # simple heuristic
    syn = 1 if meta.protocol.upper() == "TCP" else 0
    fin = 1 if meta.protocol.upper() == "TCP" else 0

    flow = FlowFeatures(
        flow_id=f"flow-pol-{uuid.uuid4().hex[:8]}",
        total_packets=int(total_packets),
        total_bytes=int(total_bytes),
        avg_packet_size=float(avg_size),
        std_packet_size=float(std_size),
        duration=float(duration),
        pps=float(pps),
        avg_entropy=float(avg_entropy),
        syn_count=int(syn),
        fin_count=int(fin),
    )
    EVENTS.append({"type": "flow", "data": flow.model_dump()})

    # Call detector
    detector_url = os.getenv("DETECTOR_URL", "http://localhost:9000")
    threat_obj = None
    try:
        r = requests.post(f"{detector_url}/detect", json=flow.model_dump(), timeout=2)
        if r.ok:
            threat_obj = r.json()
    except Exception:
        threat_obj = None

    allowed = True
    risk_score = 25
    risk_level = "LOW"
    required_auth = "password_only"

    if threat_obj:
        EVENTS.append({"type": "threat", "data": threat_obj})
        label = threat_obj.get("label")
        score = float(threat_obj.get("confidence", 0.0))
        risk_score = int(min(100, max(0, round(score * 100))))
        risk_level = "HIGH" if risk_score >= 80 else "MEDIUM" if risk_score >= 50 else "LOW"
        allowed = label != "malicious"
        required_auth = (
            "password_plus_2fa_plus_biometric" if risk_level == "HIGH" else
            "password_plus_2fa" if risk_level == "MEDIUM" else
            "password_only"
        )

        if label == "malicious":
            inc = {
                "incident_id": str(uuid.uuid4()),
                "threat": threat_obj,
                "actions": ["blocked", "quarantined"],
                "timestamp": time.time(),
            }
            INCIDENTS.append(inc)

    return PolicyDecision(
        flow_id=flow.flow_id,
        allowed=allowed,
        risk_score=risk_score,
        risk_level=risk_level,
        required_auth=required_auth,
    )
