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
    from schemas import FlowFeatures, ThreatEvent, Incident
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

@app.post("/incidents")
def add_incident(incident: Incident):
    INCIDENTS.append(incident.model_dump())
    return {"status": "ok"}
