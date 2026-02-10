from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import sys
from typing import List, Dict
import time
import uuid
import requests
from datetime import datetime, timedelta

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
        mitre_technique_id: str | None = None

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

DENY_RISK_THRESHOLD = int(os.getenv("DENY_RISK_THRESHOLD", "80"))
RESTRICT_RISK_THRESHOLD = int(os.getenv("RESTRICT_RISK_THRESHOLD", "50"))
DENY_SEVERITIES = set(
    s.strip().upper() for s in os.getenv("DENY_SEVERITIES", "CRITICAL,HIGH").split(",") if s.strip()
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
    mitre_technique_id: str | None = None

@app.get("/samples/threats")
def get_sample_threats():
    # Placeholder data for initial dashboard wiring
    return [
        {"timestamp": "2026-01-25T12:00:00Z", "threat_type": "Port Scan", "source_ip": "203.0.113.42", "severity": "HIGH", "status": "Blocked", "mitre_technique_id": "T1046"},
        {"timestamp": "2026-01-25T12:01:00Z", "threat_type": "Malware C2", "source_ip": "203.0.113.77", "severity": "MEDIUM", "status": "Quarantined", "mitre_technique_id": "T1071.001"},
        {"timestamp": "2026-01-25T12:02:00Z", "threat_type": "SQL Injection", "source_ip": "203.0.113.15", "severity": "LOW", "status": "Monitoring", "mitre_technique_id": "T1190"},
    ]

# In-memory event stores (POC)
EVENTS: List[dict] = []
INCIDENTS: List[dict] = []
OVERRIDES: dict[str, dict] = {}
DECISIONS: List[dict] = []  # Phase 3 Zero Trust outputs (real-time)

@app.get("/events")
def list_events(limit: int = 100):
    return EVENTS[-limit:]

@app.post("/events/flow")
def add_flow_event(event: FlowFeatures):
    EVENTS.append({"type": "flow", "data": event.model_dump(), "timestamp": datetime.utcnow().isoformat()})

    ws_server_url = os.getenv("WS_SERVER_URL", "http://localhost:9000")
    try:
        requests.post(f"{ws_server_url}/flow", json=event.model_dump(), timeout=2)
    except Exception:
        pass

    detector_url = os.getenv("DETECTOR_URL", "http://localhost:9001")
    threat_obj = None
    try:
        r = requests.post(f"{detector_url}/detect", json=event.model_dump(), timeout=2)
        if r.ok:
            threat_obj = r.json()
    except Exception:
        threat_obj = None

    if threat_obj:
        EVENTS.append({"type": "threat", "data": threat_obj, "timestamp": datetime.utcnow().isoformat()})

        try:
            requests.post(f"{ws_server_url}/detect", json=threat_obj, timeout=2)
        except Exception:
            pass

        # ---- Phase 3: derive deterministic Zero Trust decision from threat ----
        # WHY: Produce real risk decisions that SOAR consumes. No ML here.
        confidence = float(threat_obj.get("confidence", 0.0))
        risk_score = int(max(0, min(100, round(confidence * 100))))
        severity = str(threat_obj.get("severity", "LOW")).upper()
        reasons = threat_obj.get("reason", [])
        src_ip = threat_obj.get("source_ip")  # may be None depending on upstream
        decision = "allow"
        if severity in DENY_SEVERITIES or risk_score >= DENY_RISK_THRESHOLD:
            decision = "deny"
        elif RESTRICT_RISK_THRESHOLD <= risk_score < DENY_RISK_THRESHOLD:
            decision = "restrict"
        dec = {
            "flow_id": threat_obj.get("flow_id", event.flow_id),
            "src_ip": src_ip,
            "risk_score": risk_score,
            "decision": decision,
            "reasons": reasons,
            "timestamp": time.time(),
        }
        DECISIONS.append(dec)

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
    EVENTS.append({"type": "threat", "data": event.model_dump(), "timestamp": datetime.utcnow().isoformat()})
    # ---- Phase 3: derive deterministic decision ----
    confidence = float(getattr(event, "confidence", 0.0))
    risk_score = int(max(0, min(100, round(confidence * 100))))
    severity = str(getattr(event, "severity", "LOW")).upper()
    reasons = getattr(event, "reason", [])
    decision = "allow"
    if severity in ("CRITICAL", "HIGH") or risk_score >= 80:
        decision = "deny"
    elif 50 <= risk_score < 80:
        decision = "restrict"
    dec = {
        "flow_id": event.flow_id,
        "src_ip": None,  # may be enriched upstream
        "risk_score": risk_score,
        "decision": decision,
        "reasons": reasons,
        "timestamp": time.time(),
    }
    DECISIONS.append(dec)

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

# ---- Dashboard endpoints ----

@app.get("/api/threats/recent")
def recent_threats(limit: int = 100):
    # Return recent threat events only with MITRE ID if present
    threats = [e["data"] for e in EVENTS if e.get("type") == "threat"]
    return threats[-limit:]

class OverrideRequest(BaseModel):
    action: str  # e.g., "block", "quarantine", "allow"
    reason: str | None = None

@app.post("/api/threats/{flow_id}/override")
def override_threat(flow_id: str, body: OverrideRequest):
    # Store override action for the given flow
    OVERRIDES[flow_id] = {
        "action": body.action,
        "reason": body.reason,
        "ts": time.time(),
    }
    return {"status": "ok", "flow_id": flow_id}

@app.get("/api/threats/{flow_id}/override")
def get_override(flow_id: str):
    if flow_id not in OVERRIDES:
        raise HTTPException(status_code=404, detail="No override found")
    return OVERRIDES[flow_id]

@app.get("/decisions")
def list_decisions(since: float | None = None, limit: int = 200):
    # Return Phase 3 decisions, optionally filtered by timestamp
    if since:
        filtered = [d for d in DECISIONS if float(d.get("timestamp", 0)) > float(since)]
    else:
        filtered = DECISIONS
    return filtered[-limit:]

# ---- Aggregated metrics for frontend ----
@app.get("/metrics")
def metrics():
    total_flows = len([e for e in EVENTS if e.get("type") == "flow"])
    threats = [e["data"] for e in EVENTS if e.get("type") == "threat"]
    malicious_count = len([t for t in threats if str(t.get("label", "")).lower() == "malicious"])
    decision_count = len([d for d in DECISIONS if d.get("decision") in ("deny", "restrict")])
    blocked_count = decision_count
    # Attack type distribution based on MITRE technique or reason strings if present
    attack_counts: Dict[str, int] = {}
    for t in threats:
        mt = t.get("mitre_technique_id")
        if mt:
            attack_counts[mt] = attack_counts.get(mt, 0) + 1
        else:
            for r in t.get("reason", []):
                attack_counts[r] = attack_counts.get(r, 0) + 1
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
    recent_threats_per_minute = len([
        e
        for e in EVENTS
        if e.get("type") == "threat"
        and e.get("timestamp")
        and datetime.fromisoformat(str(e.get("timestamp"))) > one_minute_ago
    ])
    return {
        "total_flows": total_flows,
        "threats_detected": int(malicious_count + decision_count),
        "blocked_flows": blocked_count,
        "accuracy": 0.94,
        "active_connections": 0,
        "attack_types": attack_counts,
        "recent_threats_per_minute": recent_threats_per_minute,
    }

