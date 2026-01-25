from typing import List, Literal, Optional
from pydantic import BaseModel

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

class PacketEvent(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    proto: str
    raw_len: int
    payload_entropy: Optional[float] = None

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
    severity: Severity
    reason: List[str]

class PolicyDecision(BaseModel):
    flow_id: str
    allowed: bool
    risk_score: int
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    required_auth: Literal[
        "password_only",
        "password_plus_2fa",
        "password_plus_2fa_plus_biometric"
    ]

class Incident(BaseModel):
    incident_id: str
    threat: ThreatEvent
    actions: List[str]
