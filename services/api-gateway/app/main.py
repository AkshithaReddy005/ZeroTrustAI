from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os

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
