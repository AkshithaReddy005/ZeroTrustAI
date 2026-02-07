#!/usr/bin/env python3
"""
Enhanced WebSocket Server for ZeroTrust-AI Real-time Interface
Provides live threat detection with attack classification and real-time blocking
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
import json
import asyncio
import time
from datetime import datetime, timedelta
import random
from dataclasses import dataclass
import uvicorn

app = FastAPI(title="ZeroTrust-AI Real-time SOC")

# Enable CORS for web interface
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
# Mount static files (not needed for HTML dashboard)
# app.mount("/static", StaticFiles(directory="static"), name="static")

@dataclass
class ThreatEvent:
    flow_id: str
    label: str
    confidence: float
    severity: str
    reason: List[str]
    timestamp: str = None
    attack_type: str = None
    source_ip: str = None
    destination_ip: str = None
    blocked: bool = False

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.threat_history: List[ThreatEvent] = []
        self.blocked_flows: set = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"New connection: {len(self.active_connections)} active")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print(f"Connection closed: {len(self.active_connections)} active")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                disconnected.append(connection)
        
        # Remove dead connections
        for conn in disconnected:
            self.active_connections.remove(conn)

manager = ConnectionManager()

# Attack type classification
ATTACK_PATTERNS = {
    'botnet': ['regular_beaconing', 'c2_communication'],
    'data_exfiltration': ['large_outbound', 'unusual_destination'],
    'port_scanning': ['port_scan', 'reconnaissance'],
    'ddos': ['high_volume', 'syn_flood'],
    'malware': ['malicious_payload', 'suspicious_behavior']
}

def classify_attack_type(threat: ThreatEvent) -> str:
    """Classify the type of attack based on threat characteristics"""
    reasons = ' '.join(threat.reason).lower()
    
    for attack_type, patterns in ATTACK_PATTERNS.items():
        if any(pattern in reasons for pattern in patterns):
            return attack_type
    
    # Classification based on flow patterns
    if 'beaconing' in reasons or 'regular' in reasons:
        return 'botnet'
    elif 'exfiltration' in reasons or 'large' in reasons:
        return 'data_exfiltration'
    elif 'scan' in reasons or 'recon' in reasons:
        return 'port_scanning'
    elif 'ddos' in reasons or 'flood' in reasons:
        return 'ddos'
    else:
        return 'malware'

def generate_realistic_threat() -> ThreatEvent:
    """Generate realistic threat events for demonstration"""
    attack_types = ['botnet', 'data_exfiltration', 'port_scanning', 'malware']
    severities = ['high', 'medium', 'low']
    
    # Random IP addresses
    source_ip = f"192.168.1.{random.randint(100, 200)}"
    dest_ip = f"10.0.0.{random.randint(1, 50)}"
    
    # Generate threat
    attack_type = random.choice(attack_types)
    severity = random.choice(severities)
    
    threat = ThreatEvent(
        flow_id=f"{source_ip}:{random.randint(1000, 9999)}→{dest_ip}:{random.choice([80, 443, 22, 3389])}/TCP",
        label="malicious" if random.random() > 0.3 else "benign",
        confidence=random.uniform(0.6, 0.99),
        severity=severity,
        reason=random.choice([
            ["tcn_malicious", "ae_anomalous"],
            ["anomalous_flow", "high_entropy"],
            ["suspicious_timing", "unusual_pattern"],
            ["c2_communication", "regular_beaconing"]
        ]),
        attack_type=attack_type,
        source_ip=source_ip,
        destination_ip=dest_ip,
        blocked=severity == 'high' and random.random() > 0.5
    )
    
    return threat

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Send recent threats
            if manager.threat_history:
                recent_threats = [
                    {
                        "flow_id": t.flow_id,
                        "label": t.label,
                        "confidence": t.confidence,
                        "severity": t.severity,
                        "reason": t.reason,
                        "timestamp": t.timestamp,
                        "attack_type": t.attack_type,
                        "source_ip": t.source_ip,
                        "destination_ip": t.destination_ip,
                        "blocked": t.blocked
                    }
                    for t in manager.threat_history[-20:]  # Last 20 threats
                ]
                
                await manager.send_personal_message(
                    json.dumps({
                        "type": "threat_update",
                        "data": recent_threats,
                        "timestamp": datetime.now().isoformat()
                    }),
                    websocket
                )
            
            await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/detect")
async def detect_threat(threat_data: Dict[str, Any]):
    """Receive threat detection from main detector service"""
    threat = ThreatEvent(
        flow_id=threat_data.get("flow_id", "unknown"),
        label=threat_data.get("label", "unknown"),
        confidence=threat_data.get("confidence", 0.0),
        severity=threat_data.get("severity", "medium"),
        reason=threat_data.get("reason", []),
        timestamp=datetime.now().isoformat()
    )
    
    # Classify attack type
    threat.attack_type = classify_attack_type(threat)
    
    # Auto-block high severity threats
    if threat.severity == 'high' and threat.confidence > 0.8:
        threat.blocked = True
        manager.blocked_flows.add(threat.flow_id)
    
    # Add to history
    manager.threat_history.append(threat)
    
    # Keep only last 1000 threats
    if len(manager.threat_history) > 1000:
        manager.threat_history = manager.threat_history[-1000:]
    
    # Broadcast to all connected clients
    await manager.broadcast(json.dumps({
        "type": "new_threat",
        "data": {
            "flow_id": threat.flow_id,
            "label": threat.label,
            "confidence": threat.confidence,
            "severity": threat.severity,
            "reason": threat.reason,
            "timestamp": threat.timestamp,
            "attack_type": threat.attack_type,
            "source_ip": threat.source_ip,
            "destination_ip": threat.destination_ip,
            "blocked": threat.blocked
        }
    }))
    
    return {"status": "success", "threat_id": threat.flow_id, "blocked": threat.blocked}

@app.get("/threats")
async def get_threats(limit: int = 50):
    """Get recent threats"""
    threats = [
        {
            "flow_id": t.flow_id,
            "label": t.label,
            "confidence": t.confidence,
            "severity": t.severity,
            "reason": t.reason,
            "timestamp": t.timestamp,
            "attack_type": t.attack_type,
            "source_ip": t.source_ip,
            "destination_ip": t.destination_ip,
            "blocked": t.blocked
        }
        for t in manager.threat_history[-limit:]
    ]
    return threats

@app.get("/metrics")
async def get_metrics():
    """Get system metrics"""
    total_flows = len(manager.threat_history) * 10  # Estimate
    malicious_count = len([t for t in manager.threat_history if t.label == 'malicious'])
    blocked_count = len([t for t in manager.threat_history if t.blocked])
    
    # Attack type distribution
    attack_counts = {}
    for threat in manager.threat_history:
        if threat.attack_type:
            attack_counts[threat.attack_type] = attack_counts.get(threat.attack_type, 0) + 1
    
    return {
        "total_flows": total_flows,
        "threats_detected": malicious_count,
        "blocked_flows": blocked_count,
        "accuracy": 0.94,  # From your evaluation
        "active_connections": len(manager.active_connections),
        "attack_types": attack_counts,
        "recent_threats_per_minute": len([
            t for t in manager.threat_history 
            if datetime.fromisoformat(t.timestamp) > datetime.now() - timedelta(minutes=1)
        ])
    }

@app.post("/block/{flow_id}")
async def block_flow(flow_id: str):
    """Block a specific flow"""
    manager.blocked_flows.add(flow_id)
    
    # Find and update the threat
    for threat in manager.threat_history:
        if threat.flow_id == flow_id:
            threat.blocked = True
            break
    
    await manager.broadcast(json.dumps({
        "type": "flow_blocked",
        "data": {"flow_id": flow_id, "timestamp": datetime.now().isoformat()}
    }))
    
    return {"status": "success", "flow_id": flow_id, "blocked": True}

@app.get("/attack-stats")
async def get_attack_stats():
    """Get detailed attack statistics"""
    stats = {
        "total_attacks": len(manager.threat_history),
        "by_type": {},
        "by_severity": {"high": 0, "medium": 0, "low": 0},
        "blocked": len(manager.blocked_flows),
        "timeline": []
    }
    
    # Group by type and severity
    for threat in manager.threat_history:
        # By type
        if threat.attack_type:
            stats["by_type"][threat.attack_type] = stats["by_type"].get(threat.attack_type, 0) + 1
        
        # By severity
        if threat.severity in stats["by_severity"]:
            stats["by_severity"][threat.severity] += 1
    
    # Timeline (last hour)
    now = datetime.now()
    for i in range(60):
        time_bucket = now - timedelta(minutes=i)
        count = len([
            t for t in manager.threat_history
            if datetime.fromisoformat(t.timestamp) > time_bucket - timedelta(minutes=1)
        ])
        stats["timeline"].append({
            "time": time_bucket.isoformat(),
            "count": count
        })
    
    return stats

@app.get("/", response_class=HTMLResponse)
async def get_web_interface():
    """Serve main web interface"""
    try:
        with open("../../../apps/web/index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Web interface not found. Run from project root.</h1>"

# Simulation endpoint for testing
@app.post("/simulate-threats")
async def simulate_threats(count: int = 10):
    """Simulate threat events for testing"""
    for _ in range(count):
        threat = generate_realistic_threat()
        manager.threat_history.append(threat)
        
        # Broadcast to all clients
        await manager.broadcast(json.dumps({
            "type": "new_threat",
            "data": {
                "flow_id": threat.flow_id,
                "label": threat.label,
                "confidence": threat.confidence,
                "severity": threat.severity,
                "reason": threat.reason,
                "timestamp": threat.timestamp,
                "attack_type": threat.attack_type,
                "source_ip": threat.source_ip,
                "destination_ip": threat.destination_ip,
                "blocked": threat.blocked
            }
        }))
        
        await asyncio.sleep(0.5)  # Small delay between threats
    
    return {"status": "success", "simulated": count}

if __name__ == "__main__":
    print("🛡️ ZeroTrust-AI Real-time WebSocket Server Starting...")
    print("📊 Web Interface: http://localhost:9000")
    print("🔌 WebSocket: ws://localhost:9000/ws")
    
    uvicorn.run(app, host="0.0.0.0", port=9000, log_level="info")
