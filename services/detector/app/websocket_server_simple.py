#!/usr/bin/env python3
"""
Simple WebSocket Server for ZeroTrust-AI with SOAR Integration
Phase 1 + Phase 2: Live threat detection + SOAR backend calls
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from typing import List, Dict, Any
import json
import asyncio
import requests
from datetime import datetime
from dataclasses import dataclass

@dataclass
class ThreatEvent:
    flow_id: str
    label: str
    confidence: float
    severity: str
    reason: List[str]
    timestamp: str
    attack_type: str
    source_ip: str
    destination_ip: str
    blocked: bool

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.threat_history: List[ThreatEvent] = []
        self.total_flows = 0

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"🔌 WebSocket client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"❌ WebSocket client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                print(f"❌ Failed to send to client: {e}")

app = FastAPI()
manager = ConnectionManager()

# SOAR Integration - Phase 2
def trigger_soar(event: ThreatEvent):
    """Send high-confidence threats to SOAR backend (Phase 2)"""
    try:
        conf = event.confidence
        label = event.label
        reasons = event.reason or []
        is_volumetric = any(k in " ".join(reasons) for k in 
                           ["syn_flood","ddos","high_packets_per_second","flood"])
        
        # BLOCK: confidence >= 0.85
        if label == "malicious" and conf >= 0.85:
            try:
                response = requests.post("http://localhost:9002/block", json={
                    "ip_address": event.source_ip,
                    "risk_score": int(conf * 100),
                    "reason": ", ".join(reasons),
                    "attack_type": event.attack_type,
                    "mitre_tactic": "",  # Can be added later
                    "mitre_technique": "",
                    "confidence": conf,
                    "flow_id": event.flow_id,
                    "auto_block": True
                }, timeout=2)
                if response.status_code == 200:
                    print(f"🛡️ SOAR BLOCK triggered for {event.source_ip}")
            except Exception as e:
                print(f"⚠️ SOAR block failed: {e}")
        
        # RATE LIMIT: 0.70-0.85 + volumetric
        elif label == "malicious" and conf >= 0.70 and is_volumetric:
            try:
                response = requests.post("http://localhost:9002/rate-limit", json={
                    "ip_address": event.source_ip,
                    "risk_score": int(conf * 100),
                    "reason": ", ".join(reasons),
                    "flow_id": event.flow_id,
                }, timeout=2)
                if response.status_code == 200:
                    print(f"🚦 SOAR RATE LIMIT triggered for {event.source_ip}")
            except Exception as e:
                print(f"⚠️ SOAR rate-limit failed: {e}")
                
    except Exception as e:
        print(f"⚠️ SOAR integration error: {e}")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back or handle client messages if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/detect")
async def detect_threat(threat_data: Dict[str, Any]):
    """Receive threat detection - Phase 1 functionality preserved"""
    threat = ThreatEvent(
        flow_id=threat_data.get("flow_id", "unknown"),
        label=threat_data.get("label", "unknown"),
        confidence=threat_data.get("confidence", 0.0),
        severity=threat_data.get("severity", "medium"),
        reason=threat_data.get("reason", []),
        timestamp=threat_data.get("timestamp", datetime.now().isoformat()),
        attack_type=threat_data.get("attack_type", "unknown"),
        source_ip=threat_data.get("source_ip", "unknown"),
        destination_ip=threat_data.get("destination_ip", "unknown"),
        blocked=bool(threat_data.get("blocked", False)),
    )
    
    manager.threat_history.append(threat)
    manager.total_flows += 1
    
    # Phase 1: Broadcast to dashboard (unchanged)
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
    
    # Phase 2: Trigger SOAR for high-confidence threats
    if threat.confidence >= 0.70:
        trigger_soar(threat)
    
    return {"status": "success", "threat_id": threat.flow_id, "blocked": threat.blocked}

@app.get("/metrics")
async def get_metrics():
    """Get system metrics - Phase 1 unchanged"""
    total_flows = manager.total_flows
    malicious_count = len([t for t in manager.threat_history if t.attack_type and t.attack_type != 'benign'])
    blocked_count = len([t for t in manager.threat_history if t.blocked])
    
    return {
        "total_flows": total_flows,
        "threats_detected": malicious_count,
        "threats_blocked": blocked_count,
        "active_connections": len(manager.active_connections),
        "recent_threats": [
            {
                "flow_id": t.flow_id,
                "attack_type": t.attack_type,
                "confidence": t.confidence,
                "severity": t.severity,
                "timestamp": t.timestamp,
                "blocked": t.blocked
            }
            for t in manager.threat_history[-10:]
        ]
    }

@app.get("/threats")
async def get_threats(limit: int = 100):
    """Get threat history - Phase 1 unchanged"""
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
    return {"threats": threats, "total": len(threats)}

@app.get("/", response_class=HTMLResponse)
async def get_web_interface():
    """Serve main web interface - Phase 1 unchanged"""
    try:
        with open("c:/Users/shrey/Desktop/techsavishakara/techs/ZeroTrustAI/apps/web/index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Web interface not found. Run from project root.</h1>"

if __name__ == "__main__":
    import uvicorn
    print("🛡️ ZeroTrust-AI WebSocket Server Starting...")
    print("📊 Phase 1: Live threat detection + dashboard")
    print("🚀 Phase 2: SOAR backend integration")
    print("🌐 Web Interface: http://localhost:9000")
    uvicorn.run(app, host="0.0.0.0", port=9000)
