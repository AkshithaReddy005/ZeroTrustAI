#!/usr/bin/env python3
"""
Real-time threat detection endpoint for ZeroTrust-AI
Adds WebSocket and streaming capabilities to detector service
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from typing import List
import json
import asyncio
from datetime import datetime
import uvicorn

app = FastAPI(title="ZeroTrust-AI Real-time API")

# Store recent threats in memory (in production, use Redis)
recent_threats = []
active_connections: List[WebSocket] = []

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                # Remove dead connections
                self.active_connections.remove(connection)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Send recent threats every second
            if recent_threats:
                await manager.send_personal_message(
                    json.dumps({
                        "type": "threat_update",
                        "data": recent_threats[-10:],  # Last 10 threats
                        "timestamp": datetime.now().isoformat()
                    }),
                    websocket
                )
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/threats")
async def get_threats():
    """Get recent threats"""
    return recent_threats

@app.post("/threat")
async def add_threat(threat: dict):
    """Add new threat (called by detector)"""
    threat['timestamp'] = datetime.now().isoformat()
    recent_threats.append(threat)
    
    # Keep only last 100 threats
    if len(recent_threats) > 100:
        recent_threats.pop(0)
    
    # Broadcast to all connected clients
    await manager.broadcast(json.dumps({
        "type": "new_threat",
        "data": threat,
        "timestamp": datetime.now().isoformat()
    }))
    
    return {"status": "success"}

@app.get("/metrics")
async def get_metrics():
    """Get system metrics"""
    total_flows = len(recent_threats) * 10  # Estimate
    malicious_count = len([t for t in recent_threats if t.get('label') == 'malicious'])
    
    return {
        "total_flows": total_flows,
        "threats_detected": malicious_count,
        "accuracy": 0.94,  # From your evaluation
        "active_connections": len(manager.active_connections)
    }

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Simple HTML dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZeroTrust-AI Real-time Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .threat { border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }
            .high { border-left: 5px solid #f44336; }
            .medium { border-left: 5px solid #ff9800; }
            .low { border-left: 5px solid #4caf50; }
            .metrics { display: flex; gap: 20px; margin-bottom: 20px; }
            .metric { background: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; }
        </style>
    </head>
    <body>
        <h1>🛡️ ZeroTrust-AI Real-time Dashboard</h1>
        
        <div class="metrics">
            <div class="metric">
                <h3 id="total-flows">0</h3>
                <p>Total Flows</p>
            </div>
            <div class="metric">
                <h3 id="threats">0</h3>
                <p>Threats Detected</p>
            </div>
            <div class="metric">
                <h3 id="accuracy">0%</h3>
                <p>Accuracy</p>
            </div>
        </div>
        
        <h2>🚨 Live Threats</h2>
        <div id="threats-container"></div>
        
        <script>
            const ws = new WebSocket('ws://localhost:9000/ws');
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                if (data.type === 'threat_update' || data.type === 'new_threat') {
                    updateThreats(data.data);
                    updateMetrics();
                }
            };
            
            function updateThreats(threats) {
                const container = document.getElementById('threats-container');
                container.innerHTML = '';
                
                threats.forEach(threat => {
                    const div = document.createElement('div');
                    div.className = `threat ${threat.severity}`;
                    div.innerHTML = `
                        <strong>${threat.flow_id}</strong><br>
                        <small>
                        Label: ${threat.label} | 
                        Confidence: ${(threat.confidence * 100).toFixed(1)}% | 
                        Severity: ${threat.severity}
                        </small><br>
                        <small>Reason: ${threat.reason ? threat.reason.join(', ') : 'Unknown'}</small>
                    `;
                    container.appendChild(div);
                });
            }
            
            function updateMetrics() {
                fetch('/metrics')
                    .then(response => response.json())
                    .then(data => {
                        document.getElementById('total-flows').textContent = data.total_flows.toLocaleString();
                        document.getElementById('threats').textContent = data.threats_detected;
                        document.getElementById('accuracy').textContent = (data.accuracy * 100).toFixed(1) + '%';
                    });
            }
            
            // Initial metrics load
            updateMetrics();
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
