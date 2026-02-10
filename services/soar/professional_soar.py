"""
Professional SOAR (Security Orchestration, Automation, and Response) Module
Integrates with ZeroTrust-AI Adaptive Risk Scoring Engine
"""

import os
import json
import time
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import redis
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Professional SOAR Configuration
SOAR_CONFIG = {
    "FIREWALL_API_URL": os.getenv("FIREWALL_API_URL", "http://localhost:9090/api/block"),
    "SIEM_API_URL": os.getenv("SIEM_API_URL", "http://localhost:5600/api/alert"),
    "TICKET_SYSTEM_URL": os.getenv("TICKET_SYSTEM_URL", "http://localhost:8080/api/ticket"),
    "NOTIFICATION_WEBHOOK": os.getenv("NOTIFICATION_WEBHOOK", "https://hooks.slack.com/your-webhook"),
    "BLOCK_DURATION_HOURS": int(os.getenv("BLOCK_DURATION_HOURS", "24")),
    "ESCALATION_THRESHOLD": int(os.getenv("ESCALATION_THRESHOLD", "95")),
    "AUTO_BLOCK_ENABLED": os.getenv("AUTO_BLOCK_ENABLED", "true").lower() == "true"
}

# Initialize Redis connection
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=1,  # Use separate DB for SOAR
    decode_responses=True
)

# Pydantic Models
class BlockRequest(BaseModel):
    ip_address: str
    risk_score: int
    reason: str
    attack_type: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: float
    flow_id: str
    auto_block: bool = False

class BlockResponse(BaseModel):
    success: bool
    block_id: str
    message: str
    timestamp: float
    escalation_level: str

class UnblockRequest(BaseModel):
    ip_address: str
    block_id: str
    reason: str
    approved_by: str

class UnblockResponse(BaseModel):
    success: bool
    message: str
    timestamp: float

# FastAPI App
app = FastAPI(
    title="ZeroTrust-AI Professional SOAR",
    description="Security Orchestration, Automation, and Response",
    version="2.0.0"
)

class ProfessionalSOAR:
    """Professional SOAR Engine with Multi-Channel Response"""
    
    def __init__(self):
        self.config = SOAR_CONFIG
        self.redis_client = redis_client
        
    def assess_threat_level(self, risk_score: int, attack_type: str) -> str:
        """Assess threat level based on risk score and attack type"""
        if risk_score >= self.config["ESCALATION_THRESHOLD"]:
            return "CRITICAL"
        elif risk_score >= 80:
            return "HIGH"
        elif risk_score >= 60:
            return "MEDIUM"
        else:
            return "LOW"
    
    def generate_block_id(self) -> str:
        """Generate unique block ID"""
        timestamp = int(time.time())
        return f"BLOCK-{timestamp}-{hash(time.time()) % 10000:04d}"
    
    def store_block_record(self, block_request: BlockRequest, block_id: str) -> bool:
        """Store block record in Redis with TTL"""
        try:
            block_record = {
                "block_id": block_id,
                "ip_address": block_request.ip_address,
                "risk_score": block_request.risk_score,
                "reason": block_request.reason,
                "attack_type": block_request.attack_type,
                "mitre_tactic": block_request.mitre_tactic,
                "mitre_technique": block_request.mitre_technique,
                "confidence": block_request.confidence,
                "flow_id": block_request.flow_id,
                "auto_block": block_request.auto_block,
                "blocked_at": datetime.now().isoformat(),
                "escalation_level": self.assess_threat_level(block_request.risk_score, block_request.attack_type)
            }
            
            # Store with TTL based on block duration
            ttl_seconds = self.config["BLOCK_DURATION_HOURS"] * 3600
            self.redis_client.hset(f"block:{block_request.ip_address}", mapping=block_record)
            self.redis_client.expire(f"block:{block_request.ip_address}", ttl_seconds)
            
            # Also store by block_id for reference
            self.redis_client.hset(f"block_record:{block_id}", mapping=block_record)
            self.redis_client.expire(f"block_record:{block_id}", ttl_seconds)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to store block record: {e}")
            return False
    
    def execute_firewall_block(self, ip_address: str, block_id: str, reason: str) -> bool:
        """Execute firewall block via API"""
        try:
            if not self.config["FIREWALL_API_URL"]:
                logger.warning("Firewall API URL not configured")
                return False
                
            payload = {
                "ip": ip_address,
                "action": "block",
                "duration_hours": self.config["BLOCK_DURATION_HOURS"],
                "reason": reason,
                "block_id": block_id
            }
            
            response = requests.post(
                self.config["FIREWALL_API_URL"],
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully blocked IP {ip_address} via firewall")
                return True
            else:
                logger.error(f"Firewall block failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Firewall block error: {e}")
            return False
    
    def send_siem_alert(self, block_request: BlockRequest, block_id: str) -> bool:
        """Send alert to SIEM system"""
        try:
            if not self.config["SIEM_API_URL"]:
                logger.warning("SIEM API URL not configured")
                return False
                
            alert = {
                "title": f"ZeroTrust-AI Auto-Block: {block_request.ip_address}",
                "description": f"IP automatically blocked due to risk score {block_request.risk_score}",
                "severity": self.assess_threat_level(block_request.risk_score, block_request.attack_type),
                "source_ip": block_request.ip_address,
                "attack_type": block_request.attack_type,
                "mitre_tactic": block_request.mitre_tactic,
                "mitre_technique": block_request.mitre_technique,
                "confidence": block_request.confidence,
                "risk_score": block_request.risk_score,
                "block_id": block_id,
                "flow_id": block_request.flow_id,
                "timestamp": datetime.now().isoformat(),
                "auto_block": block_request.auto_block
            }
            
            response = requests.post(
                self.config["SIEM_API_URL"],
                json=alert,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"SIEM alert sent for IP {block_request.ip_address}")
                return True
            else:
                logger.error(f"SIEM alert failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"SIEM alert error: {e}")
            return False
    
    def create_security_ticket(self, block_request: BlockRequest, block_id: str) -> bool:
        """Create security ticket in ticketing system"""
        try:
            if not self.config["TICKET_SYSTEM_URL"]:
                logger.warning("Ticket system URL not configured")
                return False
                
            ticket = {
                "title": f"Security Incident: Auto-Blocked IP {block_request.ip_address}",
                "description": f"""
ZeroTrust-AI automatically blocked IP address {block_request.ip_address} due to elevated risk score.

Risk Score: {block_request.risk_score}
Attack Type: {block_request.attack_type}
MITRE Tactic: {block_request.mitre_tactic}
MITRE Technique: {block_request.mitre_technique}
Confidence: {block_request.confidence:.2f}
Reason: {block_request.reason}
Flow ID: {block_request.flow_id}
Block ID: {block_id}

This is an automated security response from the ZeroTrust-AI system.
                """,
                "priority": "High" if block_request.risk_score >= 80 else "Medium",
                "category": "Security",
                "source": "ZeroTrust-AI",
                "ip_address": block_request.ip_address,
                "auto_generated": True
            }
            
            response = requests.post(
                self.config["TICKET_SYSTEM_URL"],
                json=ticket,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Security ticket created for IP {block_request.ip_address}")
                return True
            else:
                logger.error(f"Ticket creation failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Ticket creation error: {e}")
            return False
    
    def send_notification(self, block_request: BlockRequest, block_id: str) -> bool:
        """Send notification to security team"""
        try:
            if not self.config["NOTIFICATION_WEBHOOK"]:
                logger.warning("Notification webhook not configured")
                return False
                
            escalation_level = self.assess_threat_level(block_request.risk_score, block_request.attack_type)
            
            message = {
                "text": f"""
🚨 **ZeroTrust-AI SECURITY ALERT** 🚨

**IP Address**: {block_request.ip_address}
**Risk Score**: {block_request.risk_score}
**Threat Level**: {escalation_level}
**Attack Type**: {block_request.attack_type}
**MITRE Tactic**: {block_request.mitre_tactic}
**MITRE Technique**: {block_request.mitre_technique}
**Confidence**: {block_request.confidence:.2f}
**Reason**: {block_request.reason}
**Auto-Block**: {'Yes' if block_request.auto_block else 'No'}
**Block ID**: {block_id}

🛡️ *Professional Zero Trust Security Response*
                """,
                "username": "ZeroTrust-AI SOAR",
                "icon_emoji": ":shield:"
            }
            
            response = requests.post(
                self.config["NOTIFICATION_WEBHOOK"],
                json=message,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Notification sent for IP {block_request.ip_address}")
                return True
            else:
                logger.error(f"Notification failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Notification error: {e}")
            return False
    
    def execute_block_response(self, block_request: BlockRequest) -> BlockResponse:
        """Execute comprehensive block response"""
        start_time = time.time()
        
        # Generate block ID
        block_id = self.generate_block_id()
        
        # Assess threat level
        escalation_level = self.assess_threat_level(block_request.risk_score, block_request.attack_type)
        
        # Store block record
        self.store_block_record(block_request, block_id)
        
        # Execute response actions based on configuration and threat level
        success_count = 0
        total_actions = 0
        
        # Firewall block (always execute if auto-block enabled)
        if self.config["AUTO_BLOCK_ENABLED"] or block_request.auto_block:
            total_actions += 1
            if self.execute_firewall_block(block_request.ip_address, block_id, block_request.reason):
                success_count += 1
        
        # SIEM alert (for medium and above)
        if escalation_level in ["MEDIUM", "HIGH", "CRITICAL"]:
            total_actions += 1
            if self.send_siem_alert(block_request, block_id):
                success_count += 1
        
        # Security ticket (for high and critical)
        if escalation_level in ["HIGH", "CRITICAL"]:
            total_actions += 1
            if self.create_security_ticket(block_request, block_id):
                success_count += 1
        
        # Notification (always)
        total_actions += 1
        if self.send_notification(block_request, block_id):
            success_count += 1
        
        # Determine overall success
        overall_success = success_count >= (total_actions // 2)  # At least half succeeded
        
        return BlockResponse(
            success=overall_success,
            block_id=block_id,
            message=f"Block response executed: {success_count}/{total_actions} actions successful",
            timestamp=time.time(),
            escalation_level=escalation_level
        )

# Initialize SOAR engine
soar_engine = ProfessionalSOAR()

# API Endpoints
@app.post("/block", response_model=BlockResponse)
async def block_ip(block_request: BlockRequest):
    """Block IP address with comprehensive SOAR response"""
    try:
        logger.info(f"Received block request for IP {block_request.ip_address} with risk score {block_request.risk_score}")
        
        # Validate request
        if not block_request.ip_address:
            raise HTTPException(status_code=400, detail="IP address is required")
        
        if block_request.risk_score < 50:
            raise HTTPException(status_code=400, detail="Risk score too low for blocking")
        
        # Execute block response
        response = soar_engine.execute_block_response(block_request)
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Block request error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/unblock", response_model=UnblockResponse)
async def unblock_ip(unblock_request: UnblockRequest):
    """Unblock IP address"""
    try:
        logger.info(f"Received unblock request for IP {unblock_request.ip_address}")
        
        # Check if block exists
        block_record = soar_engine.redis_client.hgetall(f"block:{unblock_request.ip_address}")
        if not block_record:
            raise HTTPException(status_code=404, detail="No active block found for this IP")
        
        # Verify block ID
        if block_record.get("block_id") != unblock_request.block_id:
            raise HTTPException(status_code=400, detail="Invalid block ID")
        
        # Remove from Redis
        soar_engine.redis_client.delete(f"block:{unblock_request.ip_address}")
        
        # Execute firewall unblock
        if soar_engine.config["FIREWALL_API_URL"]:
            try:
                payload = {
                    "ip": unblock_request.ip_address,
                    "action": "unblock",
                    "reason": unblock_request.reason,
                    "approved_by": unblock_request.approved_by
                }
                
                requests.post(
                    soar_engine.config["FIREWALL_API_URL"],
                    json=payload,
                    timeout=10
                )
            except Exception as e:
                logger.error(f"Firewall unblock error: {e}")
        
        return UnblockResponse(
            success=True,
            message=f"IP {unblock_request.ip_address} successfully unblocked",
            timestamp=time.time()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unblock request error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/blocks")
async def list_active_blocks():
    """List all active blocks"""
    try:
        blocks = []
        keys = soar_engine.redis_client.keys("block:*")
        
        for key in keys:
            block_record = soar_engine.redis_client.hgetall(key)
            if block_record:
                blocks.append(block_record)
        
        return {"blocks": blocks, "total": len(blocks)}
        
    except Exception as e:
        logger.error(f"List blocks error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/status")
async def soar_status():
    """Get SOAR system status"""
    try:
        # Test Redis connection
        redis_status = "connected" if soar_engine.redis_client.ping() else "disconnected"
        
        # Count active blocks
        active_blocks = len(soar_engine.redis_client.keys("block:*"))
        
        return {
            "status": "operational",
            "redis": redis_status,
            "auto_block_enabled": soar_engine.config["AUTO_BLOCK_ENABLED"],
            "active_blocks": active_blocks,
            "config": {
                "block_duration_hours": soar_engine.config["BLOCK_DURATION_HOURS"],
                "escalation_threshold": soar_engine.config["ESCALATION_THRESHOLD"]
            }
        }
        
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    uvicorn.run(
        "professional_soar:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )
