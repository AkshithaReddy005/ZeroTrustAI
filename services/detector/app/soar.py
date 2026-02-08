#!/usr/bin/env python3
"""
SOAR (Security Orchestration, Automation, and Response) Module
Provides manual override capabilities for IP blocking/unblocking
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import redis
import time
import json
from datetime import datetime, timedelta

# Initialize router
soar_router = APIRouter(prefix="/soar", tags=["SOAR"])

# Redis client (reuse from main.py if available)
try:
    REDIS_CLIENT = redis.from_url("redis://localhost:6379/0", decode_responses=True)
except Exception:
    REDIS_CLIENT = None

class BlockRequest(BaseModel):
    ip_address: str
    reason: str
    duration_hours: int = 24
    blocked_by: str = "manual"

class UnblockRequest(BaseModel):
    ip_address: str
    unblocked_by: str = "manual"

class BlockedIP(BaseModel):
    ip_address: str
    reason: str
    blocked_at: str
    blocked_until: str
    blocked_by: str
    status: str

def get_blocked_ip_key(ip: str) -> str:
    """Get Redis key for blocked IP"""
    return f"blocked:{ip}"

def get_risk_key(ip: str) -> str:
    """Get Redis key for risk data"""
    return f"risk:{ip}"

@soar_router.post("/block", response_model=dict)
def block_ip(request: BlockRequest):
    """
    Manually block an IP address
    This removes the IP from risk tracking and adds it to blocked list
    """
    if not REDIS_CLIENT:
        raise HTTPException(status_code=503, detail="Redis not available")
    
    try:
        # Remove from risk tracking (manual override)
        risk_key = get_risk_key(request.ip_address)
        redis_risk = REDIS_CLIENT.hgetall(risk_key)
        
        # Store original risk data before blocking
        original_risk = {}
        if redis_risk:
            original_risk = {
                "original_score": redis_risk.get("score", "0"),
                "original_severity": redis_risk.get("severity", "LOW"),
                "original_reasons": redis_risk.get("reasons", ""),
                "original_ts": redis_risk.get("ts", "0"),
                "blocked_at": str(time.time())
            }
        
        # Delete risk data (manual override)
        REDIS_CLIENT.delete(risk_key)
        
        # Add to blocked list
        blocked_key = get_blocked_ip_key(request.ip_address)
        blocked_until = datetime.now() + timedelta(hours=request.duration_hours)
        
        block_data = {
            "ip_address": request.ip_address,
            "reason": request.reason,
            "blocked_at": datetime.now().isoformat(),
            "blocked_until": blocked_until.isoformat(),
            "blocked_by": request.blocked_by,
            "status": "active",
            "original_risk": json.dumps(original_risk)
        }
        
        REDIS_CLIENT.hset(blocked_key, mapping=block_data)
        REDIS_CLIENT.expire(blocked_key, request.duration_hours * 3600)
        
        return {
            "status": "success",
            "message": f"IP {request.ip_address} blocked successfully",
            "ip_address": request.ip_address,
            "blocked_until": blocked_until.isoformat(),
            "original_risk_removed": bool(redis_risk)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to block IP: {str(e)}")

@soar_router.post("/unblock", response_model=dict)
def unblock_ip(request: UnblockRequest):
    """
    Manually unblock an IP address
    This removes the IP from blocked list and optionally restores risk data
    """
    if not REDIS_CLIENT:
        raise HTTPException(status_code=503, detail="Redis not available")
    
    try:
        blocked_key = get_blocked_ip_key(request.ip_address)
        blocked_data = REDIS_CLIENT.hgetall(blocked_key)
        
        if not blocked_data:
            raise HTTPException(status_code=404, detail=f"IP {request.ip_address} not found in blocked list")
        
        # Get original risk data if available
        original_risk_json = blocked_data.get("original_risk", "{}")
        original_risk = json.loads(original_risk_json) if original_risk_json else {}
        
        # Restore risk data if it existed
        risk_restored = False
        if original_risk and original_risk.get("original_score"):
            risk_key = get_risk_key(request.ip_address)
            
            # Calculate remaining TTL based on original risk decay
            original_ts = float(original_risk.get("original_ts", "0"))
            time_elapsed = time.time() - original_ts
            remaining_ttl = max(0, 1800 - int(time_elapsed))  # 30 minutes original TTL
            
            if remaining_ttl > 0:
                restored_data = {
                    "flow_id": f"restored_{request.ip_address}",
                    "score": original_risk.get("original_score", "0"),
                    "severity": original_risk.get("original_severity", "LOW"),
                    "reasons": original_risk.get("original_reasons", "manual_unblock"),
                    "ts": original_risk.get("original_ts", str(time.time())),
                    "unblocked_at": str(time.time()),
                    "unblocked_by": request.unblocked_by
                }
                
                REDIS_CLIENT.hset(risk_key, mapping={k: str(v) for k, v in restored_data.items()})
                REDIS_CLIENT.expire(risk_key, remaining_ttl)
                risk_restored = True
        
        # Remove from blocked list
        REDIS_CLIENT.delete(blocked_key)
        
        return {
            "status": "success",
            "message": f"IP {request.ip_address} unblocked successfully",
            "ip_address": request.ip_address,
            "risk_data_restored": risk_restored,
            "unblocked_by": request.unblocked_by
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to unblock IP: {str(e)}")

@soar_router.get("/blocked", response_model=List[BlockedIP])
def list_blocked_ips():
    """List all currently blocked IPs"""
    if not REDIS_CLIENT:
        raise HTTPException(status_code=503, detail="Redis not available")
    
    try:
        blocked_keys = REDIS_CLIENT.keys("blocked:*")
        blocked_ips = []
        
        for key in blocked_keys:
            data = REDIS_CLIENT.hgetall(key)
            if data:
                blocked_ips.append(BlockedIP(
                    ip_address=data.get("ip_address", ""),
                    reason=data.get("reason", ""),
                    blocked_at=data.get("blocked_at", ""),
                    blocked_until=data.get("blocked_until", ""),
                    blocked_by=data.get("blocked_by", ""),
                    status=data.get("status", "active")
                ))
        
        return blocked_ips
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list blocked IPs: {str(e)}")

@soar_router.get("/blocked/{ip_address}", response_model=dict)
def get_blocked_ip_details(ip_address: str):
    """Get details about a specific blocked IP"""
    if not REDIS_CLIENT:
        raise HTTPException(status_code=503, detail="Redis not available")
    
    try:
        blocked_key = get_blocked_ip_key(ip_address)
        blocked_data = REDIS_CLIENT.hgetall(blocked_key)
        
        if not blocked_data:
            raise HTTPException(status_code=404, detail=f"IP {ip_address} not found in blocked list")
        
        # Parse original risk data
        original_risk_json = blocked_data.get("original_risk", "{}")
        original_risk = json.loads(original_risk_json) if original_risk_json else {}
        
        return {
            "ip_address": blocked_data.get("ip_address"),
            "reason": blocked_data.get("reason"),
            "blocked_at": blocked_data.get("blocked_at"),
            "blocked_until": blocked_data.get("blocked_until"),
            "blocked_by": blocked_data.get("blocked_by"),
            "status": blocked_data.get("status"),
            "original_risk": original_risk
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get blocked IP details: {str(e)}")

@soar_router.get("/risk/{ip_address}", response_model=dict)
def get_ip_risk_status(ip_address: str):
    """Get current risk status for an IP"""
    if not REDIS_CLIENT:
        raise HTTPException(status_code=503, detail="Redis not available")
    
    try:
        risk_key = get_risk_key(ip_address)
        risk_data = REDIS_CLIENT.hgetall(risk_key)
        
        if not risk_data:
            return {
                "ip_address": ip_address,
                "status": "no_risk_detected",
                "message": "No risk data found for this IP"
            }
        
        # Check if IP is also blocked
        blocked_key = get_blocked_ip_key(ip_address)
        blocked_data = REDIS_CLIENT.hgetall(blocked_key)
        
        return {
            "ip_address": ip_address,
            "risk_status": "active",
            "score": risk_data.get("score"),
            "severity": risk_data.get("severity"),
            "reasons": risk_data.get("reasons"),
            "last_seen": risk_data.get("ts"),
            "blocked": bool(blocked_data),
            "blocked_reason": blocked_data.get("reason") if blocked_data else None
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get IP risk status: {str(e)}")

@soar_router.delete("/clear-expired", response_model=dict)
def clear_expired_blocks():
    """Clean up expired blocks (maintenance endpoint)"""
    if not REDIS_CLIENT:
        raise HTTPException(status_code=503, detail="Redis not available")
    
    try:
        blocked_keys = REDIS_CLIENT.keys("blocked:*")
        expired_count = 0
        
        for key in blocked_keys:
            data = REDIS_CLIENT.hgetall(key)
            if data:
                blocked_until = data.get("blocked_until", "")
                if blocked_until:
                    try:
                        expiry_time = datetime.fromisoformat(blocked_until.replace('Z', '+00:00'))
                        if datetime.now(expiry_time.tzinfo) > expiry_time:
                            REDIS_CLIENT.delete(key)
                            expired_count += 1
                    except:
                        # If we can't parse the date, assume it's expired
                        REDIS_CLIENT.delete(key)
                        expired_count += 1
        
        return {
            "status": "success",
            "expired_blocks_cleared": expired_count,
            "message": f"Cleared {expired_count} expired blocks"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear expired blocks: {str(e)}")
