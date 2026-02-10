"""
policy_store.py

WHY: Central in-memory state for SOAR actions. We avoid OS-level blocking and instead
maintain a lightweight, explainable policy store that keeps track of which IPs are
currently blocked or throttled, for how long, and why. It also retains an audit log
of all actions for transparency and demo purposes.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import threading

@dataclass
class BlockRecord:
    ip: str
    reason: str
    blocked_at: datetime
    blocked_until: datetime
    decision_ref: Optional[dict] = None

@dataclass
class ThrottleRecord:
    ip: str
    reason: str
    throttled_at: datetime
    throttled_until: datetime
    rate_limit_pct: int
    decision_ref: Optional[dict] = None

@dataclass
class AuditEvent:
    ts: datetime
    action: str  # BLOCK_IP | THROTTLE_IP | LOG_ONLY | UNBLOCK_IP | UNTHROTTLE_IP | CLEANUP
    ip: Optional[str]
    detail: Dict

class PolicyStore:
    """
    WHY: Thread-safe, in-memory store that represents the enforcement layer of the SOAR.
    This is safe for demos: we don't touch OS/network stacks. Instead we track intended
    enforcement decisions that could be integrated with network devices later.
    """
    def __init__(self) -> None:
        self._blocked: Dict[str, BlockRecord] = {}
        self._throttled: Dict[str, ThrottleRecord] = {}
        self._audit: List[AuditEvent] = []
        self._lock = threading.Lock()

    # ---- Block operations ----
    def block_ip(self, ip: str, duration_minutes: int, reason: str, decision_ref: Optional[dict] = None) -> None:
        with self._lock:
            now = datetime.utcnow()
            rec = BlockRecord(
                ip=ip,
                reason=reason,
                blocked_at=now,
                blocked_until=now + timedelta(minutes=duration_minutes),
                decision_ref=decision_ref,
            )
            self._blocked[ip] = rec
            self._audit.append(AuditEvent(ts=now, action="BLOCK_IP", ip=ip, detail={
                "reason": reason,
                "duration_minutes": duration_minutes,
                "decision_ref": decision_ref or {}
            }))

    def unblock_ip(self, ip: str, reason: str = "manual") -> bool:
        with self._lock:
            existed = ip in self._blocked
            if existed:
                del self._blocked[ip]
            self._audit.append(AuditEvent(ts=datetime.utcnow(), action="UNBLOCK_IP", ip=ip, detail={
                "reason": reason
            }))
            return existed

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            rec = self._blocked.get(ip)
            if not rec:
                return False
            return rec.blocked_until > datetime.utcnow()

    def list_blocked(self) -> List[dict]:
        with self._lock:
            return [
                {
                    "ip": r.ip,
                    "reason": r.reason,
                    "blocked_at": r.blocked_at.isoformat() + "Z",
                    "blocked_until": r.blocked_until.isoformat() + "Z",
                    "decision_ref": r.decision_ref or {}
                }
                for r in self._blocked.values()
            ]

    # ---- Throttle operations ----
    def throttle_ip(self, ip: str, duration_minutes: int, reason: str, rate_limit_pct: int, decision_ref: Optional[dict] = None) -> None:
        with self._lock:
            now = datetime.utcnow()
            rec = ThrottleRecord(
                ip=ip,
                reason=reason,
                throttled_at=now,
                throttled_until=now + timedelta(minutes=duration_minutes),
                rate_limit_pct=rate_limit_pct,
                decision_ref=decision_ref,
            )
            self._throttled[ip] = rec
            self._audit.append(AuditEvent(ts=now, action="THROTTLE_IP", ip=ip, detail={
                "reason": reason,
                "duration_minutes": duration_minutes,
                "rate_limit_pct": rate_limit_pct,
                "decision_ref": decision_ref or {}
            }))

    def unthrottle_ip(self, ip: str, reason: str = "manual") -> bool:
        with self._lock:
            existed = ip in self._throttled
            if existed:
                del self._throttled[ip]
            self._audit.append(AuditEvent(ts=datetime.utcnow(), action="UNTHROTTLE_IP", ip=ip, detail={
                "reason": reason
            }))
            return existed

    def is_throttled(self, ip: str) -> bool:
        with self._lock:
            rec = self._throttled.get(ip)
            if not rec:
                return False
            return rec.throttled_until > datetime.utcnow()

    def list_throttled(self) -> List[dict]:
        with self._lock:
            return [
                {
                    "ip": r.ip,
                    "reason": r.reason,
                    "throttled_at": r.throttled_at.isoformat() + "Z",
                    "throttled_until": r.throttled_until.isoformat() + "Z",
                    "rate_limit_pct": r.rate_limit_pct,
                    "decision_ref": r.decision_ref or {}
                }
                for r in self._throttled.values()
            ]

    # ---- Audit ----
    def audit_log(self, limit: int = 200) -> List[dict]:
        with self._lock:
            return [
                {
                    "ts": e.ts.isoformat() + "Z",
                    "action": e.action,
                    "ip": e.ip,
                    "detail": e.detail,
                }
                for e in self._audit[-limit:]
            ]

    # ---- Maintenance ----
    def cleanup_expired(self) -> Dict[str, int]:
        """Remove expired block/throttle records and log cleanup."""
        removed = {"blocks": 0, "throttles": 0}
        with self._lock:
            now = datetime.utcnow()
            for ip, rec in list(self._blocked.items()):
                if rec.blocked_until <= now:
                    del self._blocked[ip]
                    removed["blocks"] += 1
            for ip, rec in list(self._throttled.items()):
                if rec.throttled_until <= now:
                    del self._throttled[ip]
                    removed["throttles"] += 1
            self._audit.append(AuditEvent(ts=now, action="CLEANUP", ip=None, detail=removed))
        return removed