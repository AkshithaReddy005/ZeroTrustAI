"""
app.py

WHY: Minimal FastAPI microservice exposing SOAR status APIs and bootstrapping the
SoarWorker. This is the interface for listing blocked IPs, checking status, and
viewing audit logs. It keeps the demo self-contained and easy to operate.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict

from policy_store import PolicyStore
from soar_engine import SoarEngine
from soar_worker import SoarWorker

API_GATEWAY_DECISIONS_URL = "http://localhost:8000/decisions"  # expected Phase 3 output

app = FastAPI(title="ZeroTrust SOAR", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"]
)

# Bootstrap in-memory store, engine, and worker
STORE = PolicyStore()
ENGINE = SoarEngine()
WORKER = SoarWorker(policy_store=STORE, engine=ENGINE, decisions_url=API_GATEWAY_DECISIONS_URL, poll_interval_sec=2)

@app.on_event("startup")
async def on_startup():
    # Start the real-time worker
    WORKER.start()

@app.on_event("shutdown")
async def on_shutdown():
    WORKER.stop()

@app.get("/health")
async def health():
    return {"status": "ok", "worker_running": True}

@app.get("/blocked")
async def list_blocked():
    return STORE.list_blocked()

@app.get("/blocked/{ip}")
async def is_blocked(ip: str):
    return {"ip": ip, "blocked": STORE.is_blocked(ip)}

@app.get("/throttled")
async def list_throttled():
    return STORE.list_throttled()

@app.get("/throttled/{ip}")
async def is_throttled(ip: str):
    return {"ip": ip, "throttled": STORE.is_throttled(ip)}

@app.get("/audit")
async def audit(limit: int = 200):
    return STORE.audit_log(limit=limit)
