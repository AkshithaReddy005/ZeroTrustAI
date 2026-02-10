"""
soar_worker.py

WHY: Real-time processor that consumes Phase 3 (Zero Trust Engine) risk decisions
and applies the SoarEngine rules, updating PolicyStore. This ensures the SOAR layer
operates on real decisions and provides immediate enforcement state.
"""
import time
import threading
from typing import Callable, Dict, Optional
import requests

from policy_store import PolicyStore
from soar_engine import SoarEngine

class SoarWorker:
    """
    Polls an API Gateway endpoint that emits Phase 3 decisions. For hackathon clarity,
    we implement safe polling over HTTP, avoiding complex messaging systems.
    """
    def __init__(self, policy_store: PolicyStore, engine: SoarEngine, decisions_url: str, poll_interval_sec: int = 2):
        self.policy_store = policy_store
        self.engine = engine
        self.decisions_url = decisions_url
        self.poll_interval_sec = poll_interval_sec
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._last_ts: float = 0.0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="SoarWorker", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self):
        while not self._stop.is_set():
            try:
                self.policy_store.cleanup_expired()
                # We fetch decisions newer than last_ts if supported; else full list
                params = {"since": self._last_ts} if self._last_ts else {}
                resp = requests.get(self.decisions_url, params=params, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    decisions = data if isinstance(data, list) else data.get("decisions", [])
                    for dec in decisions:
                        ts = float(dec.get("timestamp", 0))
                        self._last_ts = max(self._last_ts, ts)
                        action, params = self.engine.decide(dec)
                        if action == "BLOCK_IP" and params.get("ip"):
                            self.policy_store.block_ip(
                                ip=params["ip"],
                                duration_minutes=int(params["duration_minutes"]),
                                reason=params["reason"],
                                decision_ref=params.get("decision_ref"),
                            )
                        elif action == "THROTTLE_IP" and params.get("ip"):
                            self.policy_store.throttle_ip(
                                ip=params["ip"],
                                duration_minutes=int(params["duration_minutes"]),
                                reason=params["reason"],
                                rate_limit_pct=int(params.get("rate_limit_pct", 50)),
                                decision_ref=params.get("decision_ref"),
                            )
                        else:
                            # Log-only audit entry for transparency
                            self.policy_store._audit.append({
                                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                "action": "LOG_ONLY",
                                "ip": params.get("ip"),
                                "detail": params,
                            })
                else:
                    # Backoff on non-200 responses
                    time.sleep(self.poll_interval_sec)
            except Exception as e:
                # Robustness: don't crash the worker; log and continue
                self.policy_store._audit.append({
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "action": "ERROR",
                    "ip": None,
                    "detail": {"err": str(e)}
                })
            finally:
                time.sleep(self.poll_interval_sec)