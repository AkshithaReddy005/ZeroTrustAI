"""
soar_engine.py

WHY: Deterministic, explainable playbook that translates Phase 3 decisions
into safe actions — block, throttle, or log — without any ML. This ensures
hackathon-ready clarity and Zero Trust enforcement.
"""
from typing import Dict, Tuple

class SoarEngine:
    """
    Rule-based engine applying explicit playbooks over risk decisions.
    Input is a Phase 3 decision dict like:
    {
      "flow_id": str,
      "src_ip": str,
      "risk_score": int,  # 0-100
      "decision": "allow" | "restrict" | "deny",
      "reasons": list[str],
      "timestamp": float
    }
    Output is an action tuple: (action, params)
    where action in {"BLOCK_IP", "THROTTLE_IP", "LOG_ONLY"}.
    """

    def decide(self, decision: Dict) -> Tuple[str, Dict]:
        score = int(decision.get("risk_score", 0))
        dval = str(decision.get("decision", "allow")).lower()
        src_ip = decision.get("src_ip") or decision.get("client_ip")
        flow_id = decision.get("flow_id")
        reasons = decision.get("reasons", [])

        # Playbook 1: High-risk deny => block
        if dval == "deny" and score >= 80:
            return (
                "BLOCK_IP",
                {
                    "ip": src_ip,
                    "duration_minutes": 60,  # demo-safe 1 hour block
                    "reason": f"deny/high_risk({score})",
                    "decision_ref": {
                        "flow_id": flow_id,
                        "risk_score": score,
                        "decision": dval,
                        "reasons": reasons,
                    },
                },
            )

        # Playbook 2: Restrict mid-risk => throttle
        if dval == "restrict" and 50 <= score < 80:
            return (
                "THROTTLE_IP",
                {
                    "ip": src_ip,
                    "duration_minutes": 30,  # demo-safe 30 minutes
                    "reason": f"restrict/mid_risk({score})",
                    "rate_limit_pct": 50,  # symbolic rate limit
                    "decision_ref": {
                        "flow_id": flow_id,
                        "risk_score": score,
                        "decision": dval,
                        "reasons": reasons,
                    },
                },
            )

        # Default: log-only
        return (
            "LOG_ONLY",
            {
                "ip": src_ip,
                "reason": f"{dval}/risk({score})",
                "decision_ref": {
                    "flow_id": flow_id,
                    "risk_score": score,
                    "decision": dval,
                    "reasons": reasons,
                },
            },
        )
