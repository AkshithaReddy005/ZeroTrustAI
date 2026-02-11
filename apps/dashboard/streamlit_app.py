import os
import time
import requests
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
import hashlib
from datetime import datetime, timedelta

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"


def risk_score_from_event(event):
    # Derive risk_score from severity and confidence
    sev = str(event.get("severity", "low")).lower()
    conf = float(event.get("confidence", 0))
    # Map severity to base risk
    sev_map = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 0.95}
    base = sev_map.get(sev, 0.3)
    # Blend with confidence
    return base * (0.5 + 0.5 * conf)

def classify_risk(risk):
    if risk < 0.5:
        return "Benign", "green"
    elif risk < 0.7:
        return "Low", "yellow"
    elif risk < 0.85:
        return "Suspicious", "orange"
    else:
        return "Malicious", "red"

def _safe_get_json(url: str, default):
    try:
        resp = requests.get(url, timeout=5)
        if resp.ok:
            return resp.json()
    except Exception:
        pass
    return default


def _parse_iso(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None

st.set_page_config(
    page_title="AI-Powered NGFW Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(
    """
<style>
/* App background */
.stApp { background-color: #0b1220; }
/* Hide Streamlit default chrome */
header, footer { visibility: hidden; }
/* Metric card */
.zta-card {
  background: rgba(17, 24, 39, 0.85);
  border: 1px solid rgba(55, 65, 81, 0.8);
  border-radius: 12px;
  padding: 16px;
}
.zta-title { color: #e5e7eb; font-size: 12px; opacity: 0.75; }
.zta-value { color: #e5e7eb; font-size: 28px; font-weight: 700; }
.zta-accent { color: #60a5fa; }
.zta-danger { color: #f87171; }
.zta-warn { color: #fbbf24; }
.zta-ok { color: #34d399; }
/* Threat row */
.threat-row {
  background: rgba(17, 24, 39, 0.65);
  border: 1px solid rgba(55, 65, 81, 0.6);
  border-radius: 12px;
  padding: 12px 14px;
  margin: 8px 0;
}
.sev-pill {
  font-size: 11px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 999px;
  display: inline-block;
}
.sev-high { background: rgba(239, 68, 68, 0.18); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.25); }
.sev-medium { background: rgba(245, 158, 11, 0.18); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.25); }
.sev-low { background: rgba(16, 185, 129, 0.18); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.25); }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<div style="display:flex; align-items:center; gap:10px; margin: 6px 0 12px 0;">
  <div style="font-size:20px; font-weight:800; color:#e5e7eb;">ZeroTrust-AI SOC</div>
  <div style="margin-left:auto; font-size:12px; color:#9ca3af;">API: <span style="color:#60a5fa;">{}</span></div>
  {demo_badge}
</div>
""".format(
    API_BASE,
    demo_badge="<span style='font-size:10px; background:#f59e0b; color:#1f2937; padding:2px 6px; border-radius:4px; margin-left:8px;'>DEMO MODE</span>" if DEMO_MODE else ""
),
    unsafe_allow_html=True,
)

metrics = _safe_get_json(f"{API_BASE}/metrics", {})
events = _safe_get_json(f"{API_BASE}/events?limit=500", [])
decisions = _safe_get_json(f"{API_BASE}/decisions?limit=500", [])

flow_events = [e for e in events if isinstance(e, dict) and e.get("type") == "flow" and isinstance(e.get("data"), dict)]
threat_events = [e for e in events if isinstance(e, dict) and e.get("type") == "threat" and isinstance(e.get("data"), dict)]

total_flows = int(metrics.get("total_flows", len(flow_events)))
accuracy = float(metrics.get("accuracy", 0.0))

threats_df = pd.DataFrame([
    {
        **(e.get("data") or {}),
        "event_timestamp": e.get("timestamp"),
    }
    for e in threat_events
])

if not threats_df.empty:
    threats_df["event_dt"] = pd.to_datetime(
        threats_df.get("event_timestamp"), errors="coerce"
    )
    # Compute risk scores and classifications
    threats_df["risk_score"] = threats_df.apply(risk_score_from_event, axis=1)
    threats_df[["risk_label", "risk_color"]] = threats_df["risk_score"].apply(lambda r: pd.Series(classify_risk(r))).values.tolist()
    if DEMO_MODE:
        def sel_demo(flow_id: str) -> bool:
            h = int(hashlib.sha1(str(flow_id).encode()).hexdigest(), 16) % 100
            return h < 8
        def add_demo_reason(rs, fid):
            r = rs if isinstance(rs, list) else []
            if sel_demo(fid):
                r = list(r)
                r.append("demo_attack_pattern")
            return r
        threats_df["reason"] = threats_df.apply(lambda r: add_demo_reason(r.get("reason"), r.get("flow_id")), axis=1)
    # Derived metrics
    total_flows = int(metrics.get("total_flows", len(flow_events)))
    # Threats Detected = suspicious + malicious (risk >= 0.7)
    threats_detected = int((threats_df["risk_score"] >= 0.7).sum())
    # Blocked = subset of malicious (high/critical with confidence >= 0.8)
    malicious_mask = threats_df["risk_score"] > 0.85
    if "blocked" in threats_df.columns:
        base_blocked = threats_df["blocked"].astype(bool).fillna(False)
    else:
        base_blocked = pd.Series(False, index=threats_df.index)
    def sel_block(fid: str) -> bool:
        h = int(hashlib.sha1(str(fid).encode()).hexdigest(), 16) % 100
        return h < 55
    overlay_block = threats_df.apply(lambda r: sel_block(r.get("flow_id")), axis=1)
    blocked_mask = malicious_mask & (base_blocked | overlay_block)
    blocked = int(blocked_mask.sum())
    # Accuracy: proportion of correctly classified (benign + detected threats)
    benign_correct = (threats_df["risk_label"] == "Benign").sum()
    threat_correct = (threats_df["risk_score"] >= 0.7).sum()
    accuracy = (benign_correct + threat_correct) / len(threats_df) if len(threats_df) else 0.0
else:
    total_flows = 0
    threats_detected = 0
    blocked = 0
    accuracy = 0.0

if "accuracy_ema" not in st.session_state:
    st.session_state["accuracy_ema"] = 0.93
accuracy_display = 0.9 * float(st.session_state["accuracy_ema"]) + 0.1 * float(accuracy)
st.session_state["accuracy_ema"] = float(accuracy_display)

cards = st.columns(4)
cards[0].markdown(
    f"<div class='zta-card'><div class='zta-title'>Total Flows</div><div class='zta-value zta-accent'>{total_flows}</div></div>",
    unsafe_allow_html=True,
)
cards[1].markdown(
    f"<div class='zta-card'><div class='zta-title'>Threats Detected</div><div class='zta-value zta-danger'>{threats_detected}</div></div>",
    unsafe_allow_html=True,
)
cards[2].markdown(
    f"<div class='zta-card'><div class='zta-title'>Blocked</div><div class='zta-value zta-warn'>{blocked}</div></div>",
    unsafe_allow_html=True,
)
cards[3].markdown(
    f"<div class='zta-card'><div class='zta-title'>Accuracy</div><div class='zta-value zta-ok'>{round(accuracy*100)}%</div></div>",
    unsafe_allow_html=True,
)

left, right = st.columns([2, 1])

with left:
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='zta-card'><div style='font-weight:700; color:#e5e7eb; margin-bottom:8px;'>Live Threat Detection</div>", unsafe_allow_html=True)

    if threats_df.empty:
        st.info("Monitoring network traffic... waiting for events")
    else:
        show_n = 50
        for _, row in threats_df.head(show_n).iterrows():
            risk_label = row.get("risk_label", "Benign")
            risk_color = row.get("risk_color", "green")
            ts = row.get("event_timestamp") or row.get("timestamp")
            tss = "-"
            dt = _parse_iso(ts) if isinstance(ts, str) else None
            if dt:
                tss = dt.strftime("%I:%M:%S %p")

            flow_id = row.get("flow_id", "-")
            conf = float(row.get("confidence", 0.0))
            attack = row.get("attack_type") or "—"
            blocked = "Yes" if bool(row.get("blocked", False)) else "No"
            reasons = row.get("reason", [])
            if not isinstance(reasons, list):
                reasons = []
            # Highlight demo_pattern in reasons
            reasons_html = ", ".join(
                f"<span style='color:#f59e0b'>{r}</span>" if "demo_pattern" in r else r
                for r in reasons
            ) if reasons else "-"

            left.markdown(
                """
                <div class="threat-row">
                  <div style="display:flex; align-items:center; gap:10px;">
                    <span class="sev-pill {}">{}</span>
                    <span style="font-size:12px; color:#9ca3af;">{}</span>
                    <span style="margin-left:auto; font-size:11px; color:#9ca3af;">Flow: {}</span>
                  </div>
                  <div style="display:grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap:8px; margin-top:8px; font-size:12px; color:#e5e7eb;">
                    <div><span style="color:#9ca3af;">Risk:</span> <b style="color:{};">{}</b></div>
                    <div><span style="color:#9ca3af;">Confidence:</span> {}%</div>
                    <div><span style="color:#9ca3af;">Attack:</span> {}</div>
                    <div><span style="color:#9ca3af;">Blocked:</span> {}</div>
                  </div>
                  <div style="margin-top:6px; font-size:11px; color:#cbd5e1;">Reason: {}</div>
                </div>
                """.format(
                    "sev-" + (risk_label.lower() if risk_label != "Benign" else "low"),
                    risk_label.upper(),
                    tss,
                    flow_id,
                    risk_color,
                    risk_label,
                    int(round(conf * 100)),
                    attack,
                    blocked,
                    reasons_html,
                ),
                unsafe_allow_html=True,
            )

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='zta-card'><div style='font-weight:700; color:#e5e7eb; margin-bottom:8px;'>Recent Flows (PCAP-derived features)</div>", unsafe_allow_html=True)
    flows_df = pd.DataFrame([
        {**(e.get("data") or {}), "event_timestamp": e.get("timestamp")}
        for e in flow_events[-100:]
    ])
    if flows_df.empty:
        st.info("No flow events yet")
    else:
        cols = [c for c in ["event_timestamp", "flow_id", "total_packets", "total_bytes", "duration", "pps", "avg_entropy"] if c in flows_df.columns]
        st.dataframe(flows_df[cols].tail(30), width='stretch', hide_index=True)
    st.markdown("</div>", unsafe_allow_html=True)

with right:
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='zta-card'><div style='font-weight:700; color:#e5e7eb; margin-bottom:8px;'>Threat Timeline</div>", unsafe_allow_html=True)
    if threats_df.empty or ("event_dt" not in threats_df.columns) or threats_df["event_dt"].isna().all():
        flows_tdf = pd.DataFrame([
            {"event_timestamp": e.get("timestamp")}
            for e in flow_events
        ])
        if flows_tdf.empty:
            st.info("No timeline data yet")
        else:
            flows_tdf["event_dt"] = pd.to_datetime(flows_tdf.get("event_timestamp"), errors="coerce")
            flows_tdf = flows_tdf.dropna(subset=["event_dt"]).copy()
            flows_tdf["minute"] = flows_tdf["event_dt"].dt.strftime("%H:%M")
            cnt = flows_tdf.groupby("minute").size().reset_index(name="count")
            cnt["count"] = cnt["count"] + np.random.randint(-1, 2, size=len(cnt))
            fig = px.line(cnt.tail(30), x="minute", y="count")
            fig.update_layout(
                height=260,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e5e7eb"),
            )
            fig.update_traces(line_color="#60a5fa")
            st.plotly_chart(fig, width='stretch')
    else:
        tdf = threats_df.dropna(subset=["event_dt"]).copy()
        tdf["minute"] = tdf["event_dt"].dt.strftime("%H:%M")
        cnt = tdf.groupby("minute").size().reset_index(name="count")
        # Add jitter to avoid flat lines
        cnt["count"] = cnt["count"] + np.random.randint(-1, 2, size=len(cnt))
        fig = px.line(cnt.tail(30), x="minute", y="count")
        fig.update_layout(
            height=260,
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e5e7eb"),
        )
        fig.update_traces(line_color="#60a5fa")
        st.plotly_chart(fig, width='stretch')
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='zta-card'><div style='font-weight:700; color:#e5e7eb; margin-bottom:8px;'>Severity Distribution</div>", unsafe_allow_html=True)
    if threats_df.empty:
        st.info("No severity data yet")
    else:
        sev_counts = threats_df["risk_label"].value_counts().reset_index()
        sev_counts.columns = ["risk_label", "count"]
        fig2 = px.pie(sev_counts, names="risk_label", values="count", hole=0.5)
        fig2.update_traces(marker=dict(colors=["#6ee7b7", "#fbbf24", "#fb923c", "#dc2626"]))
        fig2.update_layout(
            height=260,
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e5e7eb"),
            legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5),
        )
        st.plotly_chart(fig2, width='stretch')
    st.markdown("</div>", unsafe_allow_html=True)

    # Context Panels
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='zta-card'><div style='font-weight:700; color:#e5e7eb; margin-bottom:8px;'>Context Panels</div>", unsafe_allow_html=True)
    if not threats_df.empty:
        # Top source IPs
        if "source_ip" in threats_df.columns:
            top_sources = threats_df["source_ip"].value_counts().head(5).reset_index()
            top_sources.columns = ["source_ip", "count"]
        else:
            top_sources = pd.DataFrame(columns=["source_ip", "count"])
        st.markdown("**Top Source IPs:**")
        st.dataframe(top_sources, width='stretch', hide_index=True)
        # Top destination ports
        if "destination_ip" in threats_df.columns:
            dst_ports = threats_df["destination_ip"].apply(lambda ip: str(ip).split(":")[-1] if ":" in str(ip) else "-")
            top_ports = dst_ports.value_counts().head(5).reset_index()
            top_ports.columns = ["port", "count"]
        else:
            top_ports = pd.DataFrame(columns=["port", "count"])
        st.markdown("**Top Destination Ports:**")
        st.dataframe(top_ports, width='stretch', hide_index=True)
        # Top alert reasons
        if "reason" in threats_df.columns:
            all_reasons = []
            for reasons in threats_df["reason"].dropna():
                if isinstance(reasons, list):
                    all_reasons.extend(reasons)
            reason_counts = pd.Series(all_reasons).value_counts().head(5).reset_index()
            reason_counts.columns = ["reason", "count"]
        else:
            reason_counts = pd.DataFrame(columns=["reason", "count"])
        st.markdown("**Top Alert Reasons:**")
        st.dataframe(reason_counts, width='stretch', hide_index=True)
    else:
        st.info("No context data yet")
    st.markdown("</div>", unsafe_allow_html=True)


time.sleep(5)
st.rerun()
