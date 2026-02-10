import os
import time
import requests
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")


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
</div>
""".format(API_BASE),
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
    threats_df["severity"] = threats_df.get("severity", "LOW").fillna("LOW")
    threats_df["label"] = threats_df.get("label", "unknown").fillna("unknown")
    threats_df["confidence"] = pd.to_numeric(threats_df.get("confidence", 0.0), errors="coerce").fillna(0.0)
    threats_df["reason"] = threats_df.get("reason", [[]])
    threats_df["event_dt"] = threats_df["event_timestamp"].apply(_parse_iso)
    threats_df = threats_df.sort_values("event_timestamp", ascending=False, na_position="last")

malicious_count = int(metrics.get("threats_detected", 0))
blocked_count = int(metrics.get("blocked_flows", 0))
if blocked_count == 0 and decisions:
    blocked_count = len([d for d in decisions if str(d.get("decision", "")).lower() == "deny"])

cards = st.columns(4)
cards[0].markdown(
    f"<div class='zta-card'><div class='zta-title'>Total Flows</div><div class='zta-value zta-accent'>{total_flows}</div></div>",
    unsafe_allow_html=True,
)
cards[1].markdown(
    f"<div class='zta-card'><div class='zta-title'>Threats Detected</div><div class='zta-value zta-danger'>{malicious_count}</div></div>",
    unsafe_allow_html=True,
)
cards[2].markdown(
    f"<div class='zta-card'><div class='zta-title'>Blocked</div><div class='zta-value zta-warn'>{blocked_count}</div></div>",
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
            sev = str(row.get("severity", "LOW")).upper()
            sev_cls = "sev-low"
            if sev == "HIGH" or sev == "CRITICAL":
                sev_cls = "sev-high"
            elif sev == "MEDIUM":
                sev_cls = "sev-medium"

            ts = row.get("event_timestamp") or row.get("timestamp")
            tss = "-"
            dt = _parse_iso(ts) if isinstance(ts, str) else None
            if dt:
                tss = dt.strftime("%I:%M:%S %p")

            flow_id = row.get("flow_id", "-")
            label = row.get("label", "-")
            conf = float(row.get("confidence", 0.0))
            attack = row.get("attack_type") or "—"
            blocked = "Yes" if bool(row.get("blocked", False)) else "No"
            reasons = row.get("reason", [])
            if not isinstance(reasons, list):
                reasons = []

            left.markdown(
                """
                <div class="threat-row">
                  <div style="display:flex; align-items:center; gap:10px;">
                    <span class="sev-pill {}">{}</span>
                    <span style="font-size:12px; color:#9ca3af;">{}</span>
                    <span style="margin-left:auto; font-size:11px; color:#9ca3af;">Flow: {}</span>
                  </div>
                  <div style="display:grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap:8px; margin-top:8px; font-size:12px; color:#e5e7eb;">
                    <div><span style="color:#9ca3af;">Label:</span> <b>{}</b></div>
                    <div><span style="color:#9ca3af;">Confidence:</span> {}%</div>
                    <div><span style="color:#9ca3af;">Attack:</span> {}</div>
                    <div><span style="color:#9ca3af;">Blocked:</span> {}</div>
                  </div>
                  <div style="margin-top:6px; font-size:11px; color:#cbd5e1;">Reason: {}</div>
                </div>
                """.format(
                    sev_cls,
                    sev,
                    tss,
                    flow_id,
                    label,
                    int(round(conf * 100)),
                    attack,
                    blocked,
                    ", ".join(reasons) if reasons else "-",
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
    if threats_df.empty or threats_df.get("event_dt").isna().all():
        st.info("No timeline data yet")
    else:
        tdf = threats_df.dropna(subset=["event_dt"]).copy()
        tdf["minute"] = tdf["event_dt"].dt.strftime("%H:%M")
        cnt = tdf.groupby("minute").size().reset_index(name="count")
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
        sev_counts = threats_df["severity"].astype(str).str.upper().value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        fig2 = px.pie(sev_counts, names="severity", values="count", hole=0.5)
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


time.sleep(5)
st.rerun()
