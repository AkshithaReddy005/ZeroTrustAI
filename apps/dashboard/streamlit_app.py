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

st.set_page_config(
    page_title="AI-Powered NGFW Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🛡️ AI-Powered Next-Generation Firewall")
st.caption("Real-Time Threat Detection & Zero Trust Enforcement (POC)")
st.divider()

with st.sidebar:
    st.header("⚙️ Controls")
    auto_refresh = st.checkbox("Auto-refresh", value=True)
    refresh_sec = st.slider("Refresh interval (seconds)", min_value=1, max_value=10, value=1, step=1, help="Lower = more real-time updates")
    st.markdown("API: " + API_BASE)

    # Real-time mode only: no manual or simulated requests

col1, col2, col3, col4 = st.columns(4)
col1.metric("Threats Blocked", "12", "+2")
col2.metric("Anomalies Detected", "3", "+1")
col3.metric("Active Sessions", "124", "-5")
col4.metric("Detection Latency", "0.47 ms", "-0.12 ms")

st.subheader("🚨 Live Threat Feed")
try:
    resp = requests.get(f"{API_BASE}/events?limit=200", timeout=5)
    events = resp.json() if resp.ok else []
except Exception:
    events = []

# Only show explicit threat events
threats = [e["data"] for e in events if isinstance(e, dict) and e.get("type") == "threat" and isinstance(e.get("data"), dict)]
df = pd.DataFrame(threats)
if not df.empty:
    # Normalize fields for display
    if "severity" not in df.columns:
        df["severity"] = "LOW"
    if "flow_id" not in df.columns:
        df["flow_id"] = "-"
    for _, row in df.iloc[::-1].iterrows():
        sev = row.get("severity", "LOW")
        color = "#ff4444" if sev == "HIGH" else "#ffaa00" if sev == "MEDIUM" else "#00C851"
        st.markdown(f"""
        <div style='padding: 10px; margin: 5px 0; border-left: 4px solid {color}'>
            <strong>Flow:</strong> {row.get('flow_id','-')} &nbsp;|&nbsp;
            <strong>Label:</strong> {row.get('label','-')} &nbsp;|&nbsp;
            <strong>Severity:</strong> {sev} &nbsp;|&nbsp;
            <strong>Confidence:</strong> {row.get('confidence','-')} &nbsp;|&nbsp;
            <em>Reasons:</em> {', '.join(row.get('reason', []) if isinstance(row.get('reason'), list) else [])}
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("No threats yet. Use the sidebar to send a threat.")

st.markdown("---")

st.subheader("📊 Threat Distribution")
if not df.empty:
    if "severity" in df.columns:
        counts = df["severity"].value_counts()
        fig_pie = go.Figure(data=[go.Pie(labels=counts.index, values=counts.values, hole=0.4)])
        st.plotly_chart(fig_pie, use_container_width=True)

st.markdown("---")

st.subheader("🧾 Recent Incidents")
incidents = []
try:
    r = requests.get(f"{API_BASE}/incidents", timeout=5)
    if r.ok:
        incidents = r.json()
except Exception:
    incidents = []

if incidents:
    for inc in incidents[-50:][::-1]:
        t = inc.get("threat", {})
        sev = t.get("severity", "LOW")
        color = "#ff4444" if sev == "HIGH" else "#ffaa00" if sev == "MEDIUM" else "#00C851"
        st.markdown(f"""
        <div style='padding: 10px; margin: 6px 0; border-left: 4px solid {color}'>
            <strong>Incident:</strong> {inc.get('incident_id','-')} &nbsp;|&nbsp; <strong>Flow:</strong> {t.get('flow_id','-')} &nbsp;|&nbsp; <strong>Label:</strong> {t.get('label','-')} &nbsp;|&nbsp; <strong>Severity:</strong> {sev} &nbsp;|&nbsp; <strong>Actions:</strong> {', '.join(inc.get('actions', []))}
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("No incidents yet. Use the sidebar form to send a malicious threat to trigger a block.")

st.subheader("🗺️ Anomaly Heatmap (Sample)")
hours = list(range(24))
days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
heat = np.random.poisson(lam=2, size=(7,24))
heat[4:6, 18:22] = np.random.poisson(lam=10, size=(2,4))
fig_heat = go.Figure(data=go.Heatmap(z=heat, x=hours, y=days, colorscale='Reds'))
st.plotly_chart(fig_heat, use_container_width=True)

if auto_refresh:
    time.sleep(refresh_sec)
    st.rerun()
