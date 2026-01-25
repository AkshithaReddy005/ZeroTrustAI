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
    auto_refresh = st.checkbox("Auto-refresh (5s)", value=True)
    st.markdown("API: " + API_BASE)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Threats Blocked", "12", "+2")
col2.metric("Anomalies Detected", "3", "+1")
col3.metric("Active Sessions", "124", "-5")
col4.metric("Detection Latency", "0.47 ms", "-0.12 ms")

st.subheader("🚨 Live Threat Feed")
try:
    resp = requests.get(f"{API_BASE}/samples/threats", timeout=3)
    data = resp.json()
except Exception:
    data = []

df = pd.DataFrame(data)
if not df.empty:
    for _, row in df.iterrows():
        color = "#ff4444" if row["severity"]=="HIGH" else "#ffaa00" if row["severity"]=="MEDIUM" else "#00C851"
        st.markdown(f"""
        <div style='padding: 10px; margin: 5px 0; border-left: 4px solid {color}'>
            <strong>{row['timestamp']}</strong> -
            <span>{row['severity']}</span>
            <strong>{row['threat_type']}</strong> from {row['source_ip']} -
            <em>{row['status']}</em>
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("Waiting for API...")

st.markdown("---")

st.subheader("📊 Threat Distribution")
if not df.empty:
    counts = df["threat_type"].value_counts()
    fig_pie = go.Figure(data=[go.Pie(labels=counts.index, values=counts.values, hole=0.4)])
    st.plotly_chart(fig_pie, use_container_width=True)

st.markdown("---")

st.subheader("🗺️ Anomaly Heatmap (Sample)")
hours = list(range(24))
days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
heat = np.random.poisson(lam=2, size=(7,24))
heat[4:6, 18:22] = np.random.poisson(lam=10, size=(2,4))
fig_heat = go.Figure(data=go.Heatmap(z=heat, x=hours, y=days, colorscale='Reds'))
st.plotly_chart(fig_heat, use_container_width=True)

if auto_refresh:
    time.sleep(5)
    st.rerun()
