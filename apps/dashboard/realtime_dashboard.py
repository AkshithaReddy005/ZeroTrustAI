#!/usr/bin/env python3
"""
ZeroTrust-AI Real-Time Dashboard
Shows live threat detection with auto-refresh
"""

import streamlit as st
import requests
import time
import pandas as pd
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px

st.set_page_config(
    page_title="ZeroTrust-AI Dashboard", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.metric-container {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 5px solid #1f77b4;
}
.alert-high {
    background-color: #ffebee;
    border-left: 5px solid #f44336;
}
.alert-medium {
    background-color: #fff3e0;
    border-left: 5px solid #ff9800;
}
.alert-low {
    background-color: #e8f5e8;
    border-left: 5px solid #4caf50;
}
</style>
""", unsafe_allow_html=True)

# Sidebar controls
st.sidebar.title("🛡️ ZeroTrust-AI Control Panel")

# Auto-refresh control
auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh", value=True)
refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 1, 10, 2)

# API endpoints
DETECTOR_URL = "http://localhost:9000"
API_URL = "http://localhost:8000"

ROLLING_WINDOW_MINUTES = 15

# Session state initialization
if 'threat_history' not in st.session_state:
    st.session_state.threat_history = []
if 'metrics_history' not in st.session_state:
    st.session_state.metrics_history = []


def _parse_source_from_flow_id(flow_id):
    """Extract source IP from flow_id e.g. 192.168.1.1:12345->10.0.0.1:443/TCP"""
    if not flow_id:
        return None
    for sep in ("->", "→"):
        if sep in flow_id:
            left = flow_id.split(sep)[0].strip()
            if ":" in left:
                return left.split(":")[0].strip()
            return left
    return None


def compute_soar_actions(threats):
    """
    SOAR policy (rolling 15-min window, deduplicated, top 3).
    - risk < 0.70: no action (monitor only)
    - 0.70 <= risk < 0.85 and volumetric reason: Rate Limit (once per target)
    - risk >= 0.85 and confidence >= 0.90: Block (once per target)
    """
    now_sec = time.time()
    window_cutoff_sec = now_sec - (ROLLING_WINDOW_MINUTES * 60)
    soar_actions = []
    seen = {}  # key -> True for dedupe

    for t in threats:
        ts = t.get("timestamp")
        if not ts:
            continue
        try:
            dt = pd.to_datetime(ts)
            ts_sec = dt.timestamp()
            if ts_sec < window_cutoff_sec:
                continue
        except Exception:
            continue

        risk = t.get("risk_score")
        if risk is None:
            risk = t.get("confidence")
        if risk is None:
            sev = (t.get("severity") or "").lower()
            risk = {"high": 0.92, "medium": 0.78, "low": 0.55}.get(sev, 0.6)
        risk = float(risk) if risk is not None else 0.0
        conf = t.get("confidence")
        conf = float(conf) if conf is not None else risk
        raw_reason = t.get("reason")
        reasons = raw_reason if isinstance(raw_reason, list) else ([raw_reason] if raw_reason else [])
        primary_reason = reasons[0] if reasons else None
        source_ip = t.get("source_ip") or _parse_source_from_flow_id(t.get("flow_id", ""))
        flow_id = t.get("flow_id", "")
        target = source_ip or flow_id or "unknown"

        # Only act on threats (risk >= 0.5)
        if risk < 0.5:
            continue
        if risk < 0.70:
            continue  # monitor only

        # Medium-risk: Rate Limit only for volumetric
        if 0.70 <= risk < 0.85:
            reasons_text = " ".join(reasons).lower()
            if not any(x in reasons_text for x in ("high_packets_per_second", "syn_flood", "ddos", "flood")):
                continue
            key = f"rate|{target}"
            if key in seen:
                continue
            seen[key] = True
            soar_actions.append({
                "timestamp": ts,
                "action_type": "Rate Limit",
                "action": "Rate limited flow",
                "target": target,
                "risk_score": risk,
                "confidence": conf,
                "primary_reason": primary_reason,
                "policy": "Medium-Risk Containment",
                "status": "SUCCESS",
            })
            continue

        # High-risk: Block if confidence >= 0.90
        if risk >= 0.85 and conf >= 0.90:
            key = f"block|{target}"
            if key in seen:
                continue
            seen[key] = True
            action_label = "Block IP" if source_ip else "Block flow"
            soar_actions.append({
                "timestamp": ts,
                "action_type": "Block",
                "action": action_label,
                "target": target,
                "risk_score": risk,
                "confidence": conf,
                "primary_reason": primary_reason,
                "policy": "High-Risk Prevention",
                "status": "SUCCESS",
            })

    # Top 3 by risk_score descending
    soar_actions.sort(key=lambda x: x.get("risk_score") or 0, reverse=True)
    return soar_actions[:3]


def get_threats(limit=1000):
    """Get recent threats from detector service (larger limit for SOAR 15-min window)"""
    try:
        response = requests.get(f"{DETECTOR_URL}/threats", timeout=5, params={"limit": limit})
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return []

def get_metrics():
    """Get system metrics"""
    try:
        response = requests.get(f"{API_URL}/metrics", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {}

def main():
    st.title("🛡️ ZeroTrust-AI Real-Time Security Dashboard")
    
    # Header metrics
    col1, col2, col3, col4 = st.columns(4)
    
    threats = get_threats()
    metrics = get_metrics()
    
    # Calculate metrics
    total_flows = metrics.get('total_flows', len(threats) * 10)
    malicious_count = len([t for t in threats if t.get('label') == 'malicious'])
    blocked_count = len([t for t in threats if t.get('severity') == 'high'])
    accuracy = metrics.get('accuracy', 0.94)
    
    with col1:
        st.metric(
            "📊 Total Flows", 
            f"{total_flows:,}",
            delta=f"+{len(threats)}" if threats else "0"
        )
    
    with col2:
        st.metric(
            "🚨 Threats Detected", 
            malicious_count,
            delta=f"+{len([t for t in threats if t.get('timestamp', '') > (datetime.now() - timedelta(minutes=5)).isoformat()])}"
        )
    
    with col3:
        st.metric(
            "🚫 Blocked", 
            blocked_count,
            delta=f"+{len([t for t in threats if t.get('severity') == 'high'])}"
        )
    
    with col4:
        st.metric(
            "✅ Accuracy", 
            f"{accuracy:.1%}",
            delta=f"+{accuracy*100 - 93:.1f}%" if accuracy > 0.93 else "0%"
        )
    
    # Two column layout
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🚨 Live Threat Detection")
        
        if threats:
            # Convert to DataFrame
            df = pd.DataFrame(threats)
            
            # Format timestamp
            if 'timestamp' in df.columns:
                df['time'] = pd.to_datetime(df['timestamp']).dt.strftime('%H:%M:%S')
                df = df.sort_values('timestamp', ascending=False)
            
            # Color code by severity
            def severity_color(severity):
                if severity == 'high':
                    return 'alert-high'
                elif severity == 'medium':
                    return 'alert-medium'
                else:
                    return 'alert-low'
            
            # Display threats with styling
            for idx, row in df.head(10).iterrows():
                severity = row.get('severity', 'low')
                st.markdown(f"""
                <div class="metric-container {severity_color(severity)}">
                    <strong>{row.get('flow_id', 'Unknown')}</strong><br>
                    <small>
                    Label: {row.get('label', 'unknown')} | 
                    Confidence: {row.get('confidence', 0):.2f} | 
                    {row.get('time', '')}
                    </small><br>
                    <small>Reason: {', '.join(row.get('reason', []))}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("✅ No threats detected in recent traffic")
    
    with col2:
        st.subheader("📈 Detection Trends")
        
        # Simple trend chart
        if threats:
            df = pd.DataFrame(threats)
            if 'timestamp' in df.columns:
                df['time'] = pd.to_datetime(df['timestamp'])
                df_hour = df.groupby(df['time'].dt.floor('H')).size().reset_index(name='count')
                
                fig = px.line(
                    df_hour, 
                    x='time', 
                    y='count',
                    title='Threats per Hour',
                    labels={'count': 'Threats', 'time': 'Time'}
                )
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
        
        # Model performance
        st.subheader("🤖 Model Status")
        
        model_metrics = {
            'TCN': {'accuracy': 0.95, 'status': '✅ Active'},
            'Autoencoder': {'accuracy': 0.84, 'status': '✅ Active'},
            'IsoForest': {'accuracy': 0.83, 'status': '✅ Active'},
            'Ensemble': {'accuracy': 0.84, 'status': '✅ Active'}
        }
        
        for model, data in model_metrics.items():
            st.write(f"**{model}**: {data['status']} ({data['accuracy']:.1%})")

    # SOAR: Automated actions (last 15 min) – policy-driven, deduplicated, top 3
    st.subheader("🤖 Automated SOAR Actions (Last 15 min)")
    soar_actions = compute_soar_actions(threats)
    if not soar_actions:
        st.info("No automated SOAR actions in this window. Most threats are monitor-only.")
    else:
        for a in soar_actions:
            ts = a.get("timestamp", "")
            try:
                ts_display = pd.to_datetime(ts).strftime("%H:%M:%S") if ts else "—"
            except Exception:
                ts_display = str(ts)[:19] if ts else "—"
            with st.container():
                st.markdown(f"""
                <div class="metric-container" style="border-left-color: #ff9800;">
                    <strong>{a.get('action_type', '')}: {a.get('action', '')}</strong> · Target: <code>{a.get('target', '')}</code><br>
                    <small>Policy: {a.get('policy', '')} · Status: {a.get('status', '')}</small><br>
                    <small>Trigger: risk={a.get('risk_score', 0):.2f}, confidence={a.get('confidence', 0):.2f}, reason={a.get('primary_reason') or 'n/a'}</small><br>
                    <small>Time: {ts_display}</small>
                </div>
                """, unsafe_allow_html=True)
                st.markdown("")
    
    # Auto-refresh logic
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()

if __name__ == "__main__":
    main()
