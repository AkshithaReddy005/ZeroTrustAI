#!/usr/bin/env python3
"""
ZeroTrust-AI XAI Dashboard - Standalone Version
Enhanced Streamlit dashboard with explainable AI features
"""

import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import numpy as np
import shap
import sys
import os

# Configuration
DETECTOR_URL = "http://localhost:9000"
SOAR_URL = "http://localhost:9000"

st.set_page_config(
    page_title="ZeroTrust-AI XAI Dashboard",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.metric-container {
    background-color: #f0f2f6;
    border: 1px solid #1f77b4;
    padding: 1rem;
    border-radius: 0.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.feature-card {
    background-color: white;
    border: 1px solid #e1e5e9;
    border-radius: 0.5rem;
    padding: 1rem;
    margin-bottom: 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.shap-plot-container {
    background-color: #fafafa;
    border: 1px solid #e1e5e9;
    border-radius: 0.5rem;
    padding: 1rem;
    margin: 1rem 0;
}

.main-header {
    background: linear-gradient(90deg, #1f77b4 0%, #17becf 100%);
    color: white;
    padding: 2rem;
    border-radius: 0.5rem;
    margin-bottom: 2rem;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

def get_mock_detections():
    """Get mock detections for demonstration"""
    return [
        {
            "flow_id": "flow_001",
            "label": "malicious",
            "confidence": 0.965,
            "severity": "HIGH",
            "attack_type": "botnet",
            "mitre_technique": "T1071",
            "timestamp": "2024-02-07T21:30:00Z",
            "reasons": ["tcn_malicious", "ae_anomalous"]
        },
        {
            "flow_id": "flow_002", 
            "label": "malicious",
            "confidence": 0.847,
            "severity": "MEDIUM",
            "attack_type": "reconnaissance",
            "mitre_technique": "T1046",
            "timestamp": "2024-02-07T21:25:00Z",
            "reasons": ["port_scan", "iso_anomalous"]
        },
        {
            "flow_id": "flow_003",
            "label": "benign",
            "confidence": 0.123,
            "severity": "LOW",
            "attack_type": "normal",
            "mitre_technique": "N/A",
            "timestamp": "2024-02-07T21:20:00Z",
            "reasons": ["low_risk"]
        }
    ]

def get_mock_blocked_ips():
    """Get mock blocked IPs for demonstration"""
    return [
        {
            "ip_address": "192.168.1.100",
            "reason": "Botnet C2 communication detected",
            "blocked_at": "2024-02-07T20:00:00Z",
            "blocked_until": "2024-02-08T20:00:00Z",
            "blocked_by": "XAI_Dashboard",
            "status": "active"
        },
        {
            "ip_address": "10.0.0.50",
            "reason": "Port scanning activity",
            "blocked_at": "2024-02-07T19:30:00Z", 
            "blocked_until": "2024-02-08T19:30:00Z",
            "blocked_by": "XAI_Dashboard",
            "status": "active"
        }
    ]

def create_shap_force_plot(flow_id, confidence):
    """Create SHAP force plot using Plotly"""
    try:
        # Simulate SHAP values for demonstration
        base_value = 0.5
        shap_values = [
            0.25,  # Packet timing variance
            0.18,  # Packet size anomaly
            0.12,  # High entropy
            0.08,  # SYN flag anomaly
            0.05,  # Long duration
            0.03,  # High packet rate
        ]
        
        feature_names = [
            "Packet Timing Variance",
            "Packet Size Anomaly", 
            "High Traffic Entropy",
            "SYN Flag Anomaly",
            "Long Duration",
            "High Packet Rate"
        ]
        
        # Create force plot
        fig = go.Figure()
        
        # Add bars for each feature
        colors = ['#ff4444' if val > 0 else '#44aa44' for val in shap_values]
        
        fig.add_trace(go.Bar(
            x=shap_values,
            y=feature_names,
            orientation='h',
            marker_color=colors,
            name='SHAP Values',
            text=[f"{val:.3f}" for val in shap_values],
            textposition='auto'
        ))
        
        # Add base value line
        fig.add_vline(x=base_value, line_dash="dash", line_color="black", 
                      annotation_text="Base Value", annotation_position="top")
        
        # Add prediction line
        fig.add_vline(x=confidence, line_color="red", line_width=3,
                      annotation_text=f"Prediction: {confidence:.3f}", annotation_position="top")
        
        fig.update_layout(
            title=f"🧠 SHAP Force Plot - Flow {flow_id}",
            xaxis_title="SHAP Value (Impact on Prediction)",
            yaxis_title="Features",
            height=500,
            showlegend=False,
            template="plotly_white",
            font=dict(size=12)
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating SHAP plot: {e}")
        return None

def create_waterfall_plot(flow_id, confidence):
    """Create SHAP waterfall plot"""
    try:
        # Simulate waterfall data
        base_value = 0.5
        contributions = [
            ("Base Value", base_value, 0),
            ("Packet Timing", 0.12, 0.62),
            ("Packet Size", 0.08, 0.70),
            ("Traffic Entropy", 0.15, 0.85),
            ("Protocol Anomaly", 0.05, 0.90),
            ("Final Prediction", 0.10, 1.0)
        ]
        
        labels, values, positions = [], [], []
        for i, (label, value, position) in enumerate(contributions):
            labels.append(label)
            values.append(value)
            positions.append(position)
        
        # Create waterfall plot
        fig = go.Figure()
        
        colors = ['#1f77b4' if i < len(contributions)-1 else '#ff4444' for i in range(len(contributions))]
        
        fig.add_trace(go.Bar(
            x=positions,
            y=labels,
            marker_color=colors,
            text=[f"{val:.3f}" for val in values],
            textposition='auto',
            name='Contribution'
        ))
        
        fig.update_layout(
            title=f"💧 SHAP Waterfall Plot - Flow {flow_id}",
            xaxis_title="Prediction Value",
            yaxis_title="Features",
            height=600,
            showlegend=False,
            template="plotly_white",
            font=dict(size=12)
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating waterfall plot: {e}")
        return None

def create_feature_importance_plot():
    """Create global feature importance plot"""
    try:
        features = [
            "Packet Timing Variance",
            "Packet Size Anomaly",
            "Traffic Entropy",
            "SYN Flag Count",
            "Flow Duration",
            "Packet Rate (PPS)",
            "Protocol Anomalies",
            "Connection Patterns"
        ]
        
        importance = [0.23, 0.19, 0.15, 0.12, 0.10, 0.08, 0.07, 0.06]
        
        fig = px.bar(
            x=importance,
            y=features,
            orientation='h',
            title="📊 Global Feature Importance Across All Detections",
            labels={"x": "Importance Score", "y": "Features"},
            color=importance,
            color_continuous_scale="viridis"
        )
        
        fig.update_layout(
            height=500,
            template="plotly_white",
            font=dict(size=12)
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating feature importance plot: {e}")
        return None

def create_confidence_gauge(confidence):
    """Create confidence gauge chart"""
    try:
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = confidence * 100,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "AI Confidence", 'font': {'size': 24}},
            delta = {'reference': 50},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 25], 'color': "lightgray"},
                    {'range': [25, 50], 'color': "gray"},
                    {'range': [50, 75], 'color': "lightblue"},
                    {'range': [75, 100], 'color': "blue"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        
        fig.update_layout(height=300, font=dict(color="darkblue", family="Arial"))
        return fig
    except Exception as e:
        st.error(f"Error creating confidence gauge: {e}")
        return None

def main():
    """Main XAI Dashboard"""
    st.markdown("""
    <div class="main-header">
        <h1>🧠 ZeroTrust-AI XAI Dashboard</h1>
        <h2>Explainable AI for Network Threat Detection</h2>
        <p>Transform your "black box" into a "glass box" with SHAP explanations</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar for navigation
    st.sidebar.title("🎛️ Navigation")
    page = st.sidebar.selectbox(
        "Select Page",
        ["🔍 Detection Explorer", "🧠 AI Explanations", "📊 Feature Analysis", "🔒 SOAR Management"]
    )
    
    if page == "🔍 Detection Explorer":
        st.header("🔍 Recent Detections with XAI Insights")
        
        # Get detections (mock for demo)
        with st.spinner("Loading recent detections..."):
            detections = get_mock_detections()
        
        if not detections:
            st.warning("No recent detections found")
            return
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            min_confidence = st.slider("Min Confidence", 0.0, 1.0, 0.0)
        with col2:
            threat_type = st.selectbox("Threat Type", ["All"] + list(set([d['attack_type'] for d in detections])))
        with col3:
            time_range = st.selectbox("Time Range", ["Last Hour", "Last 6 Hours", "Last 24 Hours"])
        
        # Filter detections
        filtered_detections = [
            d for d in detections 
            if d['confidence'] >= min_confidence and 
            (threat_type == "All" or d['attack_type'] == threat_type)
        ]
        
        # Display detections with expandable XAI
        for detection in filtered_detections:
            with st.expander(f"🎯 Flow {detection['flow_id']} - {detection['label'].upper()}", expanded=False):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📊 Detection Details")
                    st.write(f"**Confidence:** {detection['confidence']:.3f}")
                    st.write(f"**Severity:** {detection['severity']}")
                    st.write(f"**Attack Type:** {detection['attack_type']}")
                    st.write(f"**MITRE Technique:** {detection['mitre_technique']}")
                    st.write(f"**Time:** {detection['timestamp']}")
                    
                    # Confidence gauge
                    gauge_fig = create_confidence_gauge(detection['confidence'])
                    if gauge_fig:
                        st.plotly_chart(gauge_fig, use_container_width=True)
                
                with col2:
                    st.subheader("🧠 AI Explanation")
                    
                    if detection['label'] == 'malicious':
                        # Display explanation summary
                        st.write("**Model Contributions:**")
                        if 'tcn_malicious' in detection['reasons']:
                            st.write("- 🧠 **TCN:** 0.500 (Botnet pattern detected)")
                        if 'ae_anomalous' in detection['reasons']:
                            st.write("- 🔍 **Autoencoder:** 0.250 (Anomalous reconstruction)")
                        if 'iso_anomalous' in detection['reasons']:
                            st.write("- 🌲 **IsolationForest:** 0.250 (Statistical outlier)")
                        
                        # SHAP visualizations
                        st.subheader("📈 SHAP Visualizations")
                        
                        plot_type = st.selectbox("Plot Type", ["Force Plot", "Waterfall Plot"], 
                                               key=f"plot_{detection['flow_id']}")
                        
                        if plot_type == "Force Plot":
                            fig = create_shap_force_plot(detection['flow_id'], detection['confidence'])
                            if fig:
                                st.plotly_chart(fig, use_container_width=True)
                                st.caption("🔴 Red bars push prediction toward 'BLOCK' | 🔵 Blue bars push toward 'ALLOW'")
                        
                        elif plot_type == "Waterfall Plot":
                            fig = create_waterfall_plot(detection['flow_id'], detection['confidence'])
                            if fig:
                                st.plotly_chart(fig, use_container_width=True)
                                st.caption("💧 Shows step-by-step how each feature contributes to final prediction")
                    else:
                        st.info("✅ Benign traffic - no explanation needed")
    
    elif page == "🧠 AI Explanations":
        st.header("🧠 AI Model Explanations")
        
        # Feature importance overview
        st.subheader("📊 Global Feature Importance")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="feature-card">
                <h4>🧠 TCN Model</h4>
                <p><strong>Focuses on temporal patterns</strong></p>
                <ul>
                    <li>📦 Packet length sequences</li>
                    <li>⏱️ Inter-arrival timing</li>
                    <li>🔄 Temporal convolutions</li>
                </ul>
                <p><strong>Weight: 50%</strong></p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="feature-card">
                <h4>🔍 Autoencoder</h4>
                <p><strong>Detects anomalies through reconstruction</strong></p>
                <ul>
                    <li>📏 Unusual packet sizes</li>
                    <li>⚡ Timing irregularities</li>
                    <li>🚨 Sequence anomalies</li>
                </ul>
                <p><strong>Weight: 25%</strong></p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="feature-card">
                <h4>🌲 IsolationForest</h4>
                <p><strong>Identifies statistical outliers</strong></p>
                <ul>
                    <li>📊 Feature distribution anomalies</li>
                    <li>🎯 Isolation scores</li>
                    <li>📈 Unusual patterns</li>
                </ul>
                <p><strong>Weight: 25%</strong></p>
            </div>
            """, unsafe_allow_html=True)
        
        # Feature importance plot
        st.subheader("📈 Feature Importance Analysis")
        fig = create_feature_importance_plot()
        if fig:
            st.plotly_chart(fig, use_container_width=True)
        
        st.info("""
        🧠 **Why XAI Matters:** 
        - **Transparency:** Security analysts understand WHY AI made decisions
        - **Trust Building:** Clear explanations build confidence in AI systems  
        - **Compliance:** Audit trail with explainable decisions
        - **Debugging:** Identify root causes of false positives/negatives
        """)
    
    elif page == "📊 Feature Analysis":
        st.header("📊 Feature Analysis & Importance")
        
        # Feature mapping explanation
        st.subheader("🔍 Technical → Human-Readable Feature Mapping")
        
        feature_mapping = {
            "Technical Name": [
                "Packet_1_Length", "Packet_2_Length", "Packet_1_Timing",
                "Total_Packets", "Avg_Entropy", "SYN_Count"
            ],
            "Human-Readable Name": [
                "First Packet Size", "Second Packet Size", "First Inter-arrival Time",
                "Total Packet Count", "Traffic Entropy", "SYN Flag Count"
            ],
            "Security Meaning": [
                "Unusually large/small packets", "Packet size patterns", "Timing between packets",
                "Overall traffic volume", "Encryption/complexity", "Connection attempts"
            ]
        }
        
        mapping_df = pd.DataFrame(feature_mapping)
        st.dataframe(mapping_df, use_container_width=True)
        
        st.subheader("🎯 How Features Drive Decisions")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="feature-card">
                <h4>🔴 High-Risk Indicators</h4>
                <ul>
                    <li><strong>High Entropy (>7.0)</strong> → Encrypted malware</li>
                    <li><strong>Large Packet Count</strong> → DDoS/Scanning</li>
                    <li><strong>Timing Anomalies</strong> → Botnet beacons</li>
                    <li><strong>SYN Flood</strong> → Port scanning</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="feature-card">
                <h4>🔵 Low-Risk Indicators</h4>
                <ul>
                    <li><strong>Standard Port 443/80</strong> → Normal web traffic</li>
                    <li><strong>Regular Packet Sizes</strong> → Standard protocols</li>
                    <li><strong>Stable Timing</strong> → Legitimate connections</li>
                    <li><strong>Low Entropy (<3.0)</strong> → Unencrypted data</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
    
    elif page == "🔒 SOAR Management":
        st.header("🔒 SOAR - Manual Override Management")
        
        # Get blocked IPs (mock for demo)
        with st.spinner("Loading blocked IPs..."):
            blocked_ips = get_mock_blocked_ips()
        
        if not blocked_ips:
            st.warning("No blocked IPs found")
        else:
            st.subheader(f"🚫 Currently Blocked IPs ({len(blocked_ips)})")
            
            for ip_info in blocked_ips:
                with st.expander(f"🚫 {ip_info['ip_address']}", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Reason:** {ip_info['reason']}")
                        st.write(f"**Blocked At:** {ip_info['blocked_at']}")
                        st.write(f"**Blocked Until:** {ip_info['blocked_until']}")
                        st.write(f"**Blocked By:** {ip_info['blocked_by']}")
                    
                    with col2:
                        # Unblock button
                        if st.button(f"🔓 Unblock {ip_info['ip_address']}", key=f"unblock_{ip_info['ip_address']}"):
                            st.success(f"✅ Successfully unblocked {ip_info['ip_address']}")
                            st.rerun()
        
        # Manual block section
        st.subheader("🚫 Manual IP Blocking")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            ip_to_block = st.text_input("IP Address to Block", placeholder="192.168.1.100")
        
        with col2:
            block_reason = st.text_input("Block Reason", placeholder="Manual security action")
        
        with col3:
            block_duration = st.selectbox("Duration (hours)", [1, 6, 12, 24, 48], index=2)
        
        if st.button("🚫 Block IP", type="primary"):
            if ip_to_block and block_reason:
                st.success(f"✅ Successfully blocked {ip_to_block}")
                st.rerun()
            else:
                st.error("Please provide IP address and reason")

if __name__ == "__main__":
    main()
