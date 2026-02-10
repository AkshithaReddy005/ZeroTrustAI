#!/usr/bin/env python3
"""
ZeroTrust-AI XAI Dashboard with SHAP Explanations
Enhanced Streamlit dashboard with explainable AI features
"""

import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import sys
import os

# Resolve project root based on this file location and add correct module paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
DETECTOR_APP_PATH = os.path.join(PROJECT_ROOT, "services", "detector", "app")
SHARED_PATH = os.path.join(PROJECT_ROOT, "shared")
# Ensure project root is on sys.path so 'shared.schemas' imports work inside xai_explainer
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
for p in (DETECTOR_APP_PATH, SHARED_PATH):
    if p not in sys.path:
        sys.path.append(p)

try:
    from xai_explainer import explain_detection, get_feature_importance_summary
    from schemas import FlowFeatures
except ImportError as e:
    st.error("❌ XAI module not available. Please ensure all dependencies are installed.")
    st.caption(f"Details: {e}")
    st.caption(f"sys.path (first entries): {sys.path[:6]}")
    st.stop()

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
    border: 1px solid #1f77b0;
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

</style>
""", unsafe_allow_html=True)

def get_recent_detections(limit=50):
    """Get recent detections from detector"""
    try:
        response = requests.get(f"{DETECTOR_URL}/recent_detections?limit={limit}", timeout=5)
        if response.status_code == 200:
            return response.json()
        return []
    except Exception:
        return []

def get_blocked_ips():
    """Get blocked IPs from SOAR"""
    try:
        response = requests.get(f"{SOAR_URL}/soar/blocked", timeout=5)
        if response.status_code == 200:
            return response.json()
        return []
    except Exception:
        return []

def create_shap_force_plot(explanation_data, flow_id):
    """Create SHAP force plot using Plotly"""
    if "error" in explanation_data:
        return None
    
    try:
        # Simulate SHAP values for demonstration
        # In real implementation, this would come from actual SHAP explainer
        base_value = 0.5
        shap_values = [
            0.2,  # Packet timing
            0.15, # Packet size variation
            0.1,  # High entropy
            0.05, # SYN count
            0.03, # Duration
            0.02, # PPS
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
            name='SHAP Values'
        ))
        
        # Add base value line
        fig.add_vline(x=base_value, line_dash="dash", line_color="black", 
                      annotation_text="Base Value", annotation_position="top")
        
        fig.update_layout(
            title=f"SHAP Force Plot - Flow {flow_id}",
            xaxis_title="SHAP Value (Impact on Prediction)",
            yaxis_title="Features",
            height=400,
            showlegend=False,
            template="plotly_white"
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating SHAP plot: {e}")
        return None

def create_waterfall_plot(explanation_data, flow_id):
    """Create SHAP waterfall plot"""
    if "error" in explanation_data:
        return None
    
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
        
        labels, values, positions = zip(*[(c[0], c[1], i) for i, c in enumerate(contributions)])
        
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
            title=f"SHAP Waterfall Plot - Flow {flow_id}",
            xaxis_title="Prediction Value",
            yaxis_title="Features",
            height=500,
            showlegend=False,
            template="plotly_white"
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating waterfall plot: {e}")
        return None

def main():
    """Main XAI Dashboard"""
    st.title("🧠 ZeroTrust-AI XAI Dashboard")
    st.markdown("### Explainable AI for Network Threat Detection")
    
    # Sidebar for navigation
    st.sidebar.title("🎛️ Navigation")
    page = st.sidebar.selectbox(
        "Select Page",
        ["🔍 Detection Explorer", "🧠 AI Explanations", "📊 Feature Analysis", "🔒 SOAR Management"]
    )
    
    if page == "🔍 Detection Explorer":
        st.header("🔍 Recent Detections with XAI Insights")
        
        # Get recent detections
        with st.spinner("Loading recent detections..."):
            detections = get_recent_detections()
        
        if not detections:
            st.warning("No recent detections found")
            return
        
        # Create dataframe
        df = pd.DataFrame(detections)
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            min_confidence = st.slider("Min Confidence", 0.0, 1.0, 0.0)
        with col2:
            threat_type = st.selectbox("Threat Type", ["All"] + list(df['attack_type'].unique()))
        with col3:
            time_range = st.selectbox("Time Range", ["Last Hour", "Last 6 Hours", "Last 24 Hours"])
        
        # Filter detections
        filtered_df = df[
            (df['confidence'] >= min_confidence) &
            (threat_type == "All" | (df['attack_type'] == threat_type))
        ]
        
        # Display detections with expandable XAI
        for _, detection in filtered_df.iterrows():
            with st.expander(f"🎯 Flow {detection['flow_id']} - {detection['label'].upper()}", expanded=False):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📊 Detection Details")
                    st.write(f"**Confidence:** {detection['confidence']:.3f}")
                    st.write(f"**Severity:** {detection['severity']}")
                    st.write(f"**Attack Type:** {detection['attack_type']}")
                    st.write(f"**MITRE Technique:** {detection.get('mitre_technique', 'Unknown')}")
                    st.write(f"**Time:** {detection.get('timestamp', 'Unknown')}")
                
                with col2:
                    st.subheader("🧠 AI Explanation")
                    
                    # Generate XAI explanation
                    if detection['label'] == 'malicious':
                        # Create mock flow for explanation
                        flow_data = {
                            'flow_id': detection['flow_id'],
                            'total_packets': 100,
                            'total_bytes': 85000,
                            'avg_packet_size': 68.2,
                            'std_packet_size': 15.3,
                            'duration': 15.3,
                            'pps': 81.5,
                            'avg_entropy': 6.8,
                            'syn_count': 10,
                            'fin_count': 0
                        }
                        
                        flow = FlowFeatures(**flow_data)
                        explanation = explain_detection(flow, detection['confidence'], detection.get('reasons', []))
                        
                        if "error" not in explanation:
                            # Display explanation summary
                            st.write("**Model Contributions:**")
                            if 'ensemble' in explanation:
                                ensemble = explanation['ensemble']
                                st.write(f"- **TCN:** {ensemble.get('model_contributions', {}).get('tcn', 0):.3f}")
                                st.write(f"- **Autoencoder:** {ensemble.get('model_contributions', {}).get('autoencoder', 0):.3f}")
                                st.write(f"- **IsolationForest:** {ensemble.get('model_contributions', {}).get('isolation_forest', 0):.3f}")
                            
                            # Display SHAP plots
                            st.subheader("📈 SHAP Visualizations")
                            
                            plot_type = st.selectbox("Plot Type", ["Force Plot", "Waterfall Plot"])
                            
                            if plot_type == "Force Plot":
                                fig = create_shap_force_plot(explanation, detection['flow_id'])
                                if fig:
                                    st.plotly_chart(fig, use_container_width=True)
                                    st.caption("Red bars push prediction toward 'BLOCK', blue bars push toward 'ALLOW'")
                            
                            elif plot_type == "Waterfall Plot":
                                fig = create_waterfall_plot(explanation, detection['flow_id'])
                                if fig:
                                    st.plotly_chart(fig, use_container_width=True)
                                    st.caption("Shows how each feature contributes to final prediction")
                    else:
                        st.info("Benign traffic - no explanation needed")
    
    elif page == "🧠 AI Explanations":
        st.header("🧠 AI Model Explanations")
        
        # Feature importance overview
        st.subheader("📊 Global Feature Importance")
        
        importance = get_feature_importance_summary()
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="feature-card">
                <h4>🧠 TCN Model</h4>
                <p>Focuses on temporal patterns in packet sequences</p>
                <ul>
                    <li>Packet length sequences</li>
                    <li>Inter-arrival timing</li>
                    <li>Temporal convolutions</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="feature-card">
                <h4>🔍 Autoencoder</h4>
                <p>Detects anomalies through reconstruction error</p>
                <ul>
                    <li>Unusual packet sizes</li>
                    <li>Timing irregularities</li>
                    <li>Sequence anomalies</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="feature-card">
                <h4>🌲 IsolationForest</h4>
                <p>Identifies statistical outliers</p>
                <ul>
                    <li>Feature distribution anomalies</li>
                    <li>Isolation scores</li>
                    <li>Unusual patterns</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        # Model weights and contributions
        st.subheader("⚖️ Ensemble Weights")
        
        weights_data = {
            "Model": ["TCN", "Autoencoder", "IsolationForest"],
            "Weight": [0.50, 0.25, 0.25],
            "Contribution": ["Primary", "Secondary", "Secondary"]
        }
        
        weights_df = pd.DataFrame(weights_data)
        fig = px.bar(weights_df, x="Model", y="Weight", color="Model", 
                     title="Ensemble Model Weights",
                     labels={"Weight": "Weight in Final Decision"})
        st.plotly_chart(fig, use_container_width=True)
        
        st.caption("TCN has highest weight due to superior accuracy on known attack patterns")
    
    elif page == "📊 Feature Analysis":
        st.header("📊 Feature Analysis & Importance")
        
        # Feature mapping explanation
        st.subheader("🔍 Feature Mapping")
        
        feature_mapping = {
            "Technical Name": [
                "Packet_1_Length", "Packet_2_Length", "Packet_1_Timing",
                "Total_Packets", "Avg_Entropy", "SYN_Count"
            ],
            "Human-Readable Name": [
                "First Packet Size", "Second Packet Size", "First Inter-arrival Time",
                "Total Packet Count", "Traffic Entropy", "SYN Flag Count"
            ],
            "What it Detects": [
                "Unusually large/small packets", "Packet size patterns", "Timing between packets",
                "Overall traffic volume", "Encryption/complexity", "Connection attempts"
            ]
        }
        
        mapping_df = pd.DataFrame(feature_mapping)
        st.dataframe(mapping_df, use_container_width=True)
        
        st.info("""
        **🧠 Why This Matters:** XAI transforms your "black box" into a "glass box" 
        where security analysts can understand WHY the AI made a decision, building 
        trust and enabling faster incident response.
        """)
    
    elif page == "🔒 SOAR Management":
        st.header("🔒 SOAR - Manual Override Management")
        
        # Get blocked IPs
        with st.spinner("Loading blocked IPs..."):
            blocked_ips = get_blocked_ips()
        
        if not blocked_ips:
            st.warning("No blocked IPs found")
        else:
            st.subheader(f"🚫 Currently Blocked IPs ({len(blocked_ips)})")
            
            for ip_info in blocked_ips:
                with st.expander(f"🚫 {ip_info['ip_address']}", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Reason:** {ip_info.get('reason', 'Unknown')}")
                        st.write(f"**Blocked At:** {ip_info.get('blocked_at', 'Unknown')}")
                        st.write(f"**Blocked Until:** {ip_info.get('blocked_until', 'Unknown')}")
                        st.write(f"**Blocked By:** {ip_info.get('blocked_by', 'Unknown')}")
                    
                    with col2:
                        # Unblock button
                        if st.button(f"🔓 Unblock {ip_info['ip_address']}", key=f"unblock_{ip_info['ip_address']}"):
                            try:
                                response = requests.post(f"{SOAR_URL}/soar/unblock", 
                                                       json={"ip_address": ip_info['ip_address'], 
                                                             "unblocked_by": "XAI_Dashboard"},
                                                       timeout=5)
                                if response.status_code == 200:
                                    st.success(f"✅ Successfully unblocked {ip_info['ip_address']}")
                                    st.rerun()
                                else:
                                    st.error(f"❌ Failed to unblock {ip_info['ip_address']}")
                            except Exception as e:
                                st.error(f"❌ Error: {e}")
        
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
                try:
                    response = requests.post(f"{SOAR_URL}/soar/block",
                                           json={"ip_address": ip_to_block,
                                                 "reason": block_reason,
                                                 "duration_hours": block_duration,
                                                 "blocked_by": "XAI_Dashboard"},
                                           timeout=5)
                    if response.status_code == 200:
                        st.success(f"✅ Successfully blocked {ip_to_block}")
                        st.rerun()
                    else:
                        st.error(f"❌ Failed to block {ip_to_block}")
                except Exception as e:
                    st.error(f"❌ Error: {e}")
            else:
                st.error("Please provide IP address and reason")

if __name__ == "__main__":
    main()
