import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import redis
from influxdb_client import InfluxDBClient
import numpy as np
from datetime import datetime, timedelta
import os

# Professional Dashboard Configuration
st.set_page_config(
    page_title="ZeroTrust-AI Professional Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional look
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    .threat-level-high {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
    }
    .threat-level-critical {
        background: linear-gradient(135deg, #c92a2a 0%, #a61e1e 100%);
    }
</style>
""", unsafe_allow_html=True)

# Initialize connections
@st.cache_resource
def init_connections():
    """Initialize Redis and InfluxDB connections"""
    redis_client = None
    influx_client = None
    
    try:
        redis_client = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            db=0,
            decode_responses=True
        )
        redis_client.ping()
    except Exception as e:
        st.sidebar.warning(f"⚠️ Redis connection failed: {e}")
    
    try:
        influx_client = InfluxDBClient(
            url=os.getenv("INFLUX_URL", "http://localhost:8086"),
            token=os.getenv("INFLUX_TOKEN", ""),
            org=os.getenv("INFLUX_ORG", "zerotrust")
        )
    except Exception as e:
        st.sidebar.warning(f"⚠️ InfluxDB connection failed: {e}")
    
    return redis_client, influx_client

redis_client, influx_client = init_connections()

# Professional Header
st.markdown('<h1 class="main-header">🛡️ ZeroTrust-AI Professional Dashboard</h1>', unsafe_allow_html=True)

# Sidebar Configuration
st.sidebar.header("🎛️ Configuration")
time_range = st.sidebar.selectbox(
    "Time Range",
    ["Last Hour", "Last 6 Hours", "Last 24 Hours", "Last 7 Days"],
    index=2
)

# Convert time range to InfluxDB query
time_mapping = {
    "Last Hour": "1h",
    "Last 6 Hours": "6h", 
    "Last 24 Hours": "24h",
    "Last 7 Days": "7d"
}
range_filter = time_mapping[time_range]

# Main Dashboard Layout
col1, col2, col3, col4 = st.columns(4)

# Professional Metrics Cards
def get_real_time_metrics():
    """Get real-time metrics from Redis and InfluxDB"""
    metrics = {
        "active_threats": 0,
        "high_risk_ips": 0,
        "blocked_ips": 0,
        "avg_entropy": 0.0
    }
    
    if redis_client:
        try:
            # Count high-risk IPs (risk_score >= 80)
            keys = redis_client.keys("risk_score:*")
            for key in keys:
                risk = int(redis_client.get(key) or 0)
                if risk >= 80:
                    metrics["blocked_ips"] += 1
                elif risk >= 50:
                    metrics["high_risk_ips"] += 1
                if risk > 0:
                    metrics["active_threats"] += 1
        except Exception:
            pass
    
    if influx_client:
        try:
            query_api = influx_client.query_api()
            # Get average entropy
            query = f'''
            from(bucket: "threat_events")
            |> range(start: -{range_filter})
            |> filter(fn: (r) => r._measurement == "network_telemetry")
            |> filter(fn: (r) => r._field == "entropy")
            |> mean(column: "_value")
            '''
            result = query_api.query(query)
            for table in result:
                for record in table.records:
                    metrics["avg_entropy"] = record.get_value()
        except Exception:
            pass
    
    return metrics

metrics = get_real_time_metrics()

# Display Professional Metrics
with col1:
    st.markdown(f"""
    <div class="metric-card">
        <h3>🚨 Active Threats</h3>
        <h2>{metrics['active_threats']}</h2>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card threat-level-high">
        <h3>⚠️ High-Risk IPs</h3>
        <h2>{metrics['high_risk_ips']}</h2>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="metric-card threat-level-critical">
        <h3>🚫 Auto-Blocked IPs</h3>
        <h2>{metrics['blocked_ips']}</h2>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="metric-card">
        <h3>📊 Avg Entropy</h3>
        <h2>{metrics['avg_entropy']:.2f}</h2>
    </div>
    """, unsafe_allow_html=True)

# Professional Threat Heatmap
st.header("🔥 Threat Heatmap - Behavioral Drift Analysis")

def create_threat_heatmap():
    """Create professional threat heatmap from InfluxDB data"""
    if not influx_client:
        return None
    
    try:
        query_api = influx_client.query_api()
        query = f'''
        from(bucket: "threat_events")
        |> range(start: -{range_filter})
        |> filter(fn: (r) => r._measurement == "threat_heatmap")
        |> filter(fn: (r) => r._field == "risk_intensity")
        |> group(columns: ["source_ip", "attack_type"])
        |> max(column: "_value")
        |> sort(columns: ["_value"], desc: true)
        |> limit(n: 50)
        '''
        
        result = query_api.query(query)
        data = []
        for table in result:
            for record in table.records:
                data.append({
                    'source_ip': record.values.get('source_ip', 'unknown'),
                    'attack_type': record.values.get('attack_type', 'unknown'),
                    'risk_intensity': record.get_value(),
                    'confidence': record.values.get('confidence', 0),
                    'time': record.get_time()
                })
        
        if not data:
            return None
        
        df = pd.DataFrame(data)
        
        # Create heatmap
        pivot_df = df.pivot_table(
            values='risk_intensity', 
            index='source_ip', 
            columns='attack_type', 
            fill_value=0
        )
        
        fig = px.imshow(
            pivot_df,
            title="🔥 Threat Intensity Heatmap by IP and Attack Type",
            labels=dict(x="Attack Type", y="Source IP", color="Risk Intensity"),
            color_continuous_scale="Reds",
            aspect="auto"
        )
        
        fig.update_layout(
            height=600,
            xaxis_title="Attack Type",
            yaxis_title="Source IP Address"
        )
        
        return fig, df
        
    except Exception as e:
        st.error(f"❌ Error creating heatmap: {e}")
        return None, None

heatmap_result = create_threat_heatmap()

if heatmap_result[0] is not None:
    fig, heatmap_data = heatmap_result
    st.plotly_chart(fig, use_container_width=True)
    
    # Show top threats table
    st.subheader("🏆 Top Threat Sources")
    top_threats = heatmap_data.nlargest(10, 'risk_intensity')
    st.dataframe(
        top_threats[['source_ip', 'attack_type', 'risk_intensity', 'confidence']],
        use_container_width=True
    )

# Behavioral Drift Analysis
st.header("📈 Behavioral Drift Analysis")

def create_behavioral_drift_chart():
    """Create behavioral drift analysis chart"""
    if not influx_client:
        return None
    
    try:
        query_api = influx_client.query_api()
        query = f'''
        from(bucket: "threat_events")
        |> range(start: -{range_filter})
        |> filter(fn: (r) => r._measurement == "network_telemetry")
        |> filter(fn: (r) => r._field == "entropy" or r._field == "risk_score")
        |> aggregateWindow(every: 5m, fn: mean, createEmpty: false)
        |> yield(name: "mean")
        '''
        
        result = query_api.query(query)
        data = []
        for table in result:
            for record in table.records:
                data.append({
                    'time': record.get_time(),
                    'field': record.get_field(),
                    'value': record.get_value()
                })
        
        if not data:
            return None
        
        df = pd.DataFrame(data)
        
        # Create time series chart
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Network Entropy Over Time', 'Risk Score Trends'),
            vertical_spacing=0.1
        )
        
        # Entropy chart
        entropy_data = df[df['field'] == 'entropy']
        if not entropy_data.empty:
            fig.add_trace(
                go.Scatter(
                    x=entropy_data['time'],
                    y=entropy_data['value'],
                    mode='lines',
                    name='Network Entropy',
                    line=dict(color='blue', width=2)
                ),
                row=1, col=1
            )
        
        # Risk score chart
        risk_data = df[df['field'] == 'risk_score']
        if not risk_data.empty:
            fig.add_trace(
                go.Scatter(
                    x=risk_data['time'],
                    y=risk_data['value'],
                    mode='lines',
                    name='Risk Score',
                    line=dict(color='red', width=2)
                ),
                row=2, col=1
            )
        
        fig.update_layout(
            height=600,
            title_text="📊 Behavioral Drift Analysis - Large Scale Detection",
            showlegend=True
        )
        
        return fig
        
    except Exception as e:
        st.error(f"❌ Error creating drift analysis: {e}")
        return None

drift_chart = create_behavioral_drift_chart()
if drift_chart is not None:
    st.plotly_chart(drift_chart, use_container_width=True)

# Risk Score Distribution
st.header("⚖️ Risk Score Distribution")

def get_risk_distribution():
    """Get risk score distribution from Redis"""
    if not redis_client:
        return None
    
    try:
        keys = redis_client.keys("risk_score:*")
        risk_scores = []
        
        for key in keys:
            risk = int(redis_client.get(key) or 0)
            risk_scores.append(risk)
        
        if not risk_scores:
            return None
        
        # Create distribution
        bins = [0, 20, 40, 60, 80, 100]
        labels = ['Very Low', 'Low', 'Medium', 'High', 'Critical']
        
        distribution = pd.cut(risk_scores, bins=bins, labels=labels, include_lowest=True)
        dist_df = distribution.value_counts().reset_index()
        dist_df.columns = ['Risk Level', 'Count']
        
        return dist_df, risk_scores
        
    except Exception as e:
        st.error(f"❌ Error getting risk distribution: {e}")
        return None, None

risk_dist_result = get_risk_distribution()
if risk_dist_result[0] is not None:
    dist_df, risk_scores = risk_dist_result
    
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.bar(
            dist_df,
            x='Risk Level',
            y='Count',
            title="📊 Risk Score Distribution",
            color='Risk Level',
            color_discrete_map={
                'Very Low': 'green',
                'Low': 'lightblue',
                'Medium': 'yellow',
                'High': 'orange',
                'Critical': 'red'
            }
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Risk statistics
        st.subheader("📈 Risk Statistics")
        st.metric("Mean Risk Score", f"{np.mean(risk_scores):.1f}")
        st.metric("Median Risk Score", f"{np.median(risk_scores):.1f}")
        st.metric("Max Risk Score", f"{np.max(risk_scores):.1f}")
        st.metric("Total Tracked IPs", len(risk_scores))

# Professional Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; margin-top: 2rem;'>
    <p>🛡️ ZeroTrust-AI Professional Dashboard | Real-time Threat Intelligence & Behavioral Analysis</p>
    <p>⚡ Powered by Adaptive Risk Scoring (Redis) & Behavioral Drift Analysis (InfluxDB)</p>
</div>
""", unsafe_allow_html=True)
