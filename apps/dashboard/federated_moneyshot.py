#!/usr/bin/env python3
import streamlit as st
import pandas as pd
from pathlib import Path
import plotly.graph_objects as go
from plotly.subplots import make_subplots

PROJECT_ROOT = Path(__file__).resolve().parents[2]

st.set_page_config(page_title="Federated Money Shot", layout="wide")

st.title("🎯 Federated Learning: Cross-Domain Knowledge Transfer")

results_path = PROJECT_ROOT / "federated-learning" / "results" / "fedavg_hospital_moneyshot.csv"

st.markdown("**💡 Key Insight:** Show how models FAIL on unknown attack types, then SUCCEED after federated learning!")

if not results_path.exists():
    st.error(f"Missing results file: {results_path}")
    st.markdown("Run these first:")
    st.code(
        "python federated-learning/create_silo_data.py\n"
        "python federated-learning/fedavg_baseline.py --rounds 5 --local-epochs 1",
        language="bash",
    )
    st.stop()

df = pd.read_csv(results_path)

# Check if we have the enhanced cross-domain results
required_cols = {"round", "bank_on_hospital_f1", "hospital_on_bank_f1", "global_on_bank_f1", "global_on_hospital_f1"}
has_cross_domain = required_cols.issubset(set(df.columns))

if not has_cross_domain:
    st.error("Run the enhanced simulation first:")
    st.code("python federated-learning/fedavg_baseline.py --rounds 5 --local-epochs 1", language="bash")
    st.stop()

col1, col2 = st.columns([2, 1])

with col2:
    st.subheader("🎯 Cross-Domain Results")
    latest = df.sort_values("round").tail(1).iloc[0]
    
    st.metric("Bank → C2 Detection", f"{latest['bank_on_hospital_f1']:.3f}")
    st.metric("Hospital → DDoS Detection", f"{latest['hospital_on_bank_f1']:.3f}")
    st.metric("Global on Bank", f"{latest['global_on_bank_f1']:.3f}")
    st.metric("Global on Hospital", f"{latest['global_on_hospital_f1']:.3f}")
    
    st.subheader("📊 Improvement")
    initial = df[df['round'] == 0].iloc[0]
    improvement = latest['global_on_hospital_f1'] - initial['bank_on_hospital_f1']
    st.metric("Cross-Domain Gain", f"{improvement:+.3f}")

with col1:
    st.subheader("� The 'Money Shot' - Cross-Domain Learning")
    
    # Create subplot with secondary y-axis
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=("Bank Model Learning C2 (Hospital Data)", "Hospital Model Learning DDoS (Bank Data)"),
        vertical_spacing=0.15
    )
    
    # Top plot: Bank model on Hospital data
    fig.add_trace(
        go.Scatter(
            x=df["round"], y=df["bank_on_hospital_f1"],
            mode="lines+markers", name="Bank Isolated → C2",
            line=dict(color="red", dash="dash"),
            legendgroup="bank"
        ),
        row=1, col=1
    )
    fig.add_trace(
        go.Scatter(
            x=df["round"], y=df["global_on_hospital_f1"],
            mode="lines+markers", name="Global Model → C2",
            line=dict(color="green"),
            legendgroup="global"
        ),
        row=1, col=1
    )
    
    # Bottom plot: Hospital model on Bank data
    fig.add_trace(
        go.Scatter(
            x=df["round"], y=df["hospital_on_bank_f1"],
            mode="lines+markers", name="Hospital Isolated → DDoS",
            line=dict(color="orange", dash="dash"),
            legendgroup="hospital",
            showlegend=False
        ),
        row=2, col=1
    )
    fig.add_trace(
        go.Scatter(
            x=df["round"], y=df["global_on_bank_f1"],
            mode="lines+markers", name="Global Model → DDoS",
            line=dict(color="blue"),
            legendgroup="global",
            showlegend=False
        ),
        row=2, col=1
    )
    
    fig.update_layout(
        height=600,
        title_text="Cross-Domain Knowledge Transfer: Failure → Success",
        xaxis_title="Federated Learning Round",
        yaxis_title="F1 Score",
        yaxis=dict(range=[0, 1]),
        xaxis2_title="Federated Learning Round",
        yaxis2_title="F1 Score",
        yaxis2=dict(range=[0, 1])
    )
    
    st.plotly_chart(fig, use_container_width=True)

# Add explanation
st.markdown("---")
st.subheader("🎬 The Story This Tells")

col1, col2 = st.columns(2)

with col1:
    st.markdown("**🔴 Before Federated Learning (Round 0):**")
    st.markdown("- Bank model: ~0% on C2 (never seen it)")
    st.markdown("- Hospital model: ~0% on DDoS (never seen it)")
    st.markdown("- **Each client is blind to other attack types**")

with col2:
    st.markdown("**🟢 After Federated Learning (Round 5):**")
    st.markdown("- Global model: High F1 on ALL attack types")
    st.markdown("- **Knowledge transferred without sharing data**")
    st.markdown("- **Zero Trust privacy maintained**")

st.subheader("📊 Raw Results")
st.dataframe(df.sort_values("round"), use_container_width=True)

st.markdown("---")
st.markdown("**💡 Jury Message:** *Our federated learning system enables cross-domain threat intelligence sharing. The Bank learned to detect C2 beaconing and the Hospital learned to detect DDoS attacks - all while maintaining complete data privacy and Zero Trust principles.*")
