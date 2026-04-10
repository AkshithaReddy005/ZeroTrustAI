#!/usr/bin/env python3
"""Live Federated Learning Demo for Jury Presentation.

Runs round-by-round simulation in Streamlit and updates charts live.
"""

from pathlib import Path
import time
from typing import Dict, List

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data" / "processed"


class TCN(nn.Module):
    def __init__(self, input_size: int, num_classes: int = 2):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def _feature_cols(df: pd.DataFrame) -> List[str]:
    exclude = {"label", "Label", "Attack_Type", "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"}
    numeric = df.select_dtypes(include=[np.number]).columns.tolist()
    return [c for c in numeric if c not in exclude]


def _load_client(path: Path, batch_size: int, seed: int, max_rows: int):
    df = pd.read_csv(path, low_memory=False)
    if "label" not in df.columns and "Label" in df.columns:
        df["label"] = df["Label"].astype(int)

    if max_rows > 0 and len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=seed)

    cols = _feature_cols(df)
    X = df[cols].fillna(0).values
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=seed,
        stratify=y if len(np.unique(y)) > 1 else None,
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    train_loader = DataLoader(
        TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train)),
        batch_size=batch_size,
        shuffle=True,
    )
    test_loader = DataLoader(
        TensorDataset(torch.FloatTensor(X_test), torch.LongTensor(y_test)),
        batch_size=batch_size,
        shuffle=False,
    )

    return {"train": train_loader, "test": test_loader, "feature_dim": len(cols)}


def _train_local(model: nn.Module, loader: DataLoader, device: torch.device, lr: float, epochs: int) -> float:
    model.train()
    opt = optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss()
    total = 0.0
    n = 0

    for _ in range(epochs):
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            opt.zero_grad()
            logits = model(xb)
            loss = loss_fn(logits, yb)
            loss.backward()
            opt.step()
            total += float(loss.item())
            n += 1
    return total / max(1, n)


def _eval_f1(model: nn.Module, loader: DataLoader, device: torch.device) -> float:
    model.eval()
    preds, labels = [], []
    with torch.no_grad():
        for xb, yb in loader:
            xb = xb.to(device)
            logits = model(xb)
            yhat = torch.argmax(logits, dim=1).cpu().numpy().tolist()
            preds.extend(yhat)
            labels.extend(yb.numpy().tolist())
    return float(f1_score(labels, preds, average="weighted"))


def _fedavg(state_dicts: List[Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
    out = {}
    for k in state_dicts[0].keys():
        out[k] = torch.stack([sd[k] for sd in state_dicts], dim=0).mean(dim=0)
    return out


def _plot_losses(history: pd.DataFrame):
    fig = go.Figure()
    for col in ["bank_loss", "hospital_loss", "tech_loss", "malicious_loss"]:
        if col in history.columns:
            fig.add_trace(go.Scatter(x=history["round"], y=history[col], mode="lines+markers", name=col.replace("_loss", "").title()))
    fig.update_layout(title="Per-Round Local Training Loss", xaxis_title="Round", yaxis_title="Loss", height=360)
    return fig


def _plot_global_f1(history: pd.DataFrame):
    fig = go.Figure()
    for col in ["global_on_bank", "global_on_hospital", "global_on_tech"]:
        if col in history.columns:
            fig.add_trace(go.Scatter(x=history["round"], y=history[col], mode="lines+markers", name=col.replace("global_on_", "Global on ").title()))
    fig.update_layout(title="Global Model Performance by Round", xaxis_title="Round", yaxis_title="F1", yaxis=dict(range=[0, 1]), height=360)
    return fig


def _plot_transfer(history: pd.DataFrame):
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=history["round"], y=history["bank_on_hospital"], mode="lines+markers", name="Bank Isolated -> C2"))
    fig.add_trace(go.Scatter(x=history["round"], y=history["global_on_hospital"], mode="lines+markers", name="Global -> C2"))
    fig.add_trace(go.Scatter(x=history["round"], y=history["hospital_on_bank"], mode="lines+markers", name="Hospital Isolated -> DDoS"))
    fig.add_trace(go.Scatter(x=history["round"], y=history["global_on_bank"], mode="lines+markers", name="Global -> DDoS"))
    fig.update_layout(title="Cross-Domain Knowledge Transfer", xaxis_title="Round", yaxis_title="F1", yaxis=dict(range=[0, 1]), height=420)
    return fig


def main():
    st.set_page_config(page_title="Federated Live Demo", layout="wide")
    st.title("Live Federated Learning Simulation (Jury Demo)")
    st.caption("4 organizations -> local training each round -> FedAvg aggregation -> live metrics")

    st.markdown(
        """
### What you are showing to the jury (in order)
1. **Local training trend**: each organization trains on its own private data each round.
2. **Global model trend**: after aggregation, one shared model improves across organizations.
3. **Cross-domain transfer**: isolated models fail on unseen attack types, global model succeeds.
"""
    )
    st.info(
        "Read left-to-right by round. If green global lines rise while isolated cross-domain lines stay lower, "
        "that is the proof of federated knowledge transfer without data sharing."
    )

    missing = [p for p in [DATA_DIR / "federated_bank.csv", DATA_DIR / "federated_hospital.csv", DATA_DIR / "federated_tech.csv", DATA_DIR / "federated_malicious.csv"] if not p.exists()]
    if missing:
        st.error("Missing silo CSVs. Run: python federated-learning/create_silo_data.py")
        st.code("python federated-learning/create_silo_data.py", language="bash")
        return

    c1, c2, c3, c4, c5 = st.columns(5)
    rounds = c1.slider("Rounds", 1, 10, 5)
    local_epochs = c2.slider("Local Epochs", 1, 3, 1)
    batch_size = c3.selectbox("Batch Size", [32, 64, 128], index=1)
    max_rows = c4.selectbox("Rows/Org (speed)", [2000, 4000, 8000, 20000], index=1)
    sleep_s = c5.slider("Live Delay (sec)", 0.0, 2.0, 0.4, 0.1)

    lr = 0.001
    seed = 42
    include_malicious = st.checkbox("Include Malicious Organization", value=True)

    run_btn = st.button("Run Live Simulation", type="primary")

    status = st.empty()
    progress = st.progress(0)
    metrics_row = st.empty()

    tab_local, tab_global, tab_transfer, tab_log = st.tabs(
        [
            "1) Local Training per Org",
            "2) Global Model by Round",
            "3) Cross-Domain Failure -> Success",
            "4) Round-by-Round Log",
        ]
    )
    with tab_local:
        st.caption("Expect loss to generally go down as rounds progress.")
        chart_losses = st.empty()
    with tab_global:
        st.caption("This is the main global model quality after each aggregation.")
        chart_global = st.empty()
    with tab_transfer:
        st.caption("Money shot: global model outperforms isolated models on unseen attack types.")
        chart_transfer = st.empty()
    with tab_log:
        st.caption("Raw round metrics for transparency.")
        table_slot = st.empty()

    if not run_btn:
        st.info("Configure options and click 'Run Live Simulation'.")
        return

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    bank = _load_client(DATA_DIR / "federated_bank.csv", batch_size, seed, max_rows)
    hospital = _load_client(DATA_DIR / "federated_hospital.csv", batch_size, seed, max_rows)
    tech = _load_client(DATA_DIR / "federated_tech.csv", batch_size, seed, max_rows)
    malicious = _load_client(DATA_DIR / "federated_malicious.csv", batch_size, seed, max_rows)

    feature_dim = min(bank["feature_dim"], hospital["feature_dim"], tech["feature_dim"], malicious["feature_dim"])
    global_model = TCN(feature_dim).to(device)

    history = []

    for r in range(rounds + 1):
        status.info(f"Round {r}/{rounds}: evaluating + local training")

        # isolated transfer checks
        bank_iso = TCN(feature_dim).to(device)
        bank_iso.load_state_dict(global_model.state_dict())
        bank_loss = _train_local(bank_iso, bank["train"], device, lr, local_epochs)
        bank_on_hospital = _eval_f1(bank_iso, hospital["test"], device)

        hospital_iso = TCN(feature_dim).to(device)
        hospital_iso.load_state_dict(global_model.state_dict())
        hospital_loss = _train_local(hospital_iso, hospital["train"], device, lr, local_epochs)
        hospital_on_bank = _eval_f1(hospital_iso, bank["test"], device)

        tech_iso = TCN(feature_dim).to(device)
        tech_iso.load_state_dict(global_model.state_dict())
        tech_loss = _train_local(tech_iso, tech["train"], device, lr, local_epochs)

        malicious_loss = np.nan
        if include_malicious:
            mal_iso = TCN(feature_dim).to(device)
            mal_iso.load_state_dict(global_model.state_dict())
            malicious_loss = _train_local(mal_iso, malicious["train"], device, lr, local_epochs)

        global_on_bank = _eval_f1(global_model, bank["test"], device)
        global_on_hospital = _eval_f1(global_model, hospital["test"], device)
        global_on_tech = _eval_f1(global_model, tech["test"], device)

        history.append(
            {
                "round": r,
                "bank_loss": bank_loss,
                "hospital_loss": hospital_loss,
                "tech_loss": tech_loss,
                "malicious_loss": malicious_loss,
                "bank_on_hospital": bank_on_hospital,
                "hospital_on_bank": hospital_on_bank,
                "global_on_bank": global_on_bank,
                "global_on_hospital": global_on_hospital,
                "global_on_tech": global_on_tech,
            }
        )

        hdf = pd.DataFrame(history)

        with metrics_row.container():
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Round", f"{r}/{rounds}")
            m2.metric("Global on Hospital", f"{global_on_hospital:.3f}")
            m3.metric("Bank->C2 (isolated)", f"{bank_on_hospital:.3f}")
            m4.metric("Hospital->DDoS (isolated)", f"{hospital_on_bank:.3f}")

        chart_losses.plotly_chart(_plot_losses(hdf), use_container_width=True)
        chart_global.plotly_chart(_plot_global_f1(hdf), use_container_width=True)
        chart_transfer.plotly_chart(_plot_transfer(hdf), use_container_width=True)
        table_slot.dataframe(hdf, use_container_width=True)

        progress.progress(int((r / max(1, rounds)) * 100))

        if r == rounds:
            break

        # Aggregate next global model
        local_states = []
        clients = [bank, hospital, tech] + ([malicious] if include_malicious else [])
        for cdata in clients:
            local = TCN(feature_dim).to(device)
            local.load_state_dict(global_model.state_dict())
            _train_local(local, cdata["train"], device, lr, local_epochs)
            local_states.append({k: v.detach().cpu() for k, v in local.state_dict().items()})

        global_model.load_state_dict(_fedavg(local_states))
        time.sleep(sleep_s)

    if history:
        final_df = pd.DataFrame(history)
        start = final_df.iloc[0]
        end = final_df.iloc[-1]

        st.markdown("---")
        st.subheader("Demo Summary (Before vs After)")
        s1, s2, s3 = st.columns(3)
        s1.metric(
            "Bank on C2 (isolated -> global)",
            f"{end['global_on_hospital']:.3f}",
            delta=f"{(end['global_on_hospital'] - start['bank_on_hospital']):+.3f} vs isolated start {start['bank_on_hospital']:.3f}",
        )
        s2.metric(
            "Hospital on DDoS (isolated -> global)",
            f"{end['global_on_bank']:.3f}",
            delta=f"{(end['global_on_bank'] - start['hospital_on_bank']):+.3f} vs isolated start {start['hospital_on_bank']:.3f}",
        )
        s3.metric(
            "Global on Tech (stability)",
            f"{end['global_on_tech']:.3f}",
            delta=f"{(end['global_on_tech'] - start['global_on_tech']):+.3f}",
        )

        with st.expander("Jury narration (read this while demo runs)"):
            st.markdown(
                """
- **Round 0**: Each organization only knows its own attack profile, so cross-domain detection is weak.
- **Rounds 1..N**: Each client trains locally, then shares only model weights.
- **Aggregation**: Server combines updates into one global model (FedAvg).
- **Outcome**: Global model detects attack types unseen by individual organizations.
- **Privacy claim**: No raw traffic records are exchanged at any point.
"""
            )

    status.success("Simulation complete. This output is ready for jury presentation.")


if __name__ == "__main__":
    main()
