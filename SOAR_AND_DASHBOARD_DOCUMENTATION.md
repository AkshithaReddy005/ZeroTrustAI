# ZeroTrust-AI: SOAR Implementation, Streamlit Dashboard & Application Workflow

## 1. Overview

This document describes the **SOAR (Security Orchestration, Automation, and Response)** logic in the React SOC dashboard, the **Streamlit real-time dashboard**, the **end-to-end workflow**, and the **commands to run the entire application**.

---

## 2. SOAR Implementation (Streamlit)

SOAR is implemented **in the Streamlit dashboard** (`apps/dashboard/realtime_dashboard.py`). The backend does not perform SOAR; it only provides threat events. The Streamlit app derives **policy-driven, deduplicated SOAR actions** from those events. The React SOC (`apps/web/index.html`) may also show a SOAR panel for consistency; the canonical implementation is in Streamlit.

### 2.1 Design Principles

- **Read-only**: Frontend does not send block/rate-limit commands to the backend; it only **displays** derived actions.
- **Risk- and confidence-driven**: Actions are derived from `risk_score` and `confidence` (or `confidence` used as risk when `risk_score` is absent).
- **Rolling 15-minute window**: All SOAR logic uses events from the last 15 minutes only.
- **Deduplication**: At most **one action per (action type, target)** in the window (e.g. one Rate Limit per IP, one Block per IP).
- **Rarity**: SOAR panel is capped to the **top 3 actions by risk_score** in the window so the log stays calm (target: 1–3 actions per 15 min, 0–1 blocks).

### 2.2 SOAR Decision Policy

| Condition | Action | Policy | When |
|-----------|--------|--------|------|
| `risk_score < 0.70` | **No SOAR entry** | Monitor only | Detection is shown in feed only; no SOAR row. |
| `0.70 ≤ risk_score < 0.85` **and** volumetric reason | **Rate Limit** | Medium-Risk Containment | Only if reason contains `high_packets_per_second`, `syn_flood`, `ddos`, or `flood`. One Rate Limit per target (IP or flow_id) per window. |
| `risk_score ≥ 0.85` **and** `confidence ≥ 0.90` | **Block** | High-Risk Prevention | One Block per target per window. |

**Volumetric check (medium risk):**  
Rate Limit is created only when the event's `reason` (joined and lowercased) contains at least one of: `high_packets_per_second`, `syn_flood`, `ddos`, `flood`. Other medium-risk threats get no SOAR entry.

**Target:**  
`target` is `source_ip` if present, else IP parsed from `flow_id`, else `flow_id`. Deduplication uses this target (e.g. `rate|192.168.1.100`, `block|192.168.1.100`).

### 2.3 Deduplication

- In-memory map `soarDedupe` keyed by `actionType|target` (e.g. `rate|192.168.1.50`, `block|flow-mal-42`).
- First qualifying event for that (action type, target) creates the SOAR entry and sets the key; later events for the same key in the same 15-minute run do **not** create another entry.
- Prevents repeated "Rate limited flow" or "Block IP" for the same entity.

### 2.4 Cap: Top 3 Actions

- After collecting all SOAR entries in the window, the list is **sorted by `risk_score` descending** and **sliced to 3**.
- Only these 3 are passed to the SOAR panel. So even with many qualifying events, the UI shows at most 3 actions per 15-minute window.

### 2.5 SOAR Entry Format (UI)

Each row in **"Automated SOAR Actions (Last 15 min)"** includes:

- **Timestamp** – event time
- **Action Type** – `Rate Limit` or `Block`
- **Target** – IP or flow_id
- **Trigger details** – `risk_score`, `confidence`, primary reason (first element of `reason[]`)
- **Policy Applied** – `Medium-Risk Containment` or `High-Risk Prevention`
- **Status** – `SUCCESS` (no failure status is derived in the frontend)

### 2.6 Code Location

- **Policy and aggregation:** `apps/dashboard/realtime_dashboard.py`:
  - `compute_soar_actions(threats)` – 15-min window (epoch), risk/confidence (with fallback from `severity`), volumetric check, dedupe by `actionType|target`, top 3 by risk.
  - `get_threats(limit=1000)` – fetches enough threats for the 15-minute window.
- **UI:** Section **"🤖 Automated SOAR Actions (Last 15 min)"** below Model Status; each entry shows timestamp, action type, target, policy, status, and trigger (risk, confidence, primary reason).

---

## 3. Streamlit Dashboard

### 3.1 Purpose and Role

- **File:** `apps/dashboard/realtime_dashboard.py`
- **Role:** Python-based real-time view. It **polls** the same backend (WebSocket server and optional API gateway), shows metrics, a short threat list, and the **Automated SOAR Actions (Last 15 min)** panel. SOAR is implemented here; the React dashboard may show a similar panel for parity.

### 3.2 Data Sources

- **Threats:** `GET http://localhost:9000/threats` (WebSocket server; same data as React).
- **Metrics:** `GET http://localhost:8000/metrics` (API Gateway).  
  If the API Gateway is not running, metrics fall back to values derived from the threats list (e.g. `total_flows`, `accuracy`).

**Configured in code:**

- `DETECTOR_URL = "http://localhost:9000"` (WebSocket server)
- `API_URL = "http://localhost:8000"` (API Gateway)

### 3.3 Layout and Features

- **Header metrics (4 columns):** Total Flows, Threats Detected, Blocked, Accuracy (from `get_metrics()` and threat list).
- **Live Threat Detection:** Last 10 threats, severity-colored cards (high/medium/low), flow_id, label, confidence, time, reason.
- **Detection Trends:** Plotly line chart – threats per hour (if timestamps present).
- **Model Status:** Static list (TCN, Autoencoder, IsoForest, Ensemble) with status and accuracy; not wired to live ML.
- **Sidebar:** Auto-refresh checkbox (default on), refresh interval slider (1–10 s). When auto-refresh is on, the app sleeps then `st.rerun()`.

### 3.4 Differences from React Dashboard

| Aspect | React (apps/web/index.html) | Streamlit (realtime_dashboard.py) |
|--------|-----------------------------|------------------------------------|
| Updates | WebSocket push + periodic /metrics | Polling (threats + metrics) at chosen interval |
| SOAR | Yes – policy, dedupe, top 3, full trigger details | No SOAR panel |
| Risk bands / MITRE / Detection Engine | Yes | No (raw label/confidence/severity) |
| Traffic composition / context panels | Yes | No |
| Port | Served by WebSocket server at 9000 | 8501 (Streamlit) |

---

## 4. End-to-End Workflow

### 4.1 High-Level Flow

```
[Traffic source]
       │
       ▼
┌──────────────────┐     flows      ┌─────────────────────┐
│  Live Detector    │ ──────────────►│  Detector (main.py)  │
│  Bridge (script)  │                │  Port 9001          │
└──────────────────┘                │  /detect → ML       │
       │                             └──────────┬──────────┘
       │                                        │ threat events
       │                             ┌──────────▼──────────┐
       │                             │  WebSocket Server    │
       │                             │  (websocket_server   │
       │                             │   .py) Port 9000     │
       │                             │  /detect, /threats,  │
       │                             │  /metrics, /ws       │
       │                             └──────────┬──────────┘
       │                                        │
       │         GET /threats, /metrics          │ WebSocket + REST
       │         WebSocket /ws                   │
       ├────────────────────────────────────────┤
       ▼                                        ▼
┌──────────────────┐                  ┌─────────────────────┐
│  Streamlit       │                  │  React SOC Dashboard │
│  Dashboard       │                  │  (index.html)        │
│  Port 8501       │                  │  SOAR, MITRE, etc.    │
└──────────────────┘                  └─────────────────────┘
```

- **Bridge** generates synthetic flows and sends them to the **Detector** (port 9001). Detector runs ML and returns threat events.
- **Bridge** then POSTs those threat events to the **WebSocket server** (port 9000) at `/detect`. The WebSocket server keeps threat history and broadcasts to WebSocket clients.
- **React dashboard** (served at port 9000) gets initial data via `GET /threats` and live updates via WebSocket; it also calls `GET /metrics` (on 9000) for top-line numbers. In the frontend it derives SOAR, severity bands, MITRE, etc.
- **Streamlit dashboard** (port 8501) only polls `GET /threats` (9000) and `GET /metrics` (8000 if API Gateway is up).

### 4.2 Optional: API Gateway

- **Port 8000.** Can receive flow events and call the Detector (e.g. 9001) and WebSocket server (9000).  
- **Streamlit** uses `API_URL = "http://localhost:8000"` for metrics. If the API Gateway is not running, Streamlit still works using the threats list for derived metrics.

### 4.3 Event Fields Used by SOAR (Frontend)

From each event (from `/threats` or WebSocket), SOAR logic uses:

- `risk_score` or `confidence` (as risk)
- `confidence` (for high-risk block threshold)
- `reason` (array; for volumetric check and primary_reason)
- `source_ip` or IP from `flow_id`
- `flow_id`
- `timestamp`
- `is_threat` (derived in frontend from risk band)

No backend or ML code is modified for SOAR; it is entirely derived on the client.

---

## 5. How to Run the Entire Application

Use the project root as `ZeroTrustAI` (e.g. `d:\techs (1)\techs\ZeroTrustAI`). Adjust paths if yours differs.

### 5.1 Prerequisites

- Python 3.9+
- Dependencies: `pip install -r requirements.txt` (and optionally `pip install streamlit-shap shap` for XAI apps).

### 5.2 Minimal Run (React SOC + SOAR + Streamlit)

**Terminal 1 – WebSocket server (serves React UI + API):**

```bash
cd "d:\techs (1)\techs\ZeroTrustAI\services\detector\app"
python -X utf8 websocket_server.py
```

- React dashboard: **http://localhost:9000**
- Demo mode (synthetic traffic): **http://localhost:9000/?demo=1**

**Terminal 2 – Detector (ML):**

```bash
cd "d:\techs (1)\techs\ZeroTrustAI"
python services/detector/app/main.py
```

- Detector: **http://localhost:9001** (e.g. `/health`)

**Terminal 3 – Live detector bridge (synthetic flows → detector → WebSocket server):**

```bash
cd "d:\techs (1)\techs\ZeroTrustAI"
python scripts/live_detector_bridge.py
```

**Terminal 4 – Streamlit dashboard:**

```bash
cd "d:\techs (1)\techs\ZeroTrustAI"
python -m streamlit run apps/dashboard/realtime_dashboard.py --server.port 8501
```

- Streamlit: **http://localhost:8501**

**Optional – Train detector (so high-risk/block conditions can be met):**

```bash
curl -X POST http://localhost:9001/train -H "Content-Type: application/json" -d "{}"
```

### 5.3 With API Gateway (for Streamlit metrics from 8000)

**Terminal 5 – API Gateway:**

```bash
cd "d:\techs (1)\techs\ZeroTrustAI\services\api-gateway"
set DETECTOR_URL=http://localhost:9001
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

- API: **http://localhost:8000** (e.g. `/health`, `/metrics`)

Streamlit's "Total Flows" and "Accuracy" will then use `/metrics` from port 8000 when available.

### 5.4 Quick Copy-Paste Summary (Windows PowerShell)

```powershell
# 1) WebSocket server + React UI
cd "d:\techs (1)\techs\ZeroTrustAI\services\detector\app"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python -X utf8 websocket_server.py"

# 2) Detector
cd "d:\techs (1)\techs\ZeroTrustAI"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python services/detector/app/main.py"

# 3) Optional: train detector
Start-Sleep -Seconds 5
Invoke-WebRequest -Uri "http://localhost:9001/train" -Method POST -ContentType "application/json" -Body "{}"

# 4) Bridge
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd 'd:\techs (1)\techs\ZeroTrustAI'; python scripts/live_detector_bridge.py"

# 5) Streamlit
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd 'd:\techs (1)\techs\ZeroTrustAI'; python -m streamlit run apps/dashboard/realtime_dashboard.py --server.port 8501"
```

Then open:

- **React (SOC + SOAR):** http://localhost:9000  
- **Streamlit:** http://localhost:8501  

### 5.5 Service Ports Reference

| Service            | Port | Purpose                              |
|--------------------|------|--------------------------------------|
| WebSocket server   | 9000 | React UI, /threats, /metrics, /ws    |
| Detector           | 9001 | /detect, /health, /train            |
| API Gateway        | 8000 | /metrics, /api (optional)           |
| Streamlit          | 8501 | Real-time dashboard                 |

---

## 6. Summary

- **SOAR** is implemented only in the React dashboard: 15-minute window, risk/confidence thresholds, volumetric filter for Rate Limit, deduplication per (action type, target), and cap of 3 actions. No backend or ML changes.
- **Streamlit** is a separate, polling-based dashboard that shows threats and metrics; it does not implement SOAR.
- **Workflow:** Bridge → Detector (9001) → WebSocket server (9000) → React (and optionally Streamlit + API Gateway).
- **Run order:** WebSocket server → Detector → (optional train) → Bridge → Streamlit (and optionally API Gateway). Use the commands in Section 5 to run the full application.
