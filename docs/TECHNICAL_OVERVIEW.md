# ZeroTrust-AI Technical Overview

## 1. Purpose and Scope
ZeroTrust-AI is a real-time network threat detection system aligned with Zero Trust principles. It inspects encrypted traffic using flow-level behavioral features (SPLT) and fuses multiple ML detectors to classify flows as benign or malicious, enabling automated, risk-aware responses.

## 2. System Architecture
- Services
  - API Gateway (FastAPI): external API and auth gateway.
  - Detector (FastAPI + PyTorch/Sklearn): model loading, scoring, and rule fusion.
  - PCAP Replay: replays PCAPs and emits flow feature events (for demos/tests).
  - InfluxDB: time-series metrics (latency, throughput, errors).
  - Redis: risk scores with TTL-based decay for SOAR-style actions.
- Data Flow
  1) PCAP/Live capture -> SPLT feature extraction.
  2) Detector computes model scores (TCN, AE, IsolationForest).
  3) Scores are fused into a final risk and label.
  4) Results stored/visualized; optional automated actions.

## 3. Datasets
- CSE-CIC-IDS2018
  - Modern enterprise-like traffic with multiple attack families.
  - Used for benign/malicious examples and SPLT extraction.
- CTU-13 (CTU-2011) Labels (binetflow)
  - Used to generate a labeled SPLT dataset by joining on canonical 5‑tuple.
- Local Artifacts
  - data/processed/splt_features.csv: extracted SPLT features.
  - data/processed/splt_features_labeled.csv: joined labels for supervision.

## 4. Features: SPLT (Sequence of Packet Lengths and Times)
- First N=20 packets per flow as two sequences:
  - Packet length with direction (+/−) and log scaling.
  - Inter-arrival times (IAT) with log scaling.
- Why SPLT?
  - Robust to encryption (no payload required).
  - Captures timing/size patterns unique to malware C2, scans, beacons, etc.

## 5. Models and Rationale
- Temporal Convolutional Network (TCN)
  - Input: 2×20 sequence tensor (lengths, IATs).
  - Output: probability of malicious (softmax).
  - Why: Captures local temporal motifs efficiently with low latency.
- Autoencoder (AE)
  - Trained on benign-only SPLT to reconstruct normal patterns.
  - Inference: reconstruction error -> anomaly score (normalized by threshold).
  - Why: Unsupervised detection of novel/rare behaviors.
- Isolation Forest (IsoForest)
  - Trained on vectorized SPLT features (scaled).
  - Inference: anomaly score from decision function; anomalies are predict = −1.
  - Why: Efficient unsupervised baseline, complements AE with different bias.
- Ensemble Fusion
  - Weighted sum: w1*TCN + w2*AE_score + w3*Iso_score (clipped 0..1).
  - Decision: label malicious if fused score >= threshold (e.g., 0.60).
  - Why: Increases robustness by combining supervised + unsupervised views.

## 6. Training & Evaluation Pipeline
- Scripts
  - scripts/train_tcn.py, train_autoencoder.py, train_isoforest_splt.py
  - scripts/evaluate_models.py (threshold/weight sweeps, IsoForest mapping fix)
  - scripts/build_labeled_splt_ctu.py (label join)
- Data Handling
  - Uses relative paths; models saved in models/.
  - Large files tracked with Git LFS or ignored via .gitignore.
- Current Metrics (example run)
  - TCN: Acc 0.9858, Prec 0.9880, Recall 0.9455, F1 0.9663
  - AE: Acc 0.7494, Prec 0.2008, Recall 0.0545, F1 0.0857
  - IsoForest: Acc 0.7824, Prec 0.0000, Recall 0.0000, F1 0.0000
  - Ensemble: Acc 0.8384, Prec 0.9989, Recall 0.2509, F1 0.4011
- Next Tuning Actions
  - Increase IsoForest contamination; verify scaler & anomaly mapping.
  - Sweep AE thresholds wider; consider stricter benign training data.
  - Rebalance ensemble weights and decision threshold for better F1.

## 7. Detector Microservice (services/detector/app/main.py)
- Loads models: TCN, AE (+ threshold), SPLT scaler + IsolationForest.
- Request: `FlowFeatures` includes optional SPLT sequences.
- Logic
  1) If SPLT present and models loaded, compute:
     - TCN p_mal = softmax(logits)[1]
     - AE reconstruction error -> normalized AE score
     - IsoForest anomaly score on scaled vectorized SPLT
  2) Fuse scores with configured weights; compare to threshold.
  3) Return `ThreatEvent` with label, confidence, severity, and reasons.
- Fallback: legacy scalar pipeline if SPLT missing.

## 8. Datastores and Why
- InfluxDB: high-ingest time-series for latency/throughput/training metrics.
- Redis: low-latency risk store with TTL for decaying risk and SOAR actions.
- Filesystem + Git LFS: versioned models/data; avoids oversized Git history.

## 9. Deployment
- Docker Compose orchestrates services with memory limits.
- Models mounted in detector container via volume.
- Optional dashboards (Streamlit) and API Gateway for external access.

## 10. Security & Reliability
- Zero Trust posture: treat every flow as untrusted; evaluate per-flow risk.
- Auditable responses and manual override planned in dashboard.
- Planned: 24‑hour stability test, metrics via Prometheus/Grafana.

## 11. How to Reproduce
1) Extract features: `python scripts/extract_splt_nfstream.py`
2) Build labeled dataset (optional): `python scripts/build_labeled_splt_ctu.py`
3) Train models:
   - `python scripts/train_tcn.py`
   - `python scripts/train_autoencoder.py`
   - `python scripts/train_isoforest_splt.py`
4) Evaluate: `python scripts/evaluate_models.py`
5) Run detector service with Docker Compose and post `FlowFeatures` requests.

## 12. Roadmap (Short-Term)
- Tune IsoForest/AE and optimize ensemble for higher recall.
- Integrate real-time NFStream pipeline; measure <500 ms latency.
- Add MITRE ATT&CK mapping & SOAR workflows in dashboard.
