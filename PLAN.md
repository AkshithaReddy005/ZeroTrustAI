# ZeroTrust-AI Implementation Plan

## Project Overview
AI-Driven Next-Generation Firewall with Zero Trust principles, featuring real-time threat detection using advanced ML models and automated response.

## Current Status: Week 1 Day 6 ✅ COMPLETE

### ✅ COMPLETED (Day 1-6)
- **Docker Environment Setup**
  - Docker Compose with all services (Python, Redis, InfluxDB)
  - Memory limits configured: API/Detector (4GB), Redis (2GB), InfluxDB (3GB)
  - WSL2 available for packet capture
  - Inter-service communication tested

- **Dataset Acquisition & Processing**
  - Downloaded CSE-CIC-IDS2018 dataset
  - Extracted SPLT features (packet lengths and inter-arrival times)
  - Created labeled dataset using CTU binetflow labels
  - Organized data in data/raw/ and data/processed/

- **Model Training Complete**
  - TCN classifier trained on SPLT sequences
  - Autoencoder trained for anomaly detection
  - Isolation Forest trained on SPLT features
  - All models saved to models/ directory

- **Evaluation & Metrics**
  - TCN: 98.58% accuracy, 96.63% F1-score
  - Autoencoder: 74.94% accuracy, 8.57% F1-score (needs tuning)
  - IsolationForest: 78.24% accuracy, 0% recall (needs improvement)
  - Ensemble: 83.84% accuracy, 40.11% F1-score

- **Git Integration**
  - All scripts and models pushed to GitHub
  - Git LFS configured for large files
  - Complete commit history preserved

---

## WEEK 1: FOUNDATION + DOCKER ENVIRONMENT ⏱️ 35–40 hours

### ✅ Day 1: Docker Environment Setup (COMPLETE)
- [x] Set up docker-compose with all services (Python, Redis, InfluxDB)
- [x] Configure memory limits for each container (prevent leaks)
- [x] Test inter-service communication
- [x] Deliverable: Memory-limited Docker environment

### ✅ Day 2: Dataset Acquisition (COMPLETE)
- [x] Download CSE-CIC-IDS2018 dataset
- [x] Verify TLS 1.3 traffic presence
- [x] Organize into data/raw/
- [x] Deliverable: Modern dataset ready

### ✅ Day 3–4: Feature Extraction with NFStream (COMPLETE)
- [x] Install NFStream
- [x] Extract SPLT features (Sequence of Packet Lengths and Times)
  - Packet length sequences (first 20 packets)
  - Inter-packet timing sequences
  - Flow duration, byte counts
  - TLS handshake metadata (version, cipher suites)
- [x] Apply log-scaling to packet lengths
- [x] Handle TLS 1.3 Encrypted Client Hello (ECH)
- [x] Deliverable: data/processed/splt_features.csv

### ✅ Day 5–6: Train TCN + Autoencoder (COMPLETE)
- [x] Build Temporal Convolutional Network (TCN)
- [x] Build Autoencoder for anomaly detection
- [x] Train on SPLT features
- [x] Deliverables:
  - models/tcn_classifier.pth (98.58% accuracy)
  - models/autoencoder.pth
  - models/splt_isoforest.joblib
  - models/splt_scaler.joblib
  - models/ae_threshold.txt

### 📅 Day 7: Train Isolation Forest + Ensemble (IN PROGRESS)
- [x] Train Isolation Forest
- [x] Create ensemble voting system (TCN + Autoencoder + Isolation Forest)
- [x] Generate performance metrics
- [ ] Optimize IsolationForest parameters (increase contamination)
- [ ] Tune Autoencoder threshold for better recall
- [ ] Optimize ensemble weights and decision threshold
- [ ] Deliverable: Enhanced ensemble with improved F1-score

---

## WEEK 2: CORE DETECTION ENGINE + SMART SOAR ⏱️ 35–40 hours

### 📅 Day 1–2: NFStream Real-Time Pipeline
- [ ] Build real-time detection with NFStream
- [ ] Integrate TCN inference for SPLT sequences
- [ ] Integrate Autoencoder + Isolation Forest
- [ ] Test detection latency (<500ms)
- [ ] Deliverable: Real-time detection engine

### 📅 Day 3–4: Device Fingerprinting + TTL-Based Risk Scoring
- [ ] Use TCN to classify device types
- [ ] Build Redis-based risk scoring with TTL (Time-To-Live)
- [ ] Implement risk scores decay over time
  - Example: SETEX device:laptop01 7200 50 (expires in 2 hours)
- [ ] Risk calculation formula: Current Risk = Base Risk + Anomaly Penalty − Time Decay
- [ ] Deliverable: Smart risk scoring with auto-decay

### 📅 Day 5–6: SOAR with Human-in-the-Loop
- [ ] Build dynamic risk-based automation
- [ ] Add "Manual Override" capability
  - Dashboard button: "Rollback Last Action"
  - Prevents accidental CEO laptop blocking
  - Logs all manual overrides for audit trail
- [ ] Automated responses:
  - Risk 50–70: Alert + Log
  - Risk 70–90: Isolate + Alert
  - Risk >90: Block IP + Require manual review
- [ ] Add "Whitelist" functionality for critical devices
- [ ] Deliverable: Production-safe SOAR with human oversight

### 📅 Day 7: Integration Testing
- [ ] Test complete workflow
- [ ] Verify TTL-based risk decay works
- [ ] Test manual override functionality
- [ ] Deliverable: Integrated system

---

## WEEK 3: FEDERATED LEARNING + MITRE DASHBOARD ⏱️ 35–40 hours

### 📅 Day 1–2: Federated Learning with Robust Aggregation
- [ ] Set up Flower framework
- [ ] Create 3 simulated clients (Hospital, Bank, Enterprise)
- [ ] Implement data poisoning simulation
  - Client 3 sends malicious updates
- [ ] Implement Robust Aggregation (FedAvg with outlier filtering)
  - Use median aggregation or Krum algorithm
- [ ] Demonstrate poisoned updates being rejected
- [ ] Privacy emphasis for demo:
  - Show Hospital and Bank sharing intelligence
  - Prove no raw traffic data exchanged
  - Visualize model convergence without data sharing
- [ ] Deliverable: Robust federated learning with poisoning defense

### 📅 Day 3–5: Dashboard with Automated MITRE Mapping
- [ ] Build Streamlit dashboard
- [ ] Create MITRE ATT&CK mapping JSON
  ```json
  {
    "Botnet": "T1071",
    "Port Scan": "T1595",
    "Brute Force": "T1110",
    "Malware C2": "T1071.001",
    "Data Exfiltration": "T1041",
    "Lateral Movement": "T1021"
  }
  ```
- [ ] Visual MITRE ATT&CK Matrix
  - Display full ATT&CK matrix
  - Highlight detected TTPs in red
  - Show technique descriptions on hover
  - Link to official MITRE documentation
- [ ] Add real-time metrics, threat feed, attack graphs
- [ ] Add anomaly heatmap
- [ ] Add "Manual Override" button (SOAR)
- [ ] Implement auto-refresh
- [ ] Deliverable: Dashboard with automated MITRE mapping

### 📅 Day 6–7: Database Integration
- [ ] Connect to InfluxDB for metrics
- [ ] Connect to Redis for risk scores (with TTL)
- [ ] Store threat events with MITRE TTP tags
- [ ] Track memory usage over time (for 24hr test)
- [ ] Build historical query functionality
- [ ] Deliverable: Database layer complete

---

## WEEK 4: API + STRESS TESTING + MEMORY PROFILING ⏱️ 35–40 hours

### 📅 Day 1–2: FastAPI Development
- [ ] Create REST API endpoints
  - Detection endpoint (accepts SPLT sequences)
  - Threat reporting with MITRE mapping
  - Risk score query (shows TTL remaining)
  - Manual override endpoints
  - Whitelist management
- [ ] Implement JWT authentication
- [ ] Deliverable: Complete REST API

### 📅 Day 3–4: TCPreplay Demo Setup
- [ ] Install TCPreplay
- [ ] Create virtual interface (veth)
- [ ] Prepare PCAP files for scenarios:
  - Normal TLS 1.3 traffic
  - Encrypted malware C2 with beacon pattern
  - Port scan
  - IoT botnet
  - DDoS
  - Federated learning poisoning attempt
- [ ] Test packet replay
- [ ] Deliverable: Controlled demo environment

### 📅 Day 5–6: 24-Hour Stress Test + Memory Profiling
- [ ] Run system for 24 hours continuously
- [ ] Monitor and graph memory usage
  - Use prometheus + grafana for monitoring
  - Track Python heap size
  - Track Redis memory
  - Track InfluxDB memory
  - Goal: Flat memory usage graph (proves no leaks)
- [ ] Monitor CPU usage, detection latency
- [ ] Fix any memory leaks found
- [ ] Deliverable: 24-hour stability proof + memory usage graph

### 📅 Day 7: Performance Optimization
- [ ] Profile code for bottlenecks
- [ ] Optimize TCN inference (batch processing)
- [ ] Optimize NFStream capture
- [ ] Optimize database queries
- [ ] Create performance dashboard showing:
  - Throughput (packets/second)
  - Detection latency
  - Memory usage (flat over 24 hours)
  - False positive rate
- [ ] Deliverable: Optimized system with performance graphs

---

## TECHNOLOGY STACK

### Core Services
- **Docker Compose**: Container orchestration
- **Redis**: Caching and TTL-based risk scoring
- **InfluxDB**: Time-series metrics storage
- **FastAPI**: REST API framework
- **Streamlit**: Dashboard frontend

### Machine Learning
- **PyTorch**: TCN and Autoencoder models
- **Scikit-Learn**: Isolation Forest
- **NFStream**: Real-time packet capture and feature extraction
- **Flower**: Federated learning framework

### Security & Monitoring
- **MITRE ATT&CK**: Threat intelligence mapping
- **JWT**: API authentication
- **Prometheus/Grafana**: Performance monitoring
- **TCPreplay**: Demo traffic generation

---

## DELIVERABLES

### Models
- `models/tcn_classifier.pth` - Temporal Convolutional Network (98.58% accuracy)
- `models/autoencoder.pth` - Anomaly detection autoencoder
- `models/splt_isoforest.joblib` - Isolation Forest for SPLT features
- `models/splt_scaler.joblib` - Feature scaler for SPLT
- `models/ae_threshold.txt` - Autoencoder anomaly threshold

### Data
- `data/raw/` - Raw CSE-CIC-IDS2018 dataset
- `data/processed/splt_features.csv` - Extracted SPLT features
- `data/processed/splt_features_labeled.csv` - Labeled SPLT dataset

### Scripts
- `scripts/train_tcn.py` - TCN training script
- `scripts/train_autoencoder.py` - Autoencoder training script
- `scripts/train_isoforest_splt.py` - Isolation Forest training script
- `scripts/evaluate_models.py` - Model evaluation with metrics
- `scripts/build_labeled_splt_ctu.py` - Dataset labeling script
- `scripts/extract_splt_nfstream.py` - SPLT feature extraction

### Services
- Complete Docker Compose stack with memory limits
- Real-time detection engine with <500ms latency (pending integration)
- REST API with JWT authentication (pending)
- Streamlit dashboard with MITRE mapping (pending)

### Documentation
- Performance metrics achieved (TCN: 98.58% accuracy)
- Git repository with complete history
- Technical documentation (this PLAN.md)

---

## NEXT STEPS (Immediate)

### 1. Model Optimization
- Improve IsolationForest recall by increasing contamination parameter
- Tune Autoencoder threshold for better F1-score
- Optimize ensemble weights for balanced precision/recall

### 2. Production Integration
- Update detector microservice with current best settings
- Implement real-time inference pipeline
- Set up monitoring for model performance

### 3. Testing & Validation
- Test on unseen PCAP captures
- Monitor false positive rates
- Validate against different attack types

---

## SUCCESS METRICS

### Performance Targets
- **Detection Latency**: <500ms
- **TCN Accuracy**: >92% on encrypted traffic
- **Memory Usage**: Flat over 24 hours (no leaks)
- **Throughput**: >10,000 packets/second

### Demo Requirements
- Live packet capture with NFStream
- Real-time threat detection and response
- MITRE ATT&CK visualization
- Manual override capabilities
- Federated learning demonstration

---

*Last Updated: February 3, 2026*
*Status: Week 1 Day 6 Complete - Models trained and evaluated*
