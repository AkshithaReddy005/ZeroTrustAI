# ZeroTrust-AI: Enterprise Security Platform

ZeroTrust-AI is a comprehensive, production-ready, enterprise-grade security platform. It combines a multi-lens deep learning detection pipeline, decentralized Byzantine-resilient federated learning, real-time network traffic analysis, and automated SOAR response capabilities to protect modern network infrastructures.

---

## 🛡️ Architecture & Core Components

ZeroTrust-AI implements a two-stage Hierarchical Meta-Fuser consensus design for multi-layered security validation and automated mitigation:

```mermaid
graph TD
    %% Nodes
    PCAP["PCAP Files<br>(Network Traffic Captures)"]
    SPLT["SPLT Feature Extraction<br>(Sequence of Packet Lengths & Inter-arrival Times)"]
    CSV["CSV Files<br>(Pre-processed Features with Fusion Scores)"]
    
    subgraph RealTimePipeline["Real-time Pipeline"]
        Engine["Real-time Data Stream /<br>Threat Scoring Engine"]
        WS["WebSocket Server<br>(Real-time Communication)"]
    end

    subgraph Stage1Lenses["Stage 1: Anomaly Experts Group"]
        AE["Autoencoder<br>(Anomaly Detection)"]
        GAN["GAN Discriminator<br>(Attack Pattern Recognition)"]
    end

    TCN["TCN Model<br>(Temporal Convolutional Network)"]
    
    subgraph Stage1Consensus["Stage 1 Consensus Evaluation"]
        Consensus["AE + GAN Consensus<br>(Anomaly Expert Output)"]
    end
    
    subgraph Stage2["Stage 2: Zero Trust Fusion"]
        MLP["MLP Classifier<br>(Meta-Fuser with Adaptive Threshold: 0.40)"]
    end

    subgraph SOAR["SOAR Integration"]
        SecOrch["Security Orchestration<br>Automation & Response<br>(Threat Mitigation Actions)"]
    end

    subgraph Vis["Output & Visualization"]
        Dash["ZeroTrust Dashboard<br>(Real-time Threat Monitoring)"]
        Alerts["Threat Alerts<br>(Benign/Malicious Predictions, Confidence Scores)"]
        AutoResponse["Automated Response<br>(Block/IP Blocking, Alert Generation)"]
    end

    %% Connections
    PCAP --> SPLT
    SPLT --> CSV
    CSV --> Engine
    
    %% Real-time engine <-> Models bidirectional/loop
    Engine <--> AE
    Engine <--> TCN
    Engine <--> GAN
    
    %% Stage 1 model interactions
    TCN --> AE
    TCN --> GAN
    
    %% Stage 1 Consensus
    AE --> Consensus
    GAN --> Consensus
    TCN --> Consensus
    
    %% Stage 2 Fusion
    Consensus --> MLP
    TCN --> MLP
    MLP --> Engine
    
    %% WebSocket and downstream
    Engine --> WS
    WS --> SecOrch
    WS --> Dash
    WS --> Alerts
    
    SecOrch --> AutoResponse
    Alerts --> AutoResponse

    %% Style Classes for Beautiful Custom Colors
    classDef inputStyle fill:#d6eaf8,stroke:#2e86c1,stroke-width:2px,color:#1b4f72;
    classDef procStyle fill:#ebdcf9,stroke:#6c3483,stroke-width:2px,color:#4a235a;
    classDef modelStyle fill:#f5eef8,stroke:#8e44ad,stroke-width:2px,color:#4a235a;
    classDef visualStyle fill:#d5f5e3,stroke:#27ae60,stroke-width:2px,color:#145a32;
    classDef alertStyle fill:#fdebd0,stroke:#d35400,stroke-width:2px,color:#5e2f0d;
    classDef responseStyle fill:#fadbd8,stroke:#cb4335,stroke-width:2px,color:#78281f;

    %% Assigning Classes
    class PCAP,CSV,Alerts inputStyle;
    class SPLT,Engine,WS,SecOrch,Consensus,MLP procStyle;
    class AE,GAN,TCN modelStyle;
    class Dash visualStyle;
    class AutoResponse responseStyle;
```

### 🔍 1. Hierarchical Meta-Fuser Architecture
The threat scoring system employs a hierarchical multi-stage evaluation:
*   **Feature Processing & Ingestion:** Ingests raw **PCAP network captures**, performs **SPLT (Sequence of Packet Lengths and Inter-arrival Times) feature extraction**, and feeds pre-processed CSV streams to the real-time scoring engine.
*   **Stage 1: Threat Analysis Lenses:** Parallel processing of traffic features split into distinct lens categories:
    *   **Anomaly Expert Group:** Unsupervised/adversarial anomaly verification.
        *   **Autoencoder:** Unsupervised anomaly detection focusing on baseline reconstruction error.
        *   **GAN Discriminator:** Identifies malicious/synthetic attack patterns via adversarial discriminator classification.
    *   **Sequence Modeling:**
        *   **TCN Model (Temporal Convolutional Network):** Models sequential patterns and temporal flow relationships.
*   **Stage 1 Consensus:** An **AE + GAN Consensus** step synthesizes outputs from the Anomaly Expert Group.
*   **Stage 2: Zero Trust Fusion:** An **MLP Classifier** acts as the final Meta-Fuser. It merges Stage 1 Consensus outputs and raw TCN scores, utilizing an **Adaptive Threshold of 0.40** to make the final benign vs. malicious determination.

### 🧠 2. Real-Time Streaming & WebSocket Server
*   **Real-time Scoring Engine:** Receives continuous network traffic, queries the hierarchical model structure, and forwards classifications.
*   **WebSocket Server:** Handles low-latency real-time distribution of threat metrics.
*   **Output & Visualization:** Renders alerts and live charts on the **ZeroTrust Dashboard**, streaming benign/malicious predictions and confidence scores.

### 🚀 3. SOAR Integration & Automated Response
*   **SOAR Action Loop:** Receives real-time threat alerts, triggers **Security Orchestration Automation & Response (SOAR)** workflows, and coordinates **Automated Response** (e.g., immediate IP blocking/quarantining and notification generation).

---

## 📁 Repository Structure

```
ZeroTrust-AI/
├── apps/                          # Web applications & visualization interfaces
│   └── dashboard/                # Streamlit SOAR dashboard
├── c2_ddos/                      # C2 & DDoS detection core
│   ├── scripts/                  # Data labeling, training, feature engineering
│   │   ├── snorkel_labeling.py   # Snorkel-based weak supervision labeling
│   │   ├── redis_feature_store.py# Real-time feature storage integration
│   │   └── ensemble_fusion.py    # Multi-lens ensemble classification
│   └── PROJECT_PLAN.md           # Implementation phase guidelines
├── data/                          # Datasets and summaries
│   └── processed/                # Unified and balanced CSV datasets
├── demo/                          # Demo scripts and playground scripts
├── docs/                          # In-depth architectural & API documents
├── federated-learning/           # Federated training framework
│   ├── run_federated_fast.py      # Main federated driver with trust scoring
│   └── byzantine_detection.py     # Byzantine defense algorithms
├── models/                        # Saved checkpoints and serialization files
├── services/                      # API services and container configs
└── scripts/                       # Root level validation & feature utility scripts
```

---

## 🚀 Quick Start

### Prerequisites
*   Python 3.9+
*   Docker & Docker Compose
*   Redis (for feature caching and PEP state)
*   InfluxDB (for timeseries metrics)

### Installation

1. **Clone the Repository**
    ```bash
    git clone https://github.com/AkshithaReddy005/ZeroTrustAI.git
    cd ZeroTrust-AI
    ```

2. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3. **Spin up Infrastructure (Redis & InfluxDB)**
    ```bash
    docker-compose -f docker-compose.web.yml up -d
    ```

4. **Launch the Dashboard**
    ```bash
    streamlit run apps/dashboard/soar_dashboard.py
    ```

---

## 🧪 Running Pipelines & Demos

### 1. Federated Learning Consensus Simulation
Simulate a decentralized training environment with dynamic trust allocation and Byzantine attack simulation:
```bash
python federated-learning/run_federated_fast.py
```

### 2. Live PCAP Processing Pipeline
Extract features from live network interfaces or PCAP files and stream metrics to the dashboard:
```bash
python realtime_pcap_processor.py --pcap path/to/traffic.pcap
```

### 3. Evaluate Real PCAP Files
Run the models on raw network captures to benchmark performance:
```bash
python evaluate_real_pcap.py
```

---

## 📈 Performance & Calibration Metrics

*   **DDoS Detection Accuracy:** 95%+
*   **C2 Beaconing Detection Accuracy:** 90%+
*   **False Positive Rate:** < 5%
*   **Response Time (PEP Trigger):** < 100ms
*   **Byzantine Resistance:** 99%+ malicious node isolation rate

---

## 📄 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
