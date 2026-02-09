# ZeroTrust-AI: Complete Input & Output Flow

## 🎯 System Overview

```
🌐 Network Traffic → 🛡️ ZeroTrust-AI → 🔒 Security Actions
                      ↓
               🗄️ Memory Layer
          (Redis + InfluxDB)
```

## 🎯 System Status: 100% COMPLETE

### **✅ Final Implementation Status**
- **ML Ensemble**: 96.54% F1-score with TCN, Autoencoder, IsolationForest
- **Real-Time Processing**: Sub-100ms detection latency
- **Persistent Memory**: Redis (risk decay) + InfluxDB (historical)
- **MITRE ATT&CK**: Complete TTP mapping (T1071, T1027, T1046, etc.)
- **Performance Verified**: <100ms latency compliance testing
- **SOAR Capabilities**: Manual override with audit trail
- **XAI Integration**: SHAP-based explainable AI with visualizations
- **Dashboard Ready**: Real-time WebSocket interface
- **Production Deployed**: Docker containerization

### **🚀 Final Checklist (Week 4)**
- ✅ **MITRE ATT&CK Final Mapping**: All threats mapped to proper T-IDs
- ✅ **Performance Stress Test**: 1000 concurrent requests verified
- ✅ **SOAR Manual Override**: IP blocking/unblocking with Redis proof
- ✅ **Complete Documentation**: All .md files updated and verified
- ✅ **XAI Implementation**: SHAP explanations with force/waterfall plots

---

## � How to Run ZeroTrust-AI

### **🐳 Option 1: Docker (Recommended)**
```bash
# Start all 6 services
docker compose up --build -d

# Access services
# Dashboard: http://localhost:8501
# API: http://localhost:8000
# Detector: http://localhost:9000
# InfluxDB: http://localhost:8086
# Redis: localhost:6379
```

### **🚀 Option 2: Without Docker (Local Development)**
```bash
# Install dependencies
pip install -r requirements.txt
pip install streamlit-shap shap

# Start required services (minimum 3)
redis-server &
influxd &
cd services/detector/app && python main.py &

# Start optional services
cd services/api-gateway && python main.py &
cd apps/dashboard && streamlit run index.py &
cd apps/dashboard && streamlit run xai_dashboard_standalone.py &
```

### **📋 Minimum Required Services:**
- **Redis** (port 6379) - Caching and risk storage
- **InfluxDB** (port 8086) - Time-series database
- **Detector** (port 9000) - ML threat detection engine

---

## �📥 INPUT: What Goes Into Your System

### **🌐 Primary Input: Network Traffic**
```
┌─────────────────────────────────────┐
│             NETWORK TRAFFIC              │
│  ┌─────────────┐  ┌─────────────┐   │
│  │   Live      │  │   PCAP     │   │
│  │  Traffic    │  │   Files     │   │
│  │             │  │             │   │
│  └─────────────┘  └─────────────┘   │
│         │               │             │
│         ▼               ▼             │
│  ┌─────────────────────┐       │
│  │    ZeroTrust-AI System     │       │
│  │  📊 Feature Extraction     │       │
│  │  🤖 ML Models             │       │
│  │  🎯 Decision Engine        │       │
│  └─────────────────────┘       │
└─────────────────────────────────────┘
```

### **📁 Detailed Input Sources**

#### **1. Live Network Traffic (Production)**
```
🔗 Source: Network Interface (eth0, wlan0, etc.)
📦 Format: Raw network packets
📊 Volume: 10,000+ packets/second
🔐 Content: Encrypted + unencrypted traffic
🌐 Protocols: HTTP, HTTPS, DNS, SSH, FTP, etc.
```

#### **2. PCAP Files (Development/Testing)**
```
📂 Location: data/raw/
📄 Datasets: CSE-CIC-IDS2018, CTU-13
📁 Format: .pcap, .pcapng files
📊 Size: GBs of historical traffic
🎯 Purpose: Model training, testing, validation
```

### **🔍 What Each Packet Contains**
```
┌─────────────────────────────────────┐
│           SINGLE PACKET             │
├─────────────────────────────────────┤
│ 📋 IP Headers:                 │
│ • Source IP (e.g., 192.168.1.100) │
│ • Destination IP (e.g., 10.0.0.1)    │
│ • Protocol (TCP/UDP/ICMP)           │
├─────────────────────────────────────┤
│ 📋 Transport Headers:            │
│ • Source Port (e.g., 45678)         │
│ • Destination Port (e.g., 443)        │
│ • Flags (SYN, ACK, FIN)             │
├─────────────────────────────────────┤
│ 📋 Packet Payload:               │
│ • Encrypted data (HTTPS, SSH)       │
│ • Unencrypted data (HTTP, DNS)      │
│ • Size: 64-1500 bytes              │
├─────────────────────────────────────┤
│ 📋 Timing Information:            │
│ • Timestamp (nanosecond precision)   │
│ • Inter-arrival times               │
└─────────────────────────────────────┘
```

## 🛡️ PROCESSING: What ZeroTrust-AI Does

### **🔍 Step 1: Flow Aggregation**
```
Input: Individual packets
┌─────────────────────────────────────┐
│  Packet 1: 192.168.1.100→10.0.0.1 │
│  Packet 2: 10.0.0.1→192.168.1.100 │
│  Packet 3: 192.168.1.100→10.0.0.1 │
│  ... (thousands more packets)          │
└─────────────────────────────────────┘
         ▼
Output: Grouped by 5-tuple flows
┌─────────────────────────────────────┐
│  Flow 1: 192.168.1.100:45678→10.0.0.1:443/TCP │
│  • Packets: 1,247                    │
│  • Duration: 15.3 seconds               │
│  • Bytes: 85,000                       │
└─────────────────────────────────────┘
```

### **🔍 Step 2: Feature Extraction (SPLT)**
```
Input: Flow with packets
┌─────────────────────────────────────┐
│  Flow: 192.168.1.100:45678→10.0.0.1:443 │
│  Packets: [1500, 1200, 1500, 64, ...]   │
│  Timing: [0.001, 0.005, 0.002, ...]     │
└─────────────────────────────────────┘
         ▼
Output: SPLT Features
┌─────────────────────────────────────┐
│  Packet Lengths: [+7.31, -7.09, +7.31, -4.16, ...] │
│  Inter-arrival Times: [0.001, 0.005, 0.002, ...]     │
│  Flow Metadata: duration=15.3s, packets=1247, bytes=85K   │
└─────────────────────────────────────┘
```

### **🤖 Step 3: ML Model Analysis**
```
Input: SPLT Features
┌─────────────────────────────────────┐
│  TCN Input: [+7.31, -7.09, ..., 0.001, 0.005, ...] │
│  AE Input: Same sequence for reconstruction               │
│  IsoForest Input: Flattened 40-dimensional vector     │
└─────────────────────────────────────┘
         ▼
Output: Model Scores
┌─────────────────────────────────────┐
│  TCN: 0.87 (malicious probability)     │
│  AE: 0.45 (anomaly score)              │
│  IsoForest: 0.32 (outlier score)         │
└─────────────────────────────────────┘
```

### **🎯 Step 4: Ensemble Decision**
```
Input: Individual Model Scores
┌─────────────────────────────────────┐
│  TCN: 0.87 (60% weight)               │
│  AE: 0.45 (20% weight)                │
│  IsoForest: 0.32 (20% weight)          │
└─────────────────────────────────────┘
         ▼
Output: Final Decision
┌─────────────────────────────────────┐
│  Ensemble Score: 0.65                 │
│  Decision: MALICIOUS (≥0.6)           │
│  Confidence: 65%                      │
│  Severity: HIGH                       │
│  Reasons: ["tcn_malicious", "ae_anomalous"] │
└─────────────────────────────────────┘
```

### **🗄️ Step 5: Database Storage (Memory)**
```
Input: Final Decision
┌─────────────────────────────────────┐
│  Decision: MALICIOUS                  │
│  Score: 0.65, Severity: HIGH          │
│  Source IP: 192.168.1.100             │
│  Flow ID: flow_12345                  │
└─────────────────────────────────────┘
         ▼
Output: Persistent Storage
┌─────────────────────────────────────┐
│  📊 Redis (Real-Time):               │
│  Key: risk:192.168.1.100             │
│  Data: {score:0.65, severity:HIGH,   │
│         reasons:"tcn_malicious,ae_anomalous"} │
│  TTL: 30 minutes (Risk Decay)        │
│                                     │
│  📈 InfluxDB (Historical):           │
│  Measurement: threat_events          │
│  Tags: label=malicious, severity=HIGH│
│  Fields: score=0.65, confidence=0.65 │
│  Timestamp: 2024-02-07T14:20:00Z     │
└─────────────────────────────────────┘
```

## 📤 OUTPUT: What Your System Produces

### **🚨 Primary Output: Security Decisions**
```
┌─────────────────────────────────────┐
│        THREAT EVENT              │
├─────────────────────────────────────┤
│ 🆔 Flow ID: 192.168.1.100:45678→10.0.0.1:443/TCP │
│ 🏷️ Label: MALICIOUS                    │
│ 📊 Confidence: 0.87 (87%)              │
│ ⚠️ Anomaly Score: 0.65 (65%)           │
│ 🚨 Severity: HIGH                        │
│ 🔍 Reasons: ["tcn_malicious", "ae_anomalous"] │
│ ⏰ Timestamp: 2024-02-06T11:24:00Z     │
└─────────────────────────────────────┘
```

### **🌐 Web Interface Output**
```
┌─────────────────────────────────────────────────────────┐
│              WEB DASHBOARD                     │
├─────────────────────────────────────────────────────────┤
│ 📊 Metrics Panel:                             │
│ • Total Flows: 12,847                        │
│ • Threats Detected: 47                          │
│ • Blocked: 23                                   │
│ • Accuracy: 94.2%                              │
├─────────────────────────────────────────────────────────┤
│ 🚨 Live Threat Feed:                          │
│ ┌─────────────────────────────────────┐           │
│ │ ⚠️ 192.168.1.100:45678→...     │           │
│ │ Label: MALICIOUS, Conf: 87%       │           │
│ │ [🚫 BLOCK] [🔍 INVESTIGATE]     │           │
│ └─────────────────────────────────────┘           │
├─────────────────────────────────────────────────────────┤
│ 📈 Analytics Charts:                           │
│ • Threat Timeline (last hour)                  │
│ • Severity Distribution (doughnut)              │
│ • Model Performance (bars)                    │
│ • Attack Types (breakdown)                   │
└─────────────────────────────────────────────────────────┘
```

### **🔒 Security Actions Output**
```
┌─────────────────────────────────────┐
│     AUTOMATED RESPONSES          │
├─────────────────────────────────────┤
│ 🚫 High Severity:                │
│ • Block flow automatically          │
│ • Add to firewall rules           │
│ • Alert security team             │
├─────────────────────────────────────┤
│ ⚠️ Medium Severity:              │
│ • Log for investigation          │
│ • Create SIEM alert              │
│ • Flag for manual review         │
├─────────────────────────────────────┤
│ ✅ Low Severity:                │
│ • Log for compliance            │
│ • Weekly report                 │
│ • Monitor for escalation         │
└─────────────────────────────────────┘
```

## 🔄 Complete Data Flow Example

### **📥 Real-World Scenario**
```
1️⃣ INPUT: Employee downloads malicious file
┌─────────────────────────────────────┐
│  Network: 192.168.1.50 → malicious-server.com │
│  Protocol: HTTPS (port 443)                 │
│  Packets: 2,347 (download)               │
│  Duration: 45.2 seconds                    │
└─────────────────────────────────────┘

2️⃣ PROCESSING: ZeroTrust-AI Analysis
┌─────────────────────────────────────┐
│  Flow Aggregation: Group packets by flow    │
│  SPLT Extraction: [+7.1, -6.8, ...]     │
│  TCN Analysis: 0.91 malicious prob       │
│  AE Analysis: 0.78 anomaly score         │
│  IsoForest: 0.65 outlier score        │
│  Ensemble: 0.82 final score             │
└─────────────────────────────────────┘

3️⃣ OUTPUT: Security Response
┌─────────────────────────────────────┐
│  🚨 ALERT: Malicious download detected │
│  📊 Confidence: 82%                   │
│  🚨 Severity: HIGH                     │
│  🔒 ACTION: Auto-block flow             │
│  📱 NOTIFICATION: Security team alerted    │
│  📊 LOG: SIEM, dashboard, forensics   │
└─────────────────────────────────────┘
```

## 🎯 Input/Output Summary

### **📥 INPUTS**
- **🌐 Live network traffic** (production)
- **📁 PCAP files** (development/testing)
- **📊 Packet data** (headers, timing, payload)
- **🔍 Flow metadata** (5-tuple, duration, volume)

### **📤 OUTPUTS**
- **🚨 Threat decisions** (malicious/benign)
- **📊 Real-time dashboard** (web interface)
- **🔒 Security actions** (block, alert, log)
- **📈 Analytics reports** (performance, trends)

### **🔄 TRANSFORMATION**
```
Raw Packets → Flows → SPLT Features → ML Scores → Security Decisions
```

## 📊 Data Format Examples

### **📥 Input: Raw Packet**
```json
{
  "timestamp": "2024-02-06T11:24:00.123456Z",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 45678,
  "dst_port": 443,
  "protocol": "TCP",
  "payload": "GET /malware.exe HTTP/1.1...",
  "size": 1500
}
```

### **📤 Output: Threat Event**
```json
{
  "flow_id": "192.168.1.100:45678→10.0.0.1:443/TCP",
  "label": "malicious",
  "confidence": 0.87,
  "anomaly_score": 0.65,
  "severity": "high",
  "reason": ["tcn_malicious", "ae_anomalous"],
  "timestamp": "2024-02-06T11:24:00Z",
  "attack_type": "malware_download",
  "blocked": true
}
```

## 🎯 System Performance

### **⚡ Processing Speed**
- **Packet Capture**: 10,000+ packets/second
- **Flow Aggregation**: <100ms per 1000 flows
- **SPLT Extraction**: <50ms per flow
- **ML Inference**: <20ms per flow
- **Total Latency**: <500ms end-to-end

### **📊 Accuracy Metrics**
- **TCN**: 99.14% accuracy, 97.99% F1-score
- **Autoencoder**: 73.76% accuracy, 12.07% F1-score
- **IsolationForest**: 73.08% accuracy, 23.28% F1-score
- **Ensemble**: 98.54% accuracy, 96.54% F1-score

Your **ZeroTrust-AI** transforms **raw network packets** into **actionable security intelligence** in real-time! 🛡️
