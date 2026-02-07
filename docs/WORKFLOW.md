# ZeroTrust-AI Workflow Documentation

## End-to-End Flow: From Network Traffic to Threat Decision

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│  Network Input  │ →  │   Capture    │ →  │   Feature   │ →  │   ML Models   │
│  (Live/PCAP)    │    │   Layer      │    │   Extractor │    │   Ensemble   │
└─────────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
                                                      ↓                    ↓
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│  Action/Alert   │ ←  │   Decision   │ ←  │   Score     │ ←  │   Individual │
│  (Block/Log)    │    │   Engine     │    │   Fusion    │    │   Models      │
└─────────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
```

---

## Step 1: Network Input

### Input Types
- **Live Traffic**: Real network interface (production)
- **PCAP Files**: Pre-recorded traffic (development/testing)

### What It Is
Raw network packets containing:
- IP headers (source/destination IPs)
- Transport headers (ports, protocol)
- Packet payloads (encrypted, we don't inspect)
- Timing information

### Why We Start Here
- **Universal**: All network security starts with packet capture
- **Complete**: Captures everything needed for analysis
- **Flexible**: Works with both live and historical data

---

## Step 2: Capture & Flow Processing Layer

### What Happens
1. **Packet Collection**: 
   - **NFStream** captures packets from network interface/PCAP
   - **dpkt** reads the same PCAP file for packet-level analysis
2. **Flow Aggregation**: Groups packets by 5-tuple (srcIP, dstIP, srcPort, dstPort, protocol)
3. **Hybrid Processing**:
   - **NFStream**: Provides flow statistics (duration, byte counts, packet counts)
   - **dpkt**: Extracts individual packets for SPLT sequences and TLS metadata

### Why Two Tools?
- **NFStream Issue**: Built-in SPLT analysis didn't work properly
- **dpkt Solution**: Excellent at packet-level extraction
- **Combined Approach**: Use each tool for what it does best

### Output
```
Flow {
  id: "flow_123",
  src_ip: "192.168.1.100",
  dst_ip: "10.0.0.1",
  src_port: 45678,
  dst_port: 443,
  protocol: "TCP",
  packets: [packet1, packet2, ..., packetN],
  duration: 15.3,
  bytes: 15000
}
```

### Why This Step
- **Organization**: Turns chaotic packets into meaningful flows
- **Efficiency**: Reduces data volume while preserving patterns
- **Foundation**: Creates the basic unit for analysis

---

## Step 3: Feature Extractor (SPLT) - Hybrid Approach

### What Happens
For each flow, we extract SPLT (Sequence of Packet Lengths and Times) using a hybrid approach:

#### 3.1 Two-Pass Processing
```
Pass 1: dpkt reads PCAP → Extracts individual packets
Pass 2: NFStream reads PCAP → Groups into flows
Result: Combine packet data with flow statistics
```

#### 3.2 Packet Length Sequence (dpkt)
```
Take first 20 packets from dpkt:
[1500, 1200, 1500, 64, 1500, 800, 1500, 64, ...]

Apply transformations:
1. Take absolute value: [1500, 1200, 1500, 64, 1500, 800, ...]
2. Log transform: [7.31, 7.09, 7.31, 4.16, 7.31, 6.68, ...]
3. Encode direction: [+7.31, -7.09, +7.31, -4.16, +7.31, -6.68, ...]
```

#### 3.3 Inter-Arrival Time Sequence (dpkt)
```
Calculate time between packets using dpkt timestamps:
[0.001, 0.005, 0.002, 0.100, 0.001, ...]

Apply log transform for normalization
```

#### 3.4 Flow Statistics (NFStream)
```
From NFStream flow records:
- Duration: 15.3 seconds
- Total packets: 127
- Total bytes: 85,000
- Protocol: TCP
```

#### 3.5 TLS Metadata (dpkt)
```
Parse TLS handshake packets with dpkt:
- TLS version: "TLS1.3"
- ECH detected: True/False
- Cipher suite: (if available)
```

### Output
```
Complete_Feature_Set {
  # From NFStream (flow statistics)
  flow_id: "192.168.1.100:45678→10.0.0.1:443/TCP",
  duration: 15.3,
  total_packets: 127,
  total_bytes: 85000,
  
  # From dpkt (SPLT sequences)
  splt_lengths: [+7.31, -7.09, +7.31, -4.16, +7.31, -6.68, ...],  # 20 values
  splt_iats: [0.001, 0.005, 0.002, 0.100, 0.001, ...],           # 20 values
  
  # From dpkt (TLS metadata)
  tls_version: "TLS1.3",
  ech_detected: true,
  tls_cipher: "TLS_AES_256_GCM_SHA384"
}
```

### Why This Hybrid Approach
- **NFStream Failed**: Built-in SPLT analysis didn't work properly
- **dpkt Succeeded**: Excellent packet-level extraction
- **Best of Both**: NFStream for flow stats + dpkt for packet details
- **Complete Picture**: Both behavioral sequences AND flow context

### Why SPLT Features
- **Privacy-Preserving**: No payload inspection needed
- **Pattern-Rich**: Captures behavioral signatures
- **Encryption-Resistant**: Works on encrypted traffic
- **Proven**: Research shows effectiveness for malware detection

---

## Step 4: Individual ML Models

### 4.1 TCN (Temporal Convolutional Network)

#### Input
```
Tensor: (1, 20, 2)  # [batch, sequence_length, features]
[[+7.31, 0.001], [-7.09, 0.005], [+7.31, 0.002], ...]
```

#### What TCN Does
1. **Convolution Layers**: Scans for local patterns
   - Detects "small packet followed by large packet" patterns
   - Finds "regular timing intervals" sequences
2. **Temporal Modeling**: Understands order and timing
3. **Classification**: Outputs probability of malicious

#### Output
```
TCN_Result {
  probability_benign: 0.15,
  probability_malicious: 0.85,
  confidence: 0.85
}
```

#### Why TCN
- **Temporal Expert**: Specializes in sequence patterns
- **Fast**: Efficient inference (<50ms)
- **Accurate**: 98.58% accuracy on our data
- **Learned Patterns**: Detects complex temporal relationships

---

### 4.2 Autoencoder

#### Input
```
Vector: (40,)  # Flattened SPLT features
[+7.31, -7.09, +7.31, -4.16, ..., 0.001, 0.005, 0.002, 0.100, ...]
```

#### What Autoencoder Does
1. **Encoder**: Compresses input to 16 dimensions
2. **Decoder**: Tries to reconstruct original input
3. **Error Calculation**: Measures reconstruction quality

#### Training (Offline)
- **Trained on**: Benign traffic only
- **Learns**: What "normal" patterns look like
- **Result**: Can reconstruct normal traffic well, fails on abnormal

#### Inference
```
Reconstruction_Error = 0.73
Threshold = 0.45
Anomaly_Score = min(Reconstruction_Error / Threshold, 1.0) = 1.0
```

#### Output
```
AE_Result {
  reconstruction_error: 0.73,
  anomaly_score: 1.0,
  is_anomaly: true
}
```

#### Why Autoencoder
- **Unsupervised**: No labels needed for training
- **Novelty Detection**: Catches new/unknown threats
- **Complementary**: Different bias than TCN
- **Threshold-Based**: Clear decision boundary

---

### 4.3 Isolation Forest

#### Input
```
Vector: (40,)  # Same flattened SPLT features
[+7.31, -7.09, +7.31, -4.16, ..., 0.001, 0.005, 0.002, 0.100, ...]
```

#### What Isolation Forest Does
1. **Random Trees**: Builds many decision trees
2. **Isolation**: Measures how easily a point can be isolated
3. **Scoring**: Anomalies are easier to isolate → shorter paths

#### Inference
```
Anomaly_Score = 0.62  # Higher = more anomalous
Prediction = -1        # -1 = anomaly, 1 = normal
```

#### Output
```
IsoForest_Result {
  anomaly_score: 0.62,
  prediction: -1,  # anomaly
  is_anomaly: true
}
```

#### Why Isolation Forest
- **Efficient**: Fast training and inference
- **Unsupervised**: No labels required
- **Different Approach**: Tree-based vs neural networks
- **Robust**: Handles different types of anomalies

---

## Step 5: Score Fusion

### What We Combine
```
TCN_Confidence: 0.85
AE_Anomaly_Score: 1.0
IsoForest_Score: 0.62
```

### Fusion Method
```python
# Weighted combination
ensemble_score = (
    0.50 * tcn_confidence +      # TCN gets 50% weight (most reliable)
    0.25 * ae_anomaly_score +    # AE gets 25% weight
    0.25 * isoforest_score       # IsoForest gets 25% weight
)

ensemble_score = 0.50 * 0.85 + 0.25 * 1.0 + 0.25 * 0.62
ensemble_score = 0.425 + 0.25 + 0.155 = 0.83
```

### Why Ensemble
- **Robustness**: Reduces individual model errors
- **Complementary**: Each model catches different things
- **Balanced**: Combines supervised and unsupervised views
- **Tunable**: Weights can be adjusted based on performance

---

## Step 6: Decision Engine

### Decision Logic
```python
if ensemble_score >= 0.60:
    label = "malicious"
else:
    label = "benign"

# Calculate severity
if ensemble_score >= 0.80:
    severity = "critical"
elif ensemble_score >= 0.70:
    severity = "high"
elif ensemble_score >= 0.60:
    severity = "medium"
else:
    severity = "low"
```

### Output
```
Decision {
  flow_id: "flow_123",
  label: "malicious",
  confidence: 0.83,
  severity: "high",
  reasons: ["tcn_malicious", "ae_anomalous", "isoforest_anomalous"],
  timestamp: "2024-02-03T12:34:56Z"
}
```

### Why This Logic
- **Threshold-Based**: Clear, explainable decisions
- **Severity Levels**: Enables graduated responses
- **Reason Tracking**: Auditable decision process
- **Configurable**: Thresholds can be tuned

---

## Step 7: Action/Alert

### Possible Actions
Based on severity and confidence:

#### Low Severity (0.60-0.69)
- **Action**: Log and monitor
- **Reason**: Suspicious but not critical

#### Medium Severity (0.70-0.79)
- **Action**: Alert security team
- **Reason**: Likely threat, needs investigation

#### High Severity (0.80-0.89)
- **Action**: Isolate endpoint, alert immediately
- **Reason**: Strong evidence of malicious activity

#### Critical Severity (0.90-1.00)
- **Action**: Block IP, isolate network segment, emergency alert
- **Reason**: Confirmed malicious activity

### Response System
```
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐
│  Decision       │ →  │   Action     │ →  │   Response   │
│  (Malicious)    │    │   Engine     │    │   System     │
└─────────────────┘    └──────────────┘    └─────────────┘
```

### Why Automated Response
- **Speed**: Faster than human response
- **Consistency**: Same response every time
- **Scalability**: Can handle many threats simultaneously
- **Audit Trail**: All actions logged

---

## Complete Example Walkthrough

### Input
```
Network flow from 192.168.1.100 to 10.0.0.1:443
20 packets with regular timing (every 60 seconds)
Consistent packet sizes (64 bytes each)
```

### Step-by-Step Processing

1. **Capture**: NFStream groups packets into flow
2. **SPLT Extraction**: 
   - Lengths: [+4.16, +4.16, +4.16, ...] (all 64-byte packets)
   - IATs: [4.09, 4.09, 4.09, ...] (60-second intervals)
3. **TCN**: Recognizes regular pattern → 0.92 malicious confidence
4. **Autoencoder**: Poor reconstruction (unusual regularity) → 0.95 anomaly score
5. **Isolation Forest**: Easy to isolate (very different) → 0.88 anomaly score
6. **Fusion**: 0.50×0.92 + 0.25×0.95 + 0.25×0.88 = 0.92
7. **Decision**: Malicious (0.92 > 0.60), High severity
8. **Action**: Isolate endpoint, alert security team

### Why This Works
- **Pattern Recognition**: Regular timing = botnet beacon
- **Multiple Confirmations**: All models agree
- **Appropriate Response**: High confidence justifies strong action

---

## Model Roles Summary

| Model | Primary Role | Strength | When It Excels |
|-------|--------------|----------|----------------|
| **TCN** | Pattern Recognition | Temporal sequences | Known attack patterns |
| **Autoencoder** | Novelty Detection | Unseen threats | Zero-day attacks |
| **Isolation Forest** | Outlier Detection | Statistical anomalies | Unusual behaviors |
| **Ensemble** | Decision Fusion | Robustness | Combined scenarios |

Each model contributes unique insights, and their combination provides comprehensive threat detection while minimizing false positives.
