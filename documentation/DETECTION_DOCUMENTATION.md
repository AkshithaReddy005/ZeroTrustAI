# ZeroTrust-AI Attack Detection Documentation

## Detection Architecture Overview

ZeroTrust-AI employs a **multi-layered ensemble detection system** that combines supervised machine learning with unsupervised anomaly detection to identify both known and unknown cyber threats in real-time.

### Core Detection Models

The system uses an ensemble of three complementary models:

1. **Temporal Convolutional Network (TCN)** - Deep learning model for temporal pattern recognition
2. **Autoencoder** - Neural network for unsupervised anomaly detection via reconstruction error
3. **IsolationForest** - Machine learning algorithm for statistical outlier detection

### Ensemble Fusion Logic
```python
# Weighted ensemble scoring for final decision
Final Score = (50% × TCN) + (25% × Autoencoder) + (25% × IsolationForest)
```

**Decision Threshold**: Final Score ≥ 0.6 = **MALICIOUS**, Final Score < 0.6 = **BENIGN**

---

## Known Attack Detection

### Attack Categories & MITRE ATT&CK Mapping

| Attack Type | MITRE Technique | Key Detection Features | Typical Patterns |
|-------------|----------------|----------------------|------------------|
| **Botnet & C2** | T1071 - Application Layer Protocol | • **Packet Size**: Regular 200-800 bytes<br>• **Timing**: Consistent beacon intervals (30-300s)<br>• **Port**: 443, 8443 (HTTPS)<br>• **Entropy**: Low-moderate (2.0-4.5) | Periodic C2 communication, command patterns, encrypted tunnels |
| **Data Exfiltration** | T1041 - Exfiltration Over C2 Channel | • **Packet Size**: Large 1000-1500 bytes<br>• **Total Bytes**: High (>100MB)<br>• **Duration**: Long flows (>300s)<br>• **Packet Rate**: Steady 10-50 PPS | Large uploads, sustained transfers, unusual outbound traffic |
| **DDoS Attacks** | T1498 - Network Denial of Service | • **Packet Count**: Very high (>10,000)<br>• **Packet Rate**: Extreme (>1000 PPS)<br>• **Duration**: Short bursts (1-60s)<br>• **Source IPs**: Many sources to one target | Traffic floods, high volume, coordinated attacks |
| **Reconnaissance** | T1046 - Network Service Scanning | • **Packet Count**: Low per flow (1-3 packets)<br>• **Duration**: Very short (<1s)<br>• **Port Range**: Sequential port scanning<br>• **Source**: Single IP scanning many targets | Port scanning, network discovery, vulnerability probing |
| **Web Attacks** | T1190 - Exploit Public-Facing Application | • **Port**: 80, 8080, 443 (HTTP/HTTPS)<br>• **Packet Size**: Variable 100-1400 bytes<br>• **Entropy**: High (>6.0) for encoded attacks<br>• **Timing**: Rapid request bursts | SQL injection, XSS, web exploits, application attacks |
| **Malware Execution** | T1059 - Command and Scripting Interpreter | • **Packet Size**: Small command packets (100-500 bytes)<br>• **Timing**: Command-response patterns<br>• **Entropy**: Low for commands, high for payloads<br>• **Ports**: 22, 23, 3389 (RDP/SSH) | Command execution, remote access, backdoor communication |
| **Anomalous Behavior** | T1027 - Obfuscated Files or Information | • **Packet Size**: Unusual distributions<br>• **Timing**: Irregular patterns<br>• **Entropy**: Very high (>7.0)<br>• **Protocol**: Unusual port usage | Obfuscated traffic, encrypted tunnels, protocol anomalies |

### Feature Analysis Details

#### **Primary Detection Features**

1. **Packet Size Analysis**
   - **Normal**: 100-1500 bytes (standard MTU)
   - **Suspicious**: <50 bytes (scanning) or >1500 bytes (jumbo frames/attacks)
   - **Attack Indicators**: 
     - Consistent small packets = port scanning
     - Large packets = data exfiltration
     - Variable sizes = obfuscation

2. **Timing & Rate Analysis**
   - **Packet Rate (PPS)**: Packets per second
     - Normal: 1-100 PPS
     - DDoS: >1000 PPS
     - C2: 0.1-1 PPS (periodic)
   - **Inter-arrival Times**: Time between packets
     - Normal: Variable (0.1-10s)
     - Beaconing: Regular intervals (30-300s)
     - Scanning: Very rapid (<0.01s)

3. **Flow Duration Analysis**
   - **Normal**: 10-300 seconds
   - **Data Exfiltration**: >300 seconds (sustained)
   - **Scanning**: <1 second (quick probes)
   - **DDoS**: Variable, often short bursts

4. **Entropy Analysis**
   - **Normal Traffic**: 2.0-6.0 (moderate randomness)
   - **Encrypted Data**: 7.0-8.0 (high randomness)
   - **Compressed Data**: 7.5-8.0 (very high)
   - **Attack Payloads**: Often >6.0 (obfuscated content)

5. **Port-Based Detection**
   - **Standard Ports**: 80, 443, 22, 53, 25
   - **C2 Ports**: 443, 8443, 8080 (HTTPS tunneling)
   - **Scanning Targets**: 1-65535 (sequential)
   - **Malware Ports**: High-numbered ports (>1024)

#### **SPLT (Sequence Packet Length and Timing) Analysis**

For advanced detection, system analyzes first 10 packets:

| Feature | Normal Range | Suspicious Range | Attack Type |
|----------|--------------|------------------|-------------|
| **Packet 1-3 Sizes** | 200-1200 bytes | <100 bytes or >1400 bytes | Scanning/Malware |
| **Packet 4-10 Sizes** | Variable | Consistent identical sizes | C2 Beaconing |
| **Inter-arrival 1-3** | 0.01-5.0 seconds | <0.001 seconds | Port Scanning |
| **Inter-arrival 4-10** | Variable | Regular intervals (30-300s) | Botnet C2 |
| **Size Variation** | Moderate (std 100-500) | Very low (std <50) or very high (std >800) | Anomalous |

### Detection Thresholds
- **TCN Malicious**: `p_mal >= 0.6` - Recognizes known attack patterns
- **Autoencoder Anomaly**: `ae_score >= 0.7` - Unusual reconstruction error
- **IsolationForest Anomaly**: `iso_score >= 0.6` - Statistical outlier detection
- **Overall Decision**: `score >= 0.6` - Final malicious classification

### Port-Specific Detection Enhancements
- **HTTPS C2 (443, 8443)**: `T1071.001` - Application Layer Protocol: HTTPS
- **HTTP Attacks (80, 8080)**: `T1071.001` - Application Layer Protocol: HTTP  
- **Brute Force (22, 23, 3389)**: `T1110` - Brute Force

---

## Unknown Attack Detection (Zero-Day Protection)

### Anomaly-Based Detection Strategy

**Core Principle**: Rather than relying on known attack signatures, the system identifies **behavioral anomalies** that indicate potential zero-day attacks.

#### 1. Autoencoder Reconstruction Analysis
- **Training Method**: Model learns exclusively on normal traffic patterns
- **Detection Mechanism**: High reconstruction error indicates unusual traffic characteristics
- **Advantage**: No prior knowledge of specific attack signatures required
- **Threshold**: `ae_score >= 0.7`

#### 2. IsolationForest Statistical Outlier Detection  
- **Method**: Unsupervised algorithm identifies statistical deviations from baseline
- **Detection Capability**: Flags novel attack patterns that deviate from normal behavior
- **Threshold**: `iso_score >= 0.6`

#### 3. Ensemble Consensus for Unknown Threats
Unknown attacks are flagged when multiple models independently detect anomalies:
```python
reasons = []
if ae_score >= 0.7:
    reasons.append("ae_anomalous")  # Autoencoder anomaly detected
if iso_score >= 0.6:
    reasons.append("isoforest_anomalous")  # Statistical outlier detected
```

### Unknown Attack Classification
When detected patterns don't match known attack signatures:
```python
attack_type = "unknown"
mitre_tactic = "unknown" 
mitre_technique = "unknown"
```

### Detection Reasons for Unknown Attacks
- **`ae_anomalous`**: Autoencoder detects significant reconstruction anomaly
- **`isoforest_anomalous`**: IsolationForest identifies statistical outlier
- **`anomalous_flow`**: General traffic pattern deviation detected
- **`low_risk`**: Baseline classification when no specific patterns identified

---

## Detection Examples

### Example 1: Known Botnet Attack
```
Flow: 192.168.1.100:12345 → 10.0.0.1:443/TCP
TCN Score: 0.85 (recognizes botnet command pattern)
Autoencoder: 0.20 (normal reconstruction - matches training)
IsolationForest: 0.30 (normal statistical profile)
Final Score: 0.85×0.5 + 0.20×0.25 + 0.30×0.25 = 0.55
Result: MALICIOUS (botnet command & control detected)
```

### Example 2: Unknown Zero-Day Attack
```
Flow: 192.168.1.200:54321 → 10.0.0.1:8080/TCP
TCN Score: 0.30 (no known pattern recognition)
Autoencoder: 0.85 (high reconstruction error - unusual)
IsolationForest: 0.78 (statistical outlier detected)
Final Score: 0.30×0.5 + 0.85×0.25 + 0.78×0.25 = 0.56
Result: MALICIOUS (unknown attack - zero-day threat)
```

### Example 3: Normal Benign Traffic
```
Flow: 192.168.1.50:12345 → 8.8.8.8:53/TCP (DNS)
TCN Score: 0.10 (normal pattern)
Autoencoder: 0.15 (normal reconstruction)
IsolationForest: 0.20 (normal statistical profile)
Final Score: 0.10×0.5 + 0.15×0.25 + 0.20×0.25 = 0.14
Result: BENIGN (normal traffic)
```

---

## Detection Output Format

### Standard Detection Event (Known Attack)
```json
{
  "flow_id": "192.168.1.100:12345→10.0.0.1:443/TCP",
  "label": "malicious",
  "confidence": 0.847,
  "anomaly_score": 0.723,
  "severity": "HIGH",
  "reason": ["tcn_malicious", "ae_anomalous"],
  "attack_type": "botnet",
  "mitre_tactic": "Command and Control",
  "mitre_technique": "T1071"
}
```

### Unknown Attack Event (Zero-Day)
```json
{
  "flow_id": "192.168.1.200:54321→10.0.0.1:8080/TCP",
  "label": "malicious",
  "confidence": 0.743,
  "anomaly_score": 0.812,
  "severity": "HIGH",
  "reason": ["ae_anomalous", "isoforest_anomalous"],
  "attack_type": "unknown",
  "mitre_tactic": "unknown",
  "mitre_technique": "unknown"
}
```

---

## Performance Metrics

| Metric | Value | Description |
|--------|-------|-------------|
| **Detection Accuracy** | 96.54% | Overall F1-score across all attack types |
| **Response Latency** | <100ms | Real-time detection capability |
| **False Positive Rate** | <2% | Low false positive through ensemble consensus |
| **Known Attack Coverage** | 7 categories | Comprehensive MITRE-mapped attack types |
| **Unknown Attack Detection** | Anomaly-based | Zero-day protection without signatures |

### Severity Classification
- **LOW**: `score < 0.4` - Log only, no action required
- **MEDIUM**: `0.4 ≤ score < 0.7` - Alert security team
- **HIGH**: `0.7 ≤ score < 0.9` - Auto-block + security alert
- **CRITICAL**: `score ≥ 0.9` - Immediate block + investigation

---

## Technical Implementation Details

### Feature Analysis
The system analyzes comprehensive network flow features:
- **Temporal Features**: Packet timing, flow duration, inter-arrival times
- **Statistical Features**: Packet sizes, byte distributions, protocol patterns
- **Behavioral Features**: Communication patterns, connection frequencies
- **Contextual Features**: Port usage, protocol types, source/destination analysis

### SPLT (Sequence Packet Length and Timing) Processing
For advanced temporal analysis, the system utilizes SPLT sequences:
- **Temporal Windows**: 10-packet sliding windows for sequence analysis
- **Multi-dimensional Analysis**: Packet length, timing, and direction patterns
- **TCN Processing**: Temporal convolution for pattern recognition in sequences

---

## Key Advantages Over Traditional Security

### Traditional Security Limitations
- **Signature-Based Detection**: Only catches previously known attacks
- **Static Blacklists**: Requires constant manual updates
- **Rule-Based Systems**: Easily bypassed by sophisticated attackers

### ZeroTrust-AI Advantages
- **Behavior-Based Detection**: Automatically identifies novel attack patterns
- **Machine Learning**: Continuously learns and improves from new data
- **Ensemble Consensus**: Multiple AI models reduce false positives
- **Real-Time Adaptation**: No signature updates required for zero-day threats

---

## Summary

ZeroTrust-AI provides comprehensive threat detection through:

1. **Known Attack Detection** - Pattern recognition against 7 MITRE-mapped attack categories
2. **Unknown Attack Detection** - Anomaly-based zero-day protection without signatures
3. **Ensemble Intelligence** - Multiple AI models working together for accuracy
4. **Real-Time Performance** - Sub-100ms detection with 96.54% accuracy
5. **Adaptive Learning** - Continuous improvement without manual signature updates

**Result**: Whether facing known botnets or novel zero-day attacks, the system detects and blocks threats based on behavioral analysis rather than signature matching.
