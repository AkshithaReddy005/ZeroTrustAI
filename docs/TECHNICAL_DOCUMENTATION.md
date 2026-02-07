# ZeroTrust-AI Technical Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Data Pipeline](#data-pipeline)
4. [Machine Learning Models](#machine-learning-models)
5. [Feature Engineering](#feature-engineering)
6. [Database Integration](#database-integration)
7. [API Documentation](#api-documentation)
8. [Deployment](#deployment)
9. [Performance Metrics](#performance-metrics)
10. [Security Considerations](#security-considerations)
11. [Troubleshooting](#troubleshooting)

---

## System Overview

ZeroTrust-AI is a real-time network threat detection system that operates on encrypted traffic without packet inspection. The system implements Zero Trust principles by treating every network flow as potentially malicious and evaluating it based on behavioral patterns.

### Key Design Principles
- **Privacy-Preserving**: No payload inspection, only metadata analysis
- **Real-Time**: Sub-500ms detection latency
- **Behavioral Analysis**: Detects patterns rather than signatures
- **Multi-Model Ensemble**: Reduces false positives through consensus
- **Persistent Memory**: Redis (real-time) + InfluxDB (historical)
- **Scalable**: Microservices architecture with containerization

---

## Architecture

### High-Level Architecture
```
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐
│  Network Traffic│ →  │   Capture    │ →  │   Feature   │
│  (Live/PCAP)    │    │   Layer      │    │   Extractor │
└─────────────────┘    └──────────────┘    └─────────────┘
                                                      ↓
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐
│  Response      │ ←  │   Decision   │ ←  │   ML Models │
│  System        │    │   Engine     │    │   Ensemble  │
└─────────────────┘    └──────────────┘    └─────────────┘
                              ↓
                    ┌─────────────────────┐
                    │   Memory Layer      │
                    │  Redis + InfluxDB   │
                    └─────────────────────┘
```

### Microservices Components

#### 1. API Gateway (`services/api-gateway/`)
- **Technology**: FastAPI
- **Purpose**: External API interface, authentication, rate limiting
- **Endpoints**: `/detect`, `/health`, `/metrics`

#### 2. Detector Service (`services/detector/`)
- **Technology**: FastAPI + PyTorch + Scikit-learn
- **Purpose**: Model inference, score fusion, threat classification
- **Models**: TCN, Autoencoder, IsolationForest

#### 3. PCAP Replay Service (`services/pcap-replay/`)
- **Technology**: Python + NFStream
- **Purpose**: Replay PCAP files for testing/demonstration
- **Note**: Replaced by live capture in production

#### 4. Collector Service (`services/collector/`)
- **Technology**: Python
- **Purpose**: Aggregate metrics, forward to time-series DB

#### 5. Data Stores
- **InfluxDB**: Time-series metrics (latency, throughput, errors)
- **Redis**: Risk scores with TTL-based decay, caching

---

## Data Pipeline

### Data Sources

#### 1. CIC-IDS2018 Dataset
- **Size**: ~16GB of PCAP files
- **Attacks**: Botnet, DoS, DDoS, Web attacks, infiltration
- **Format**: PCAP + CSV labels
- **Usage**: Training and evaluation

#### 2. CTU-13 Dataset
- **Size**: 13 scenarios of botnet traffic
- **Labels**: Detailed flow-level annotations
- **Usage**: Ground truth for evaluation

### Data Processing Pipeline

#### 1. PCAP Processing
```python
# Extract SPLT features from PCAP
nfstream = NFStream(source=pcap_file)
for flow in nfstream:
    splt_features = extract_splt_sequence(flow)
    save_to_csv(splt_features)
```

#### 2. Feature Extraction
```python
def extract_splt_sequence(flow):
    # Get first 20 packets
    packets = flow.packets[:20]
    
    # Extract packet lengths with direction
    lengths = [math.log(abs(p.length)) * (1 if p.direction == 'outbound' else -1) 
               for p in packets]
    
    # Extract inter-arrival times
    iats = [math.log(packets[i+1].time - packets[i].time) 
            for i in range(len(packets)-1)]
    
    return {
        'lengths': lengths,
        'iats': iats,
        'flow_id': flow.id,
        'src_ip': flow.src_ip,
        'dst_ip': flow.dst_ip
    }
```

#### 3. Data Storage
- **Raw PCAPs**: `data/raw/`
- **Processed Features**: `data/processed/splt_features.csv`
- **Labeled Data**: `data/processed/splt_features_labeled.csv`

---

## Machine Learning Models

### 1. Temporal Convolutional Network (TCN)

#### Architecture
```python
class TCN(nn.Module):
    def __init__(self, input_size=2, seq_len=20, hidden_size=64):
        super().__init__()
        self.conv1 = nn.Conv1d(input_size, hidden_size, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(hidden_size, hidden_size, kernel_size=3, padding=1)
        self.conv3 = nn.Conv1d(hidden_size, hidden_size, kernel_size=3, padding=1)
        self.pool = nn.AdaptiveAvgPool1d(1)
        self.fc = nn.Linear(hidden_size, 2)  # Binary classification
        
    def forward(self, x):
        # x shape: (batch, seq_len, input_size)
        x = x.transpose(1, 2)  # (batch, input_size, seq_len)
        x = F.relu(self.conv1(x))
        x = F.relu(self.conv2(x))
        x = F.relu(self.conv3(x))
        x = self.pool(x).squeeze(-1)
        return self.fc(x)
```

#### Training Details
- **Input**: 2×20 tensor (packet lengths, inter-arrival times)
- **Output**: Binary classification (benign/malicious)
- **Loss**: Cross-entropy loss
- **Optimizer**: Adam (lr=1e-3)
- **Batch Size**: 64
- **Epochs**: 5
- **Performance**: 98.58% accuracy, 96.63% F1-score

### 2. Autoencoder

#### Architecture
```python
class Autoencoder(nn.Module):
    def __init__(self, input_size=40):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16)
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_size)
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
```

#### Training Details
- **Input**: Flattened SPLT sequence (40 features)
- **Training Data**: Benign-only flows
- **Loss**: MSE reconstruction loss
- **Threshold**: 95th percentile of training reconstruction errors
- **Performance**: 74.94% accuracy, 8.57% F1-score (needs tuning)

### 3. Isolation Forest

#### Configuration
```python
isoforest = IsolationForest(
    contamination=0.05,  # Expected anomaly rate
    n_estimators=100,
    random_state=42
)
```

#### Training Details
- **Input**: Scaled SPLT features
- **Preprocessing**: StandardScaler
- **Output**: Anomaly score (-1 for anomalies, 1 for normal)
- **Performance**: 78.24% accuracy, 0% recall (needs improvement)

### 4. Ensemble Fusion

#### Score Combination
```python
def ensemble_score(tcn_prob, ae_score, iso_score, weights=(0.5, 0.25, 0.25)):
    """
    Combine scores from multiple models
    """
    score = (
        weights[0] * tcn_prob +
        weights[1] * ae_score +
        weights[2] * iso_score
    )
    return np.clip(score, 0.0, 1.0)

def classify_ensemble(score, threshold=0.6):
    return "malicious" if score >= threshold else "benign"
```

#### Performance
- **Accuracy**: 83.84%
- **Precision**: 99.89%
- **Recall**: 25.09%
- **F1-score**: 40.11%

---

## Feature Engineering

### SPLT (Sequence of Packet Lengths and Times)

#### Feature Construction
1. **Packet Lengths**: First 20 packets per flow
   - Log-transformed to handle heavy-tailed distribution
   - Direction encoded (+1 for outbound, -1 for inbound)

2. **Inter-Arrival Times**: Time between consecutive packets
   - Log-transformed for normalization
   - Microsecond precision for fine-grained patterns

#### Preprocessing
```python
def preprocess_splt(splt_data):
    # Log transformation
    lengths = np.log1p(np.abs(splt_data['lengths']))
    iats = np.log1p(splt_data['iats'])
    
    # Direction encoding
    directions = np.sign(splt_data['lengths'])
    lengths = lengths * directions
    
    # Padding/truncation to fixed length
    lengths = pad_or_truncate(lengths, 20)
    iats = pad_or_truncate(iats, 20)
    
    return np.stack([lengths, iats], axis=1)
```

### Feature Importance
- **Timing Patterns**: Regular intervals indicate C2 communication
- **Size Patterns**: Consistent packet sizes suggest automated behavior
- **Direction**: Asymmetric traffic may indicate data exfiltration

---

## Database Integration

ZeroTrust-AI implements a dual-database architecture for optimal performance and analytics:

### Redis: Real-Time State Management

#### Purpose
- **Risk Decay**: Automatic expiration of threat indicators
- **Active Monitoring**: Current risky IPs and their scores
- **Session Management**: WebSocket connection tracking
- **Message Queuing**: Real-time threat broadcasting

#### Data Schema
```
Key: risk:<src_ip> or risk:<flow_id>
Type: Hash
Fields:
  - flow_id: Unique flow identifier
  - score: Ensemble risk score (0.0-1.0)
  - severity: LOW/MEDIUM/HIGH/CRITICAL
  - reasons: Detection reasons (comma-separated)
  - ts: Unix timestamp
TTL: 1800 seconds (30 minutes, configurable)
```

#### Usage Examples
```python
# Store risky IP with TTL
redis_client.hset(f"risk:{src_ip}", mapping={
    "score": "0.87",
    "severity": "HIGH",
    "reasons": "mlp_malicious,anomalous_flow"
})
redis_client.expire(f"risk:{src_ip}", 1800)

# Get all active risks
keys = redis_client.keys("risk:*")
for key in keys:
    risk_data = redis_client.hgetall(key)
    # Display in real-time dashboard
```

### InfluxDB: Historical Analytics

#### Purpose
- **Time-Series Logging**: Every detection event
- **Trend Analysis**: Threat patterns over time
- **Compliance**: Audit trails and reporting
- **Performance Metrics**: Model accuracy tracking

#### Data Schema
```
Measurement: threat_events
Tags (indexed):
  - label: benign/malicious
  - severity: LOW/MEDIUM/HIGH/CRITICAL
  - attack_type: botnet/data_exfiltration/unknown
  - mitre_tactic: TA0001/TA0002/unknown
  - mitre_technique: T1071/T1041/unknown

Fields (values):
  - score: float (ensemble confidence)
  - anomaly_score: float (anomaly detection)
  - confidence: float (overall confidence)
  - src_ip: string (source IP)
  - dst_ip: string (destination IP)

Timestamp: RFC3339 UTC
```

#### Query Examples
```flux
// Threats over last 24 hours
from(bucket: "threat_events")
  |> range(start: -24h)
  |> filter(fn: (r) => r._measurement == "threat_events" and r.label == "malicious")
  |> aggregateWindow(every: 5m, fn: count, createEmpty: false)

// Top attack types this week
from(bucket: "threat_events")
  |> range(start: -7d)
  |> filter(fn: (r) => r.attack_type != "unknown")
  |> group(columns: ["attack_type"])
  |> count()
  |> sort(desc: true, column: "_value")
```

### Configuration

#### Environment Variables
```bash
# Redis Configuration
REDIS_URL=redis://localhost:6379/0
REDIS_TTL_SECONDS=1800

# InfluxDB Configuration
INFLUX_URL=http://localhost:8086
INFLUX_TOKEN=your-token-here
INFLUX_ORG=zerotrust
INFLUX_BUCKET=threat_events
```

#### Dependencies
```bash
pip install redis influxdb-client
```

### Best Practices

#### Redis
- Use appropriate TTL values (30min-2hours for risk decay)
- Monitor memory usage with `redis-cli info memory`
- Use connection pooling for high-throughput scenarios

#### InfluxDB
- Use tags for frequently filtered fields
- Use fields for numeric values
- Implement retention policies for long-term storage
- Batch writes for better performance

---

## API Documentation

### Detection Endpoint

#### POST `/detect`
**Request Body**:
```json
{
  "flow_id": "flow_123",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 45678,
  "dst_port": 443,
  "protocol": "TCP",
  "splt_sequences": {
    "lengths": [7.31, -7.09, 7.31, -4.16, ...],
    "iats": [0.001, 0.005, 0.002, 0.100, ...]
  }
}
```

**Response**:
```json
{
  "flow_id": "flow_123",
  "label": "malicious",
  "confidence": 0.85,
  "anomaly_score": 0.72,
  "severity": "high",
  "reason": ["tcn_malicious", "ae_anomalous"],
  "timestamp": "2024-02-03T12:34:56Z"
}
```

### Health Check

#### GET `/health`
**Response**:
```json
{
  "status": "healthy",
  "models_loaded": true,
  "version": "1.0.0",
  "uptime": 3600
}
```

---

## Deployment

### Docker Configuration

#### docker-compose.yml
```yaml
version: '3.8'
services:
  detector:
    build: ./services/detector
    mem_limit: 4g
    volumes:
      - ./models:/app/models:ro
      - ./data:/app/data:ro
    environment:
      - MODEL_PATH=/app/models
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
      - influxdb

  redis:
    image: redis:7-alpine
    mem_limit: 2g
    volumes:
      - redis_data:/data

  influxdb:
    image: influxdb:2.7
    mem_limit: 3g
    volumes:
      - influxdb_data:/var/lib/influxdb2
    environment:
      - INFLUXDB_DB=zerotrust
```

### Environment Variables
```bash
# Model Configuration
MODEL_PATH=/app/models
TCN_MODEL_PATH=${MODEL_PATH}/tcn_classifier.pth
AE_MODEL_PATH=${MODEL_PATH}/autoencoder.pth
AE_THRESHOLD_PATH=${MODEL_PATH}/ae_threshold.txt

# Database Configuration
REDIS_URL=redis://redis:6379
INFLUXDB_URL=http://influxdb:8086
INFLUXDB_DB=zerotrust

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
LOG_LEVEL=INFO
```

### Production Deployment Steps

1. **Build Images**:
```bash
docker-compose build
```

2. **Start Services**:
```bash
docker-compose up -d
```

3. **Verify Health**:
```bash
curl http://localhost:8000/health
```

4. **Monitor Logs**:
```bash
docker-compose logs -f detector
```

---

## Performance Metrics

### Model Performance

| Model | Accuracy | Precision | Recall | F1-Score | Latency |
|-------|----------|-----------|--------|----------|---------|
| TCN | 98.58% | 98.80% | 94.55% | 96.63% | 45ms |
| Autoencoder | 74.94% | 20.08% | 5.45% | 8.57% | 12ms |
| IsolationForest | 78.24% | 0.00% | 0.00% | 0.00% | 8ms |
| Ensemble | 83.84% | 99.89% | 25.09% | 40.11% | 65ms |

### System Performance

- **Detection Latency**: <500ms (target: 65ms achieved)
- **Throughput**: 10,000 flows/second
- **Memory Usage**: <4GB per container
- **CPU Usage**: <50% per container

### Monitoring Metrics

#### InfluxDB Metrics
- Detection latency histogram
- Model confidence distribution
- False positive rate
- System resource usage

#### Redis Metrics
- Risk score distribution
- TTL expiration rate
- Cache hit ratio

---

## Security Considerations

### Data Privacy
- **No Payload Inspection**: Only metadata analysis
- **Local Processing**: Data never leaves the network
- **Configurable Retention**: TTL-based data expiration

### Model Security
- **Adversarial Robustness**: Ensemble reduces single-point failures
- **Model Versioning**: Track model performance over time
- **Input Validation**: Sanitize all inputs before processing

### Network Security
- **TLS Encryption**: All inter-service communication encrypted
- **Access Control**: JWT-based authentication
- **Rate Limiting**: Prevent API abuse

---

## Troubleshooting

### Common Issues

#### 1. Model Loading Errors
**Symptoms**: Service fails to start, model loading errors
**Solutions**:
- Verify model files exist in `/app/models`
- Check file permissions
- Ensure correct model versions

#### 2. High Memory Usage
**Symptoms**: Container OOM kills
**Solutions**:
- Reduce batch size
- Implement model quantization
- Add memory monitoring

#### 3. Poor Detection Performance
**Symptoms**: High false positive/negative rates
**Solutions**:
- Retrain with recent data
- Adjust ensemble weights
- Tune decision thresholds

#### 4. Network Connectivity Issues
**Symptoms**: Services can't communicate
**Solutions**:
- Check Docker network configuration
- Verify service discovery
- Test DNS resolution

### Debug Commands

#### Check Service Health
```bash
curl http://localhost:8000/health
```

#### Monitor Resource Usage
```bash
docker stats
```

#### View Logs
```bash
docker-compose logs -f detector
```

#### Test Detection
```bash
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d @test_flow.json
```

---

## Future Enhancements

### Model Improvements
- Transformer-based sequence models
- Online learning capabilities
- Federated learning integration

### System Enhancements
- GPU acceleration for inference
- Distributed processing
- Advanced threat intelligence feeds

### Operational Improvements
- Automated model retraining
- A/B testing framework
- Advanced visualization dashboard

---

*Last Updated: February 3, 2026*
*Version: 1.0.0*
