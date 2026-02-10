# Federated Learning Server

## Overview

The Federated Learning Server coordinates distributed training across multiple clients using the Federated Averaging (FedAvg) algorithm. It manages client registration, model distribution, update aggregation, and global model storage.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Federated Server                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Client    │  │   Client    │  │   Client    │         │
│  │ Registration│  │ Management  │  │ Monitoring  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Model     │  │  Update     │  │   Global    │         │
│  │ Distribution│  │ Aggregation│  │  Storage    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │    API      │  │   Security  │  │   Logging   │         │
│  │  Endpoints  │  │   Layer     │  │ & Monitoring│         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

### Health Check
```
GET /health
```
Returns server health status and current round information.

### Client Registration
```
POST /register
```
Register a new client with the federated server.

**Request:**
```json
{
  "client_id": "enterprise_a",
  "client_info": {
    "platform": "ZeroTrust-AI Client",
    "version": "1.0.0",
    "data_size": 1000,
    "environment": "production"
  }
}
```

**Response:**
```json
{
  "status": "registered",
  "client_id": "enterprise_a",
  "global_round": 0
}
```

### Get Global Model
```
GET /get_global_model?client_id=enterprise_a
```
Retrieve the current global model for local training.

**Response:**
```json
{
  "round": 0,
  "model_state": {
    "tcn.0.weight": [[0.1, 0.2, ...]],
    "tcn.0.bias": [0.0, 0.0, ...],
    ...
  },
  "config": {
    "local_epochs": 5,
    "learning_rate": 0.001,
    ...
  },
  "timestamp": "2024-02-10T15:30:00Z"
}
```

### Submit Update
```
POST /submit_update
```
Submit local model updates to the server.

**Request:**
```json
{
  "client_id": "enterprise_a",
  "round": 0,
  "model_update": {
    "tcn.0.weight": [[0.11, 0.21, ...]],
    "tcn.0.bias": [0.01, 0.01, ...],
    ...
  },
  "metrics": {
    "accuracy": 0.85,
    "loss": 0.45,
    "num_samples": 1000,
    "epochs": 5
  },
  "num_samples": 1000
}
```

**Response:**
```json
{
  "status": "received",
  "round": 0,
  "client_id": "enterprise_a"
}
```

### Server Status
```
GET /status
```
Get comprehensive server status and metrics.

**Response:**
```json
{
  "round": 3,
  "total_rounds": 10,
  "connected_clients": 3,
  "ready_for_aggregation": true,
  "client_metrics": {
    "enterprise_a": {"accuracy": 0.85, "loss": 0.45},
    "university_b": {"accuracy": 0.82, "loss": 0.48},
    "datacenter_c": {"accuracy": 0.88, "loss": 0.42}
  },
  "aggregation_history": [...],
  "timestamp": "2024-02-10T15:30:00Z"
}
```

## Configuration

### Server Configuration (`config.yaml`)
```yaml
server:
  host: "0.0.0.0"
  port: 5000
  debug: false

federated:
  min_clients: 2
  max_clients: 10
  rounds: 10
  local_epochs: 5
  learning_rate: 0.001
  aggregation_strategy: "fedavg"

model:
  input_size: 12
  hidden_size: 64
  num_classes: 2
  sequence_length: 50

security:
  require_auth: false
  api_key: null
  update_validation: true
```

## Aggregation Algorithm

### Federated Averaging (FedAvg)

The server uses weighted averaging based on client data sizes:

```
w_global = Σ (n_i / n_total) * w_client_i
```

Where:
- `w_global` = Global model weights
- `n_i` = Number of samples at client i
- `n_total` = Total samples across all clients
- `w_client_i` = Model weights from client i

### Aggregation Process

1. **Collect Updates**: Wait for minimum number of client updates
2. **Validate Updates**: Check update integrity and format
3. **Weight Calculation**: Calculate weights based on data sizes
4. **Parameter Aggregation**: Apply weighted averaging to each parameter
5. **Model Update**: Update global model with aggregated parameters
6. **Storage**: Save global model checkpoint
7. **Round Increment**: Increment round counter

## Security Features

### Client Authentication
- Mutual TLS authentication (optional)
- API key authentication
- Client certificate validation
- Rate limiting and DDoS protection

### Update Validation
- Parameter shape validation
- Anomaly detection in updates
- Byzantine-robust aggregation options
- Rollback capabilities

### Privacy Protection
- No raw data collection
- Secure model update transmission
- Optional differential privacy
- Update encryption

## Monitoring and Logging

### Metrics Tracked
- **Round Progress**: Current round vs total rounds
- **Client Participation**: Number of active clients
- **Aggregation History**: Performance over time
- **Client Metrics**: Individual client performance
- **System Health**: Server resource usage

### Logging Levels
- **INFO**: Normal operations, client connections
- **WARNING**: Non-critical issues, aggregation delays
- **ERROR**: Critical failures, authentication issues
- **DEBUG**: Detailed debugging information

## Model Storage

### File Structure
```
models/federated/
├── global_model_round_1.pth
├── global_model_round_2.pth
├── ...
├── global_model_round_10.pth
└── global_model_latest.pth
```

### Model Versioning
- Round-specific checkpoints
- Latest model symlink
- Metadata tracking
- Automatic cleanup options

## Usage

### Start Server
```bash
# Basic usage
python federated_server.py

# With custom configuration
python federated_server.py --config custom_config.yaml

# Override host/port
python federated_server.py --host 192.168.1.100 --port 8080
```

### Docker Deployment
```bash
# Build image
docker build -t zerotrust-federated-server .

# Run container
docker run -p 5000:5000 \
  -v $(pwd)/models:/app/models \
  zerotrust-federated-server
```

### Production Deployment
```bash
# With Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 federated_server:app

# With SSL
gunicorn -w 4 -b 0.0.0.0:443 \
  --keyfile server.key \
  --certfile server.crt \
  federated_server:app
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Check port usage
   netstat -tulpn | grep :5000
   
   # Kill process
   sudo kill -9 <PID>
   ```

2. **Client Connection Failed**
   - Check firewall settings
   - Verify server URL
   - Check network connectivity

3. **Aggregation Timeout**
   - Increase `min_clients` requirement
   - Check client connectivity
   - Verify client data processing

4. **Model Loading Errors**
   - Check model architecture compatibility
   - Verify model file permissions
   - Check PyTorch version compatibility

### Debug Mode
```bash
# Enable debug logging
python federated_server.py --config config.yaml --debug
```

## Performance Optimization

### Scaling Considerations
- **Horizontal Scaling**: Multiple server instances
- **Load Balancing**: nginx or HAProxy
- **Database Integration**: PostgreSQL for metadata
- **Caching**: Redis for frequent operations

### Resource Requirements
- **CPU**: 2-4 cores for moderate loads
- **Memory**: 4-8GB RAM
- **Storage**: 10GB+ for model checkpoints
- **Network**: 100Mbps+ for client communication

---

*Last Updated: 2024-02-10*
