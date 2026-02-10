# Federated Learning Client

## Overview

The Federated Learning Client enables local training on private network traffic data without sharing raw data with the central server. It implements secure local training, model update generation, and server communication.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Federated Client                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Data      │  │   Model     │  │   Training  │         │
│  │ Management  │  │ Management  │  │   Engine    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Server    │  │   Update    │  │   Privacy   │         │
│  │ Communication│  │ Generation │  │ Protection  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Local     │  │   Metrics   │  │   Logging   │         │
│  │  Storage    │  │ Collection  │  │ & Monitoring│         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  1. Register    │    │  2. Download    │    │  3. Local       │
│     with Server │───▶│   Global Model  │───▶│    Training     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  6. Wait for    │    │  5. Submit      │    │  4. Generate    │
│   Next Round    │◀───│    Updates      │◀───│   Model Update  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Configuration

### Client Configuration (`config.yaml`)
```yaml
server:
  host: "localhost"
  port: 5000
  protocol: "http"

federated:
  local_epochs: 5
  batch_size: 32
  learning_rate: 0.001
  optimizer: "adam"
  loss_function: "cross_entropy"

data:
  data_path: "data/local_client_data.csv"
  test_size: 0.2
  random_state: 42

model:
  input_size: 12
  hidden_size: 64
  num_classes: 2
  sequence_length: 50

training:
  device: "auto"  # auto, cpu, cuda
  save_local_models: true
  log_interval: 10
```

## Data Management

### Data Format
The client expects CSV data with the following structure:

```csv
total_packets,total_bytes,avg_packet_size,std_packet_size,flow_duration,bytes_per_second,packets_per_second,src_to_dst_bytes,dst_to_src_bytes,src_to_dst_packets,dst_to_src_packets,tcp_flags,label,flow_id
150,75000,500,50,10,7500,15,37500,37500,75,75,2,1,flow_001
80,40000,500,45,8,5000,10,20000,20000,40,40,1,0,flow_002
```

### Feature Columns
- **total_packets**: Total number of packets in the flow
- **total_bytes**: Total bytes transferred
- **avg_packet_size**: Average packet size
- **std_packet_size**: Standard deviation of packet sizes
- **flow_duration**: Flow duration in seconds
- **bytes_per_second**: Bytes transferred per second
- **packets_per_second**: Packets transferred per second
- **src_to_dst_bytes**: Bytes from source to destination
- **dst_to_src_bytes**: Bytes from destination to source
- **src_to_dst_packets**: Packets from source to destination
- **dst_to_src_packets**: Packets from destination to source
- **tcp_flags**: TCP flags summary
- **label**: 0=benign, 1=attack
- **flow_id**: Unique flow identifier

### Synthetic Data Generation
If no data file exists, the client automatically generates synthetic data:

```python
# Benign traffic characteristics
benign_patterns = {
    "total_packets": (100, 30),      # mean, std
    "total_bytes": (50000, 15000),
    "flow_duration": (10, 3),
    "packets_per_second": (10, 3)
}

# Attack traffic characteristics
attack_patterns = {
    "total_packets": (1000, 200),
    "total_bytes": (500000, 100000),
    "flow_duration": (5, 2),
    "packets_per_second": (200, 50)
}
```

## Training Process

### Local Training Loop
```python
for epoch in range(local_epochs):
    for batch in dataloader:
        # Forward pass
        outputs = model(batch_X)
        loss = loss_function(outputs, batch_y)
        
        # Backward pass
        loss.backward()
        optimizer.step()
        optimizer.zero_grad()
        
        # Log metrics
        if batch_idx % log_interval == 0:
            log_metrics(epoch, batch_idx, loss.item())
```

### Model Architecture
The client uses the same TCN (Temporal Convolutional Network) architecture as the server:

```python
class TCN(nn.Module):
    def __init__(self, in_ch=12, n_classes=2):
        super().__init__()
        self.tcn = nn.Sequential(
            # Temporal convolution blocks
        )
        self.head = nn.Sequential(
            nn.AdaptiveAvgPool1d(1),
            nn.Flatten(),
            nn.Linear(hidden_size, n_classes)
        )
```

### Update Generation
After local training, the client generates model updates:

```python
# Extract model parameters
model_updates = {}
for name, param in model.named_parameters():
    model_updates[name] = param.detach().cpu().numpy().tolist()

# Calculate metrics
metrics = {
    "accuracy": accuracy_score(y_true, y_pred),
    "loss": test_loss,
    "num_samples": len(X_train),
    "epochs": local_epochs
}
```

## Privacy Features

### Data Privacy
- **No Raw Data Sharing**: Only model parameters are transmitted
- **Local Processing**: All training happens on client premises
- **Secure Communication**: TLS encryption for server communication
- **Data Isolation**: Each client's data remains completely isolated

### Privacy-Enhancing Technologies
```python
# Differential Privacy (optional)
class DPTensor:
    def __init__(self, data, epsilon=1.0):
        self.data = data
        self.epsilon = epsilon
    
    def add_noise(self):
        noise = np.random.normal(0, self.epsilon, self.data.shape)
        return self.data + noise

# Secure Aggregation (research)
def encrypt_update(update, public_key):
    # Homomorphic encryption implementation
    pass
```

## Usage

### Basic Usage
```bash
# Start client with default config
python federated_client.py --client-id enterprise_a

# Custom configuration
python federated_client.py \
  --client-id university_b \
  --config custom_config.yaml

# Override server settings
python federated_client.py \
  --client-id datacenter_c \
  --server-host 192.168.1.100 \
  --server-port 8080 \
  --data-path /path/to/local/data.csv
```

### Advanced Configuration
```bash
# Custom training parameters
python federated_client.py \
  --client-id enterprise_a \
  --rounds 10 \
  --data-path /data/enterprise_traffic.csv

# GPU acceleration
python federated_client.py \
  --client-id datacenter_c \
  --config gpu_config.yaml
```

## Monitoring and Logging

### Training Metrics
- **Loss**: Training and validation loss per epoch
- **Accuracy**: Model accuracy on test set
- **Learning Rate**: Current learning rate
- **Batch Processing**: Progress through batches
- **Round Progress**: Current federated round

### Performance Metrics
```python
# Example metrics output
{
  "accuracy": 0.8547,
  "loss": 0.4231,
  "num_samples": 1000,
  "epochs": 5,
  "epoch_losses": [0.8234, 0.6543, 0.5234, 0.4567, 0.4231],
  "training_time": 45.2,
  "communication_time": 2.1
}
```

### Logging Levels
```python
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Log examples
logger.info("Starting local training...")
logger.warning("GPU not available, using CPU")
logger.error("Failed to connect to server")
```

## Troubleshooting

### Common Issues

1. **Server Connection Failed**
   ```bash
   # Check server status
   curl http://localhost:5000/health
   
   # Verify network connectivity
   ping server_host
   
   # Check firewall settings
   telnet server_host 5000
   ```

2. **Data Loading Errors**
   ```python
   # Validate data format
   df = pd.read_csv(data_path)
   print(df.columns)
   print(df.head())
   
   # Check for missing values
   print(df.isnull().sum())
   ```

3. **Model Training Issues**
   ```python
   # Check device availability
   device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
   print(f"Using device: {device}")
   
   # Verify model architecture
   print(model)
   print(f"Parameters: {sum(p.numel() for p in model.parameters())}")
   ```

4. **Memory Issues**
   ```python
   # Reduce batch size
   batch_size = 16  # Instead of 32
   
   # Use gradient accumulation
   accumulation_steps = 4
   effective_batch_size = batch_size * accumulation_steps
   ```

### Debug Mode
```bash
# Enable debug logging
python federated_client.py --client-id debug_client --debug

# Save intermediate results
python federated_client.py --client-id test_client --save-checkpoints
```

## Performance Optimization

### Training Optimization
```python
# Mixed precision training
scaler = torch.cuda.amp.GradScaler()

with torch.cuda.amp.autocast():
    outputs = model(inputs)
    loss = loss_function(outputs, targets)

scaler.scale(loss).backward()
scaler.step(optimizer)
scaler.update()
```

### Data Loading Optimization
```python
# Use DataLoader with multiple workers
dataloader = DataLoader(
    dataset,
    batch_size=batch_size,
    shuffle=True,
    num_workers=4,  # Parallel data loading
    pin_memory=True  # Faster GPU transfer
)
```

### Communication Optimization
```python
# Compress model updates
def compress_update(update):
    # Quantization or pruning
    return compressed_update

# Batch multiple updates
def batch_updates(updates):
    # Combine multiple small updates
    return batched_update
```

## Security Considerations

### Authentication
```python
# API key authentication
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

# Client certificate authentication
cert_path = "/path/to/client.crt"
key_path = "/path/to/client.key"
```

### Update Validation
```python
# Validate update format
def validate_update(update):
    required_keys = ["model_update", "metrics", "num_samples"]
    for key in required_keys:
        if key not in update:
            raise ValueError(f"Missing required key: {key}")
    
    # Check parameter shapes
    for name, param in update["model_update"].items():
        expected_shape = get_parameter_shape(name)
        if param.shape != expected_shape:
            raise ValueError(f"Invalid shape for {name}")
```

---

*Last Updated: 2024-02-10*
