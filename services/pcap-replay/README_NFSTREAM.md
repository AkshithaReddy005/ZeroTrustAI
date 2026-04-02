# NFStream Real-time PCAP Flow Processor

This service provides real-time flow extraction from PCAP files using **nfstream** instead of CSV files, with direct integration to the dashboard via websockets.

## Features

- **Real-time PCAP Processing**: Uses nfstream for efficient flow extraction from PCAP files
- **WebSocket Integration**: Direct communication with the dashboard for real-time updates
- **Threat Detection**: Built-in threat detection based on flow characteristics
- **Automatic File Monitoring**: Continuously monitors for new PCAP files
- **Multiple Processing Modes**: CSV, dpkt, and nfstream processing options

## Architecture

```
PCAP Files → NFStream → Flow Extraction → WebSocket → Dashboard
                ↓
            Threat Detection → API Events → Dashboard Alerts
```

## Quick Start

### Using Docker (Recommended)

1. **Add PCAP files**:
   ```bash
   # Copy your PCAP files to the data directory
   cp your-pcap-file.pcap data/raw/
   ```

2. **Start the services**:
   ```bash
   # Linux/Mac
   ./start_nfstream.sh
   
   # Windows
   start_nfstream.bat
   
   # Or manually with Docker Compose
   docker-compose -f docker-compose.nfstream.yml up --build
   ```

3. **View the dashboard**:
   Open http://localhost:9000 in your browser

### Manual Installation

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the WebSocket server**:
   ```bash
   cd ../detector/app
   python websocket_server.py
   ```

3. **Start the NFStream processor**:
   ```bash
   cd ../../pcap-replay
   python nfstream_websocket_bridge.py
   ```

## Configuration

Environment variables can be set to configure the behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `USE_CSV` | `false` | Use CSV file processing instead of PCAP |
| `USE_NFSTREAM` | `true` | Use nfstream for PCAP processing |
| `PCAP_SOURCE` | `/data/raw` | Directory containing PCAP files |
| `WEBSOCKET_URL` | `ws://localhost:9000/ws` | WebSocket server URL |
| `THROTTLE_MS` | `100` | Delay between flow processing (milliseconds) |
| `DEMO_MODE` | `true` | Enable demo threat injection |
| `DEMO_RATE` | `0.1` | Probability of demo threat injection |

## Services

### 1. WebSocket Server (`websocket_server.py`)
- **Port**: 9000
- **Purpose**: Provides WebSocket connections for the dashboard
- **Endpoints**:
  - `GET /` - Dashboard web interface
  - `POST /events/flow` - Receive flow events
  - `POST /events/threat` - Receive threat events
  - `WebSocket /ws` - Real-time dashboard updates

### 2. NFStream Processor (`app.py`)
- **Purpose**: Processes PCAP files using nfstream
- **Features**:
  - Real-time flow extraction
  - Statistical analysis
  - Threat detection
  - API integration

### 3. WebSocket Bridge (`nfstream_websocket_bridge.py`)
- **Purpose**: Direct NFStream to WebSocket communication
- **Features**:
  - Bypasses API for faster updates
  - Real-time threat detection
  - Automatic file monitoring
  - Processing summaries

## Threat Detection

The system includes built-in threat detection based on flow characteristics:

### Detection Rules

1. **High Packet Rate**: > 1000 packets per second
2. **Unusual Ports**: Access to sensitive ports (22, 3389, 1433, etc.)
3. **Large Transfers**: > 5MB total bytes
4. **Suspicious Persistence**: Long duration with high packet count

### Threat Classification

- **Data Exfiltration**: Large data transfers
- **Port Scanning**: Access to multiple unusual ports
- **DDoS**: High packet rates
- **Suspicious Activity**: Other anomalous patterns

## File Structure

```
services/pcap-replay/
├── app.py                          # Main PCAP processor (supports nfstream)
├── realtime_nfstream.py            # Standalone nfstream processor
├── nfstream_websocket_bridge.py    # Direct WebSocket bridge
├── docker-compose.nfstream.yml     # Docker composition
├── Dockerfile.nfstream            # NFStream processor Dockerfile
├── Dockerfile.bridge              # WebSocket bridge Dockerfile
├── start_nfstream.sh              # Linux startup script
├── start_nfstream.bat             # Windows startup script
└── data/
    ├── raw/                        # Input PCAP files
    └── processed/                  # Processed data (if needed)
```

## Monitoring

### Dashboard Features

- **Real-time Flow Updates**: Live flow information
- **Threat Alerts**: Instant threat notifications
- **Flow Statistics**: Packet counts, byte rates, durations
- **Attack Classification**: Automatic attack type identification
- **Blocking Actions**: Automatic flow blocking for high-severity threats

### Metrics

The system provides various metrics:
- Total flows processed
- Threats detected
- Packets per second
- Byte transfer rates
- Attack type distribution

## Troubleshooting

### Common Issues

1. **No PCAP files found**:
   - Ensure PCAP files are in `data/raw/`
   - Check file permissions

2. **WebSocket connection failed**:
   - Verify WebSocket server is running on port 9000
   - Check firewall settings

3. **High memory usage**:
   - Reduce `THROTTLE_MS` to slow processing
   - Process smaller PCAP files

4. **Missing dependencies**:
   ```bash
   pip install nfstream websockets fastapi uvicorn
   ```

### Logs

View logs for debugging:
```bash
# Docker logs
docker-compose -f docker-compose.nfstream.yml logs -f

# Specific service
docker-compose -f docker-compose.nfstream.yml logs -f pcap-processor-nfstream
```

## Performance

### Optimization Tips

1. **Throttle Adjustment**: Increase `THROTTLE_MS` for slower systems
2. **File Size**: Process smaller PCAP files for better responsiveness
3. **Memory**: Monitor memory usage with large PCAP files
4. **Network**: Ensure sufficient bandwidth for WebSocket updates

### Benchmarks

- **Processing Speed**: ~1000 flows/second (depends on PCAP complexity)
- **Memory Usage**: ~100MB for typical PCAP files
- **Latency**: < 100ms from flow extraction to dashboard update

## Migration from CSV

To migrate from CSV-based processing:

1. **Set environment variables**:
   ```bash
   export USE_CSV=false
   export USE_NFSTREAM=true
   ```

2. **Convert existing CSV data**:
   ```bash
   python scripts/400k_training/extract_splt_nfstream.py
   ```

3. **Update configuration**:
   - Remove CSV path references
   - Add PCAP file sources
   - Update processing scripts

## Contributing

To extend the system:

1. **Add new detection rules** in `detect_threat()` function
2. **Enhance flow features** in `process_nfstream_flow()` function
3. **Add new message types** in WebSocket handlers
4. **Create custom Docker images** for specific deployments

## License

This project is part of the ZeroTrust-AI framework. See the main project license for details.
