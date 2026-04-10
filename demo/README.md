# Two-Laptop Demo Setup

This demo shows real-time network flow classification between two laptops on the same WiFi network.

## Architecture

```
Laptop A (Sender)          Laptop B (Classifier)
sends network flows    →   receives flows
                           scores with ensemble
                           shows real-time results
```

## Prerequisites

Both laptops must:
- Be on the same WiFi network
- Have Python 3.8+ installed
- Have the required dependencies installed

## Setup Instructions

### Step 1: Find IP Addresses

On **both laptops**, run:

**Windows:**
```bash
ipconfig
```

**Linux/Mac:**
```bash
ifconfig
```

Look for the IPv4 address (e.g., `192.168.1.5`). Write down both IPs.

### Step 2: Configure Laptop A (Sender)

1. Edit `sender_laptop_a.py`
2. Change line 13:
   ```python
   RECEIVER_IP = "192.168.1.X"  # PUT LAPTOP B IP HERE
   ```
   Replace `192.168.1.X` with Laptop B's actual IP address

### Step 3: Configure Firewall on Laptop B

**Windows:**
```bash
netsh advfirewall firewall add rule name="ZTAI Demo" dir=in action=allow protocol=TCP localport=9999
```

**Linux:**
```bash
sudo ufw allow 9999/tcp
```

**Mac:**
```bash
# System Preferences → Security & Privacy → Firewall → Firewall Options
# Add Python and allow incoming connections
```

### Step 4: Install Dependencies

On **both laptops**:

```bash
cd c:\Users\akshi\Downloads\ZeroTrustAI
pip install -r requirements.txt
```

## Running the Demo

### On Laptop B (Classifier) - Start FIRST

```bash
cd c:\Users\akshi\Downloads\ZeroTrustAI
python demo/receiver_laptop_b.py
```

You should see:
```
LAPTOP B - NETWORK FLOW CLASSIFIER
Loading trained models...
  ✅ TCN loaded
  ✅ Autoencoder loaded
  ✅ Isolation Forest loaded
  ✅ Scalers loaded

🎯 Listening on port 9999...
Waiting for flows from Laptop A...
```

### On Laptop A (Sender) - Start SECOND

```bash
cd c:\Users\akshi\Downloads\ZeroTrustAI
python demo/sender_laptop_a.py
```

You should see flows being sent:
```
LAPTOP A - NETWORK FLOW SENDER
Target: 192.168.1.X:9999

[0001] 🟢 Benign | 192.168.1.25 → 8.8.8.8 | 45 pkts
[0002] 🔴 DDoS   | 192.168.1.150 → 192.168.1.1 | 1200 pkts
[0003] 🟡 C2     | 192.168.1.75 → 45.33.32.156 | 12 pkts
```

### On Laptop B - See Classifications

```
[0001] 192.168.1.25    → 8.8.8.8         | Score: 0.125 | 🟢 ALLOW | Ground truth: Normal
[0002] 192.168.1.150   → 192.168.1.1     | Score: 0.782 | 🔴 QUARANTINE | Ground truth: DDoS
[0003] 192.168.1.75    → 45.33.32.156    | Score: 0.456 | 🟡 MONITOR | Ground truth: C2
```

## Understanding the Output

### Three-Tier Policy

- **🔴 QUARANTINE** (score > 0.55): Block + SOAR alert
- **🟡 MONITOR** (score 0.35-0.55): Allow + elevated telemetry
- **🟢 ALLOW** (score < 0.35): Standard pass-through

### Ensemble Scoring

The classifier uses three models:
- **TCN (60%)**: Temporal pattern analysis on SPLT sequences
- **Autoencoder (30%)**: Anomaly detection on benign baseline
- **Isolation Forest (10%)**: Volumetric outlier detection

Final score = 0.6 × TCN + 0.3 × AE + 0.1 × IF

## Troubleshooting

### "Connection refused" on Laptop A

**Problem**: Laptop B is not reachable
**Fix**:
1. Verify both laptops are on same WiFi
2. Ping Laptop B from Laptop A: `ping 192.168.1.X`
3. Check firewall on Laptop B
4. Verify receiver is running on Laptop B

### "Error loading models"

**Problem**: Model files not found
**Fix**:
1. Verify models exist in `models/` directory:
   - `tcn_classifier.pth`
   - `autoencoder.pth`
   - `isoforest.joblib`
   - `scaler.joblib`
   - `robust_scaler_volumetric.joblib`
   - `ae_threshold.txt`

### All flows classified as ALLOW

**Problem**: Models not scaling features correctly
**Fix**:
1. Check that scalers are being applied in `receiver_laptop_b.py`
2. Verify model files match the training data distribution

### Test Connection

On Laptop A, run:
```bash
python -c "import socket; s=socket.socket(); s.connect(('192.168.1.X', 9999)); s.send(b'test'); s.close(); print('✅ Connected!')"
```

Replace `192.168.1.X` with Laptop B's IP. If you see "✅ Connected!" the network is working.

## Flow Types Generated

### Benign (60% of traffic)
- Normal web traffic patterns
- Varied packet sizes (60-1500 bytes)
- Random inter-arrival times (10-1000ms)

### DDoS (20% of traffic)
- High packet rate (500-2000 packets)
- Small packet sizes (40-100 bytes)
- Fast bursts (0.1-10ms intervals)

### C2 Beacon (20% of traffic)
- Low packet count (5-20 packets)
- Consistent packet sizes (~200-500 bytes)
- Regular intervals (5-15 second beacons)

## Stopping the Demo

Press `Ctrl+C` on both laptops to stop gracefully.
