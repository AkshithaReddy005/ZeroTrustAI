# ZeroTrust-AI Local Setup Guide

## 🚀 Running ZeroTrust-AI Without Docker

### **📋 Prerequisites**
- Python 3.9+
- Redis server
- InfluxDB 2.x
- Trained ML models in `/models/` directory

---

## 🔧 **Installation Steps**

### **1. Install Dependencies**
```bash
# Clone repository
git clone https://github.com/AkshithaReddy005/ZeroTrust-AI.git
cd ZeroTrust-AI

# Install Python dependencies
pip install -r requirements.txt

# Install XAI dependencies
pip install streamlit-shap shap
```

### **2. Install Redis**
```bash
# Windows: Download from redis.io
# macOS: brew install redis
# Linux: sudo apt-get install redis-server

# Start Redis
redis-server
```

### **3. Install InfluxDB**
```bash
# Download InfluxDB 2.x from influxdata.com
# Extract and run:
influxd.exe  # Windows
./influxd     # Linux/macOS

# Setup via browser: http://localhost:8086
# - Organization: zerotrust
# - Bucket: threat_events
# - Token: copy for environment variable
```

---

## 🚀 **Startup Sequence**

### **Required Services (Minimum 3)**
```bash
# Terminal 1: Start Redis
redis-server

# Terminal 2: Start InfluxDB
influxd

# Terminal 3: Start Detector
cd services/detector/app
export PYTHONUNBUFFERED=1
export MODEL_DIR=/path/to/your/models
export REDIS_URL=redis://localhost:6379/0
export REDIS_TTL_SECONDS=1800
export INFLUX_URL=http://localhost:8086
export INFLUX_TOKEN=your_influx_token
export INFLUX_ORG=zerotrust
export INFLUX_BUCKET=threat_events
python main.py
```

### **Optional Services**
```bash
# Terminal 4: Start API Gateway
cd services/api-gateway
export PYTHONUNBUFFERED=1
export DETECTOR_URL=http://localhost:9000
python main.py

# Terminal 5: Start Main Dashboard
cd apps/dashboard
export API_BASE_URL=http://localhost:8000
streamlit run index.py --server.port 8501

# Terminal 6: Start XAI Dashboard
cd apps/dashboard
streamlit run xai_dashboard_standalone.py --server.port 8502
```

---

## 📋 **Service Access Points**

| Service | URL | Port | Required |
|---------|------|-------|----------|
| **Redis** | localhost | 6379 | ✅ |
| **InfluxDB** | http://localhost | 8086 | ✅ |
| **Detector** | http://localhost | 9000 | ✅ |
| **API Gateway** | http://localhost | 8000 | ❌ |
| **Main Dashboard** | http://localhost | 8501 | ❌ |
| **XAI Dashboard** | http://localhost | 8502 | ❌ |

---

## 🎯 **Quick Start Script**

### **Windows (start_local.bat)**
```batch
@echo off
echo Starting ZeroTrust-AI services...

start "Redis" redis-server
start "InfluxDB" influxd
timeout /t 5
start "Detector" cmd /k "cd services\detector\app && set PYTHONUNBUFFERED=1 && set MODEL_DIR=C:\path\to\models && set REDIS_URL=redis://localhost:6379/0 && set INFLUX_URL=http://localhost:8086 && python main.py"
start "API Gateway" cmd /k "cd services\api-gateway && set PYTHONUNBUFFERED=1 && set DETECTOR_URL=http://localhost:9000 && python main.py"
start "Dashboard" cmd /k "cd apps\dashboard && set API_BASE_URL=http://localhost:8000 && streamlit run index.py --server.port 8501"
start "XAI Dashboard" cmd /k "cd apps\dashboard && streamlit run xai_dashboard_standalone.py --server.port 8502"

echo All services started!
echo Dashboard: http://localhost:8501
echo XAI Dashboard: http://localhost:8502
```

### **Linux/macOS (start_local.sh)**
```bash
#!/bin/bash
echo "Starting ZeroTrust-AI services..."

# Start required services
redis-server &
influxd &
sleep 5

# Start detector
cd services/detector/app
export PYTHONUNBUFFERED=1
export MODEL_DIR=/path/to/your/models
export REDIS_URL=redis://localhost:6379/0
export INFLUX_URL=http://localhost:8086
python main.py &
DETECTOR_PID=$!

# Start optional services
cd ../api-gateway
export PYTHONUNBUFFERED=1
export DETECTOR_URL=http://localhost:9000
python main.py &
API_PID=$!

cd ../../apps/dashboard
export API_BASE_URL=http://localhost:8000
streamlit run index.py --server.port 8501 &
DASHBOARD_PID=$!

streamlit run xai_dashboard_standalone.py --server.port 8502 &
XAI_PID=$!

echo "All services started!"
echo "Dashboard: http://localhost:8501"
echo "XAI Dashboard: http://localhost:8502"
echo "Press Ctrl+C to stop all services"

# Wait for interrupt
trap "kill $DETECTOR_PID $API_PID $DASHBOARD_PID $XAI_PID; exit" INT
wait
```

---

## 🔧 **Environment Variables**

### **Required for Detector**
```bash
PYTHONUNBUFFERED=1
MODEL_DIR=/path/to/your/models
REDIS_URL=redis://localhost:6379/0
REDIS_TTL_SECONDS=1800
INFLUX_URL=http://localhost:8086
INFLUX_TOKEN=your_influx_token
INFLUX_ORG=zerotrust
INFLUX_BUCKET=threat_events
```

### **Required for API Gateway**
```bash
PYTHONUNBUFFERED=1
DETECTOR_URL=http://localhost:9000
```

### **Required for Dashboard**
```bash
API_BASE_URL=http://localhost:8000
```

---

## ⚠️ **Troubleshooting**

### **Common Issues**

#### **1. Redis Connection Failed**
```bash
# Check if Redis is running
redis-cli ping

# Should return: PONG
```

#### **2. InfluxDB Connection Failed**
```bash
# Check if InfluxDB is running
curl http://localhost:8086/health

# Should return: {"name":"influxdb","message":"ready for queries"}
```

#### **3. Model Loading Failed**
```bash
# Check if models exist
ls -la /path/to/your/models/

# Should see:
# tcn_classifier.pth
# autoencoder.pth
# splt_scaler.joblib
# splt_isoforest.joblib
```

#### **4. Port Already in Use**
```bash
# Check what's using the port
netstat -an | findstr :9000  # Windows
netstat -an | grep :9000     # Linux/macOS

# Change port in service if needed
```

---

## 🎯 **Verification**

### **Test Services**
```bash
# Test detector
curl http://localhost:9000/health

# Test API gateway
curl http://localhost:8000/health

# Test Redis
redis-cli ping

# Test InfluxDB
curl http://localhost:8086/health
```

### **Access Dashboards**
- **Main Dashboard**: http://localhost:8501
- **XAI Dashboard**: http://localhost:8502

---

## 📊 **Resource Requirements**

### **Minimum System Requirements**
- **RAM**: 8GB (16GB recommended)
- **CPU**: 4 cores (8 cores recommended)
- **Storage**: 10GB free space
- **Python**: 3.9+

### **Service Memory Usage**
- **Redis**: ~100MB
- **InfluxDB**: ~500MB
- **Detector**: ~2GB
- **API Gateway**: ~500MB
- **Dashboard**: ~500MB
- **XAI Dashboard**: ~500MB

---

## 🚀 **Production Deployment**

For production use, consider:
1. **Process Managers**: Use systemd/supervisor to manage services
2. **Load Balancing**: nginx for multiple instances
3. **Security**: Firewall rules, SSL certificates
4. **Monitoring**: Prometheus + Grafana
5. **Logging**: Centralized log management

---

**Your ZeroTrust-AI system is now running locally without Docker!** 🛡️🚀
