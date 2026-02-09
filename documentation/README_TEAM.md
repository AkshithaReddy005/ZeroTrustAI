# 🛡️ ZeroTrust-AI: AI-Powered Network Security System

> **Motto: Never Trust. Always Verify.**

## 🎯 Quick Start for New Team Members

### **🚀 What This Project Does**
ZeroTrust-AI is an **AI-powered next-generation firewall** that:
- **Detects network threats** in real-time using machine learning
- **Analyzes network traffic** for malicious patterns (botnets, malware, data exfiltration)
- **Provides live dashboard** for security operations
- **Achieves 96.54% F1-score** in threat detection

### **📁 Project Overview**
```
🌐 Network Traffic → 🛡️ ZeroTrust-AI → 🔒 Security Actions
```

## � Docker Setup (Recommended for Production)

### **🚀 Why Use Docker?**
- **Consistent environment** across all machines
- **Easy deployment** with one command
- **Resource management** (memory limits)
- **Scalable architecture** for production

### **📋 Docker Prerequisites**
- **Docker Desktop** (Windows/Mac) or **Docker Engine** (Linux)
- **Docker Compose** (usually included with Docker)
- **8GB+ RAM** available for containers

### **🚀 Quick Docker Start**
```bash
# 1. Clone and navigate to project
git clone https://github.com/AkshithaReddy005/ZeroTrust-AI.git
cd ZeroTrust-AI

# 2. Build and start all services
docker-compose -f docker-compose.web.yml up -d

# 3. Access the dashboard
open http://localhost:9000
```

### **📊 Docker Services Overview**
```
🐳 Services Started:
├── 🌐 WebSocket Server (Port 9000)
│   └── Real-time threat detection & dashboard
├── 🗄️ Redis (Port 6379)
│   └── Real-time caching & message passing
├── 📈 InfluxDB (Port 8086)
│   └── Time-series analytics & historical data
├── 🌐 Nginx (Port 80/443)
│   └── Static file serving & load balancing
└── 📊 Grafana (Port 3000)
│   └── Advanced analytics & monitoring
```

### **🔧 Docker Compose Files**
```bash
# For real-time dashboard (recommended)
docker-compose -f docker-compose.web.yml up -d

# For basic services only
docker-compose -f docker-compose.yml up -d

# For development with hot reload
docker-compose -f docker-compose.web.yml up --build
```

### **📊 Docker Commands Cheat Sheet**
```bash
# Start all services
docker-compose -f docker-compose.web.yml up -d

# View running containers
docker-compose ps

# View logs
docker-compose logs -f websocket-server

# Stop all services
docker-compose down

# Rebuild and start
docker-compose up --build -d

# Access container shell
docker-compose exec websocket-server bash

# Monitor resource usage
docker stats
```

### **🌐 Access Points After Docker Start**
```
🎯 Main Dashboard: http://localhost:9000
📊 Grafana Analytics: http://localhost:3000 (admin/admin123)
🗄️ InfluxDB Interface: http://localhost:8086
🌐 Nginx (if enabled): http://localhost:80
```

### **🔧 Docker Troubleshooting**
```bash
# If port conflicts occur
docker-compose down
# Edit docker-compose.web.yml to change ports
docker-compose up -d

# If containers won't start
docker system prune -f
docker-compose up --build

# Check container health
docker-compose ps
docker-compose logs websocket-server
```

### **📁 Docker Volumes (Data Persistence)**
```bash
# Redis data persists in: redis_data volume
# InfluxDB data persists in: influxdb_data volume
# Grafana configs persist in: grafana_data volume

# View volumes
docker volume ls

# Backup data
docker run --rm -v redis_data:/data -v $(pwd):/backup alpine tar czf /backup/redis-backup.tar.gz -C /data .
```

### **🚀 Production Docker Deployment**
```bash
# For production environment
docker-compose -f docker-compose.web.yml -f docker-compose.prod.yml up -d

# Environment variables
export ENVIRONMENT=production
export LOG_LEVEL=info
export REDIS_URL=redis://redis:6379

# Start with production settings
docker-compose -f docker-compose.web.yml up -d
```

## 🎯 Quick Start for New Team Members

### **📋 Prerequisites**
- **Python 3.7+** (recommended 3.9+)
- **Git** (for cloning)
- **Docker** (optional, for production)
- **8GB+ RAM** (for ML models)

### **🚀 Installation Options**

#### **Option 1: Docker (Recommended)**
```bash
# 1. Clone the project
git clone https://github.com/AkshithaReddy005/ZeroTrust-AI.git
cd ZeroTrust-AI

# 2. Start with Docker
docker-compose -f docker-compose.web.yml up -d

# 3. Access dashboard
http://localhost:9000
```

#### **Option 2: Local Python**
```bash
# 1. Clone the project
git clone https://github.com/AkshithaReddy005/ZeroTrust-AI.git
cd ZeroTrust-AI

# 2. Install dependencies
pip install -r requirements.txt

# Database dependencies included:
# - redis==4.2.0 (real-time state)
# - influxdb-client==1.36.0 (historical analytics)

# 3. Download models (if not included)
# Models are in models/ directory (tcn_classifier.pth, autoencoder.pth, etc.)

# 4. Test the system
python scripts/evaluate_models.py
```

## 🎯 What to Do First

### **📊 Step 1: Understand the System**
Read these files (in order):
1. **INPUT_OUTPUT_FLOW.md** - How data flows through the system
2. **MODEL_IMPROVEMENT_TRACKER.md** - Project evolution story
3. **docs/WORKFLOW.md** - End-to-end process
4. **docs/TECHNICAL_DOCUMENTATION.md** - Technical details

### **🚀 Step 2: Test the Real-Time Dashboard**
```bash
# Start the WebSocket server
python services/detector/app/websocket_server.py

# Open browser to
http://localhost:9000

# Generate demo threats (optional, in another terminal)
python demo_realtime.py
```

### **📊 Step 3: Evaluate Model Performance**
```bash
# Test current model performance
python scripts/evaluate_models.py

# Expected results:
# TCN: 99.14% accuracy, 97.99% F1-score
# Ensemble: 98.54% accuracy, 96.54% F1-score
```

## 📁 Project Structure

### **🎯 Important Directories**
```
ZeroTrust-AI/
├── 📁 apps/
│   ├── 📁 web/                 # Real-time web dashboard
│   │   └── 📄 index.html       # Main dashboard
│   └── 📁 dashboard/           # Streamlit dashboard
├── 📁 services/
│   └── 📁 detector/
│       └── 📁 app/
│           ├── 📄 main.py      # Core detection logic
│           └── 📄 websocket_server.py # Real-time server
├── 📁 scripts/
│   ├── 📄 extract_splt_nfstream.py # Feature extraction
│   ├── 📄 train_*.py          # Model training scripts
│   └── 📄 evaluate_models.py  # Performance evaluation
├── 📁 models/                 # Trained ML models
├── 📁 data/                   # Datasets and processed data
├── 📁 docs/                   # Complete documentation
└── 📄 requirements.txt        # Python dependencies
```

### **🔑 Key Files to Understand**
- **services/detector/app/main.py** - Core threat detection logic
- **apps/web/index.html** - Real-time dashboard
- **scripts/evaluate_models.py** - Model performance testing
- **docs/TECHNICAL_DOCUMENTATION.md** - Complete technical details

## 🎮 How to Use the System

### **🐳 Option 1: Docker (Recommended for Production)**
```bash
# Start all services with Docker
docker-compose -f docker-compose.web.yml up -d

# Access the dashboard
http://localhost:9000

# Access Grafana for advanced analytics
http://localhost:3000 (admin/admin123)

# Monitor containers
docker-compose ps
docker-compose logs -f websocket-server
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

### **🚀 Option 3: Real-Time Dashboard (Local Python)**
```bash
# Start WebSocket server
python services/detector/app/websocket_server.py

# Open browser
http://localhost:9000

# You'll see:
# - Live threat detection feed
# - Real-time metrics
# - Interactive charts
# - Model performance monitoring
```

### **📊 Option 3: Model Evaluation**
```bash
# Test model performance
python scripts/evaluate_models.py

# This shows:
# - Individual model performance
# - Ensemble results
# - Best thresholds and weights
```

### **🔧 Option 4: Feature Extraction**
```bash
# Extract features from PCAP files
python scripts/extract_splt_nfstream.py

# Output: data/processed/splt_features.csv
# Contains SPLT features for ML models
```

## 🤖 Understanding the ML Models

### **📊 Model Ensemble**
Your system uses **3 complementary models**:

#### **1. TCN (Temporal Convolutional Network)**
- **Purpose**: Pattern recognition in network flows
- **Input**: SPLT sequences (packet lengths + timing)
- **Performance**: 99.14% accuracy, 97.99% F1-score
- **Strength**: Excellent at detecting known attack patterns

#### **2. Autoencoder**
- **Purpose**: Anomaly detection
- **Input**: SPLT sequences for reconstruction
- **Performance**: 73.76% accuracy, 12.07% F1-score
- **Strength**: Detects unusual/unknown attacks

#### **3. IsolationForest**
- **Purpose**: Statistical outlier detection
- **Input**: Flattened SPLT features
- **Performance**: 73.08% accuracy, 23.28% F1-score
- **Strength**: Finds statistical anomalies

#### **4. Ensemble (Combined)**
- **Method**: Weighted voting (TCN=60%, AE=20%, ISO=20%)
- **Performance**: 98.54% accuracy, 96.54% F1-score
- **Result**: Production-ready threat detection

## 📊 Data Flow Explained

### **🌐 Input → Output**
```
🌐 Network Traffic (PCAP files or live capture)
    ↓
📊 Flow Aggregation (NFStream + dpkt)
    ↓
🔍 Feature Extraction (SPLT sequences)
    ↓
🤖 ML Model Analysis (TCN + AE + IsoForest)
    ↓
🎯 Ensemble Decision (malicious/benign)
    ↓
🚨 Security Actions (block/alert/log)
    ↓
📊 Real-Time Dashboard (live updates)
```

### **🔍 SPLT Features**
- **S**: Sequence of packet lengths (first 20 packets)
- **P**: Packet lengths (log-transformed with direction)
- **L**: Lengths of packets
- **T**: Timing between packets (inter-arrival times)

## 🎯 Common Tasks

### **📊 Testing Model Performance**
```bash
python scripts/evaluate_models.py
```

### **🚀 Starting Real-Time Dashboard**
```bash
python services/detector/app/websocket_server.py
# Then open http://localhost:9000
```

### **🔧 Training New Models**
```bash
# Train TCN
python scripts/train_tcn.py

# Train Autoencoder
python scripts/train_autoencoder.py

# Train IsolationForest
python scripts/train_isoforest_splt.py
```

### **📁 Processing New PCAP Files**
```bash
python scripts/extract_splt_nfstream.py
# Specify PCAP file path in the script
```

## 🔧 Troubleshooting

### **❌ Common Issues**

#### **1. Model Loading Errors**
```bash
# Check if models exist
ls models/

# Should see:
# tcn_classifier.pth
# autoencoder.pth
# splt_scaler.joblib
# splt_isoforest.joblib
```

#### **2. WebSocket Server Won't Start**
```bash
# Check dependencies
pip install fastapi uvicorn websockets

# Check if port 9000 is free
netstat -an | findstr :9000
```

#### **3. Dashboard Won't Load**
- Try http://127.0.0.1:9000 instead of localhost
- Check browser console for errors
- Ensure WebSocket server is running

#### **4. Model Performance Issues**
```bash
# Re-evaluate models
python scripts/evaluate_models.py

# Check data files
ls data/processed/
# Should see: splt_features.csv
```

## 📚 Development Guide

### **🔧 Making Changes**
1. **Understand the codebase** - Read docs first
2. **Test changes locally** - Use evaluate_models.py
3. **Update documentation** - Keep docs current
4. **Test real-time interface** - Verify dashboard works

### **📊 Adding New Features**
1. **Feature extraction** - Modify scripts/extract_splt_*.py
2. **Model changes** - Update scripts/train_*.py
3. **Dashboard updates** - Edit apps/web/index.html
4. **API changes** - Modify services/detector/app/*.py

### **🚀 Deployment**
```bash
# For production use Docker (recommended)
docker-compose -f docker-compose.web.yml up -d

# Access:
# Main dashboard: http://localhost:9000
# Grafana: http://localhost:3000 (admin/admin123)
# InfluxDB: http://localhost:8086

# For development (local Python)
python services/detector/app/websocket_server.py
# Then open http://localhost:9000
```

## 🎯 Current Project Status

### **✅ Completed Features**
- **96.54% F1-score** ML ensemble with TCN, Autoencoder, IsolationForest
- **Real-time dashboard** with WebSocket live updates
- **Redis + InfluxDB** persistent memory with risk decay
- **MITRE ATT&CK** TTP mapping for threat intelligence
- **Performance testing** with <100ms latency verification
- **SOAR capabilities** with manual override and audit trail
- **XAI integration** SHAP-based explainable AI with visualizations
- **Complete documentation** and team onboarding guides
- **Docker deployment** ready for production

### **🚀 Final Checklist (Week 4)**
- ✅ **MITRE ATT&CK Mapping**: Botnet → T1071, Data Exfiltration → T1041, etc.
- ✅ **Performance Stress Test**: 1000 concurrent requests, <100ms latency
- ✅ **SOAR Manual Override**: IP blocking/unblocking with Redis risk management
- ✅ **Verification Complete**: All modules tested and functional
- ✅ **XAI Implementation**: SHAP explanations with force/waterfall plots

### **📊 Model Performance Summary**
| Model | Accuracy | Precision | Recall | F1-Score |
|--------|----------|-----------|---------|-----------|
| TCN | 99.14% | 98.70% | 97.29% | 97.99% |
| Autoencoder | 73.76% | 21.75% | 8.35% | 12.07% |
| IsolationForest | 73.08% | 30.19% | 18.94% | 23.28% |
| **Ensemble** | **98.54%** | **98.83%** | **94.36%** | **96.54%** |

## 🤝 Getting Help

### **📚 Resources**
- **Complete documentation**: docs/ folder
- **Technical details**: docs/TECHNICAL_DOCUMENTATION.md
- **Project evolution**: MODEL_IMPROVEMENT_TRACKER.md
- **Data flow**: INPUT_OUTPUT_FLOW.md

### **🎯 Quick Questions**
- **How does it work?** → Read INPUT_OUTPUT_FLOW.md
- **What are the models?** → Read docs/TECHNICAL_DOCUMENTATION.md
- **How to run it?** → Follow Quick Start above
- **How to improve it?** → Read MODEL_IMPROVEMENT_TRACKER.md

### **🔧 Technical Support**
- Check the troubleshooting section above
- Review the complete documentation
- Test with the provided evaluation scripts

## 🎉 Welcome to the Team!

### **🚀 Your ZeroTrust-AI system is:**
- **Production-ready** with 96.54% accuracy
- **Real-time capable** with live dashboard
- **Well-documented** with complete guides
- **Easily deployable** with Docker support

### **📊 Next Steps:**
1. **Read the documentation** (start with INPUT_OUTPUT_FLOW.md)
2. **Test the dashboard** (run websocket_server.py)
3. **Evaluate models** (run evaluate_models.py)
4. **Explore the code** (check services/detector/app/main.py)

**Welcome to ZeroTrust-AI! Your AI-powered network security system is ready to protect networks from threats!** 🛡️
