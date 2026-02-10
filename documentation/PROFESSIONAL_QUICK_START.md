# ZeroTrust-AI Professional Quick Start Guide

---

## 🚀 **PROFESSIONAL ARCHITECTURE DEPLOYMENT**

### **🎯 Overview**
Deploy the complete ZeroTrust-AI Professional Architecture with Adaptive Risk Scoring (Redis) and Behavioral Drift Analysis (InfluxDB).

---

## 📋 **PREREQUISITES**

### **🔧 System Requirements**
- **CPU**: 4+ cores recommended
- **Memory**: 8GB+ RAM recommended
- **Storage**: 50GB+ available space
- **OS**: Linux/macOS/Windows with Docker
- **Docker**: Version 20.10+ and Docker Compose

### **📦 Required Software**
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
pip install docker-compose

# Verify installation
docker --version
docker-compose --version
```

---

## 🚀 **QUICK DEPLOYMENT**

### **🎯 Step 1: Clone Repository**
```bash
git clone https://github.com/AkshithaReddy005/ZeroTrust-AI.git
cd ZeroTrust-AI
```

### **🎯 Step 2: Environment Configuration**
```bash
# Copy environment template
cp .env.example .env.professional

# Edit configuration
nano .env.professional
```

**Environment Variables (.env.professional):**
```bash
# InfluxDB Configuration
INFLUX_TOKEN=your-super-secure-token-here
INFLUX_PASSWORD=your-strong-password-here
GRAFANA_PASSWORD=admin123

# SOAR Integration (Optional)
FIREWALL_API_URL=https://your-firewall.com/api/block
SIEM_API_URL=https://your-siem.com/api/alert
TICKET_SYSTEM_URL=https://your-ticket-system.com/api/ticket
NOTIFICATION_WEBHOOK=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Traffic Simulation
FLOW_RATE=10
THREAT_RATE=0.1
```

### **🎯 Step 3: Deploy Professional Architecture**
```bash
# Deploy all services
docker-compose -f infra/docker-compose.professional.yml up -d

# Check deployment status
docker-compose -f infra/docker-compose.professional.yml ps
```

### **🎯 Step 4: Initialize InfluxDB**
```bash
# Wait for InfluxDB to start (30 seconds)
sleep 30

# Initialize InfluxDB (automatic with Docker setup)
# Check: http://localhost:8086
# Username: admin
# Password: from .env.professional
```

---

## 🌐 **ACCESSING SERVICES**

### **🛡️ Professional Dashboard**
- **URL**: http://localhost:8501
- **Features**: Real-time threat heatmap, behavioral drift analysis
- **Login**: No authentication required

### **🔍 API Gateway**
- **URL**: http://localhost:8080
- **Docs**: http://localhost:8080/docs
- **Purpose**: Central API entry point

### **🚨 SOAR Engine**
- **URL**: http://localhost:8001
- **Docs**: http://localhost:8001/docs
- **Purpose**: Security orchestration and response

### **📊 Detector Service**
- **URL**: http://localhost:8000
- **Docs**: http://localhost:8000/docs
- **Purpose**: AI threat detection

### **🗃️ Management Tools**
- **Redis Commander**: http://localhost:8081
- **Grafana**: http://localhost:3000 (admin/admin123)
- **InfluxDB**: http://localhost:8086

---

## 🧪 **TESTING THE SYSTEM**

### **🎯 Step 1: Send Test Traffic**
```bash
# Simulate network traffic
curl -X POST http://localhost:8080/detect \
  -H "Content-Type: application/json" \
  -d '{
    "flow_id": "test-flow-001",
    "total_packets": 150,
    "total_bytes": 85000,
    "avg_packet_size": 566.7,
    "std_packet_size": 45.2,
    "duration": 2.5,
    "pps": 60.0,
    "avg_entropy": 3.2,
    "syn_count": 3,
    "fin_count": 1,
    "src_ip": "192.168.1.100"
  }'
```

### **🎯 Step 2: Check Risk Score in Redis**
```bash
# Access Redis Commander
# URL: http://localhost:8081
# View: risk_score:192.168.1.100

# Or use Redis CLI
docker exec -it zerotrust-redis redis-cli
GET risk_score:192.168.1.100
```

### **🎯 Step 3: View Threat in Dashboard**
1. Open http://localhost:8501
2. Check "Active Threats" metric
3. View "Threat Heatmap" for IP 192.168.1.100
4. Monitor "Behavioral Drift" charts

### **🎯 Step 4: Trigger Auto-Block**
```bash
# Send multiple suspicious flows to accumulate risk
for i in {1..10}; do
  curl -X POST http://localhost:8080/detect \
    -H "Content-Type: application/json" \
    -d "{
      \"flow_id\": \"test-flow-$(date +%s)\",
      \"total_packets\": 1000,
      \"total_bytes\": 500000,
      \"avg_packet_size\": 500,
      \"std_packet_size\": 100,
      \"duration\": 1.0,
      \"pps\": 1000,
      \"avg_entropy\": 7.5,
      \"syn_count\": 50,
      \"fin_count\": 0,
      \"src_ip\": \"192.168.1.200\"
    }"
  sleep 1
done
```

### **🎯 Step 5: Check SOAR Response**
```bash
# Check active blocks
curl http://localhost:8001/blocks

# Check SOAR status
curl http://localhost:8001/status
```

---

## 📊 **MONITORING DASHBOARD**

### **🔥 Key Metrics to Watch**
1. **Active Threats**: Number of currently tracked threats
2. **High-Risk IPs**: IPs with risk score 50-79
3. **Auto-Blocked IPs**: IPs automatically blocked (risk ≥80)
4. **Average Entropy**: Network entropy baseline

### **📈 Behavioral Analysis**
1. **Threat Heatmap**: Risk intensity by IP and attack type
2. **Entropy Trends**: Network entropy over time
3. **Risk Score Trends**: Risk accumulation patterns
4. **Correlation Analysis**: Entropy vs Risk correlation

### **🚨 Alert Thresholds**
- **Risk Score ≥80**: Auto-block triggers SOAR response
- **Entropy Spike**: Indicates large-scale attack
- **Multiple High-Risk IPs**: Suggests attack campaign

---

## 🔧 **ADVANCED CONFIGURATION**

### **⚙️ Risk Scoring Tuning**
```python
# In detector service, adjust risk increment
risk_increment = int(confidence_score * 100)  # 0-100 scale

# Adjust risk threshold
if current_risk >= 80:  # Lower for more aggressive blocking
    trigger_soar_block()
```

### **⏰ Risk Decay Configuration**
```python
# In detector service, adjust TTL
REDIS_CLIENT.expire(f"risk_score:{src_ip}", 1800)  # 30 minutes

# For longer memory:
REDIS_CLIENT.expire(f"risk_score:{src_ip}", 7200)  # 2 hours
```

### **🎯 SOAR Escalation Levels**
```python
# In SOAR service, adjust thresholds
ESCALATION_THRESHOLD = 95  # Critical level
BLOCK_DURATION_HOURS = 24   # Block duration
```

---

## 🛠️ **TROUBLESHOOTING**

### **🔍 Common Issues**

#### **Services Not Starting**
```bash
# Check logs
docker-compose -f infra/docker-compose.professional.yml logs detector
docker-compose -f infra/docker-compose.professional.yml logs redis
docker-compose -f infra/docker-compose.professional.yml logs influxdb

# Restart services
docker-compose -f infra/docker-compose.professional.yml restart
```

#### **Redis Connection Issues**
```bash
# Check Redis status
docker exec -it zerotrust-redis redis-cli ping

# Check Redis logs
docker logs zerotrust-redis
```

#### **InfluxDB Connection Issues**
```bash
# Check InfluxDB status
curl http://localhost:8086/health

# Check InfluxDB logs
docker logs zerotrust-influxdb
```

#### **Dashboard Not Showing Data**
```bash
# Check if data is being written to InfluxDB
curl -G "http://localhost:8086/api/v2/query" \
  -H "Authorization: Token your-token" \
  --data-urlencode "org=zerotrust" \
  --data-urlencode 'query=from(bucket:"threat_events") |> range(start:-1h)'
```

### **🔧 Performance Tuning**

#### **High Memory Usage**
```bash
# Check Redis memory usage
docker exec -it zerotrust-redis redis-cli info memory

# Adjust Redis maxmemory in redis.conf
maxmemory 1gb  # Reduce if needed
```

#### **Slow Dashboard Updates**
```bash
# Check InfluxDB query performance
# Optimize queries in dashboard code
# Add indexes to frequently queried fields
```

---

## 📚 **NEXT STEPS**

### **🎯 Production Deployment**
1. **Security**: Enable authentication and TLS
2. **Monitoring**: Set up alerts and notifications
3. **Backup**: Configure data backup strategies
4. **Scaling**: Add load balancers and clustering

### **🔧 Customization**
1. **Models**: Train custom models for your environment
2. **Thresholds**: Adjust risk scores based on traffic patterns
3. **Integrations**: Connect to your existing security tools
4. **Dashboard**: Create custom visualizations

### **📊 Advanced Features**
1. **Machine Learning**: Implement adaptive threshold learning
2. **Threat Intelligence**: Integrate external threat feeds
3. **User Behavior**: Add user and entity behavior analytics
4. **Compliance**: Implement regulatory reporting

---

## 🆘 **SUPPORT**

### **📖 Documentation**
- **Professional Architecture**: [PROFESSIONAL_ARCHITECTURE.md](PROFESSIONAL_ARCHITECTURE.md)
- **Model Improvement Tracker**: [MODEL_IMPROVEMENT_TRACKER.md](MODEL_IMPROVEMENT_TRACKER.md)
- **Technical Documentation**: [TECHNICAL_DOCUMENTATION.md](TECHNICAL_DOCUMENTATION.md)

### **🐛 Issue Reporting**
- **GitHub**: https://github.com/AkshithaReddy005/ZeroTrust-AI/issues
- **Logs**: Check container logs for troubleshooting
- **Community**: Join discussions for support

---

## 🎉 **SUCCESS!**

**🛡️ Your ZeroTrust-AI Professional Architecture is now running!**

- **Dashboard**: http://localhost:8501
- **API Gateway**: http://localhost:8080
- **SOAR Engine**: http://localhost:8001
- **Management**: http://localhost:8081 (Redis), http://localhost:3000 (Grafana)

**🚀 You now have:**
- ✅ Adaptive Risk Scoring Engine (Redis)
- ✅ Behavioral Drift Analysis (InfluxDB)
- ✅ Professional SOAR Integration
- ✅ Real-time Threat Dashboard
- ✅ Automated Response System

**🎯 Start monitoring your network security like a pro!**

---

*Last Updated: 2024-02-09*  
*Version: Professional Architecture 2.0*  
*Status: Production Ready*
