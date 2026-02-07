# 🐳 Docker Quick Start Guide

## 🚀 Just 2 Commands to Run ZeroTrust-AI

### **Step 1: Install Docker**
- Install Docker Desktop from https://docker.com
- Restart your computer after installation

### **Step 2: Clone & Run**
```bash
git clone https://github.com/AkshithaReddy005/ZeroTrust-AI.git
cd ZeroTrust-AI
docker compose -f infra/docker-compose.yml up -d
```

### **Step 3: Open Dashboard**
```
http://localhost:9000
```

## 🎯 That's It! Your System is Running!

### **What You'll See:**
- 🛡️ **Real-time security dashboard**
- 🚨 **Live threat detection feed**
- 📊 **Model performance metrics**
- 📈 **Interactive charts**

### **📊 Additional Services (Optional):**
- **Grafana Analytics**: http://localhost:3000 (admin/admin123)
- **InfluxDB**: http://localhost:8086

## 🔧 Basic Docker Commands

### **Check Status**
```bash
docker compose -f infra/docker-compose.yml ps
```

### **View Logs**
```bash
docker compose -f infra/docker-compose.yml logs -f websocket-server
```

### **Stop Everything**
```bash
docker compose -f infra/docker-compose.yml down
```

### **Restart**
```bash
docker compose -f infra/docker-compose.yml up -d
```

## ❌ Troubleshooting

### **If Port 9000 is Busy:**
```bash
# Stop other services using port 9000
docker compose -f infra/docker-compose.yml down
# Then try again
docker compose -f infra/docker-compose.yml up -d
```

### **If Containers Won't Start:**
```bash
# Clean and rebuild
docker compose -f infra/docker-compose.yml down
docker system prune -f
docker compose -f infra/docker-compose.yml up --build -d
```

### **Check Everything is Working:**
```bash
# Should show all services as "Up"
docker compose -f infra/docker-compose.yml ps

# Should load the dashboard
curl http://localhost:9000
```

## 🎉 Success!

When you see the dashboard at http://localhost:9000, your ZeroTrust-AI system is fully operational!

**For demo data, run this in another terminal:**
```bash
python demo_realtime.py
```

That's all you need to run the complete AI-powered security system! 🛡️
