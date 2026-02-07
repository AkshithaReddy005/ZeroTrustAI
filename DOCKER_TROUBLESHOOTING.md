# 🔧 Docker Troubleshooting Guide

## ❌ Common Docker Issues & Solutions

### **Issue 1: Docker Desktop Not Running**
**Error**: `unable to get image 'redis:7-alpine': error during connect`

**✅ Solutions:**
1. **Start Docker Desktop**
   - Open Docker Desktop from Start Menu
   - Wait for "Docker Desktop is running" message
   - Try again after 30 seconds

2. **Restart Docker Desktop**
   - Right-click Docker Desktop icon → Restart
   - Wait for full restart

3. **Check Docker Status**
   ```bash
   docker version
   docker info
   ```

### **Issue 2: Path Problems**
**Error**: `The system cannot find the path specified`

**✅ Solutions:**
1. **Make sure you're in correct directory**
   ```bash
   cd "c:\Users\akshi\OneDrive\Documents\AKKI\projects\ZeroTrust-AI"
   ```

2. **Check file exists**
   ```bash
   dir infra\docker-compose.yml
   ```

3. **Use correct command**
   ```bash
   docker compose -f infra/docker-compose.yml up -d
   ```

### **Issue 3: Port Conflicts**
**Error**: `Port 9000 is already in use`

**✅ Solutions:**
1. **Stop existing containers**
   ```bash
   docker compose -f infra/docker-compose.yml down
   ```

2. **Check what's using port**
   ```bash
   netstat -ano | findstr :9000
   ```

3. **Kill process using port**
   ```bash
   taskkill /PID <PID_NUMBER> /F
   ```

### **Issue 4: INFLUX_TOKEN Warning**
**Warning**: `The "INFLUX_TOKEN" variable is not set`

**✅ Solutions:**
1. **Ignore for now** - InfluxDB logging is optional
2. **Set token later** if you want historical logging:
   ```bash
   $env:INFLUX_TOKEN="your-token-here"
   ```

## 🚀 Quick Start Checklist

### **Before Running Docker:**
- [ ] Docker Desktop is running
- [ ] You're in project root directory
- [ ] No other services using ports 9000, 6379, 8086

### **Run Commands:**
```bash
# 1. Navigate to project
cd "c:\Users\akshi\OneDrive\Documents\AKKI\projects\ZeroTrust-AI"

# 2. Start services
docker compose -f infra/docker-compose.yml up -d

# 3. Check status
docker compose -f infra/docker-compose.yml ps
```

### **Expected Output:**
```
NAME            IMAGE          COMMAND                  SERVICE   CREATED          STATUS          PORTS
ztai_redis      redis:7-alpine "docker-entrypoint.s…"   redis      5 seconds ago    Up 4 seconds    0.0.0.0:6379->6379/tcp
ztai_influxdb   influxdb:2     "/entrypoint.sh infl…"   influxdb   5 seconds ago    Up 4 seconds    0.0.0.0:8086->8086/tcp
ztai_detector    zerotrust-ai_… "uvicorn app:main --…"   detector   5 seconds ago    Up 4 seconds    0.0.0.0:9000->9000/tcp
```

## 🎯 Success Indicators

### **✅ Everything Working When:**
- Docker Desktop shows running containers
- `docker compose ps` shows all services as "Up"
- `http://localhost:9000` loads the dashboard
- No error messages in terminal

### **🌐 Access Points:**
- **Main Dashboard**: http://localhost:9000
- **Redis**: localhost:6379 (if you need to connect)
- **InfluxDB**: http://localhost:8086 (if you need to access)

## 🆘 If Still Not Working

### **Step 1: Clean Everything**
```bash
docker compose -f infra/docker-compose.yml down
docker system prune -f
```

### **Step 2: Restart Docker Desktop**
- Close Docker Desktop completely
- Wait 10 seconds
- Restart Docker Desktop
- Wait for "Docker Desktop is running"

### **Step 3: Try Again**
```bash
docker compose -f infra/docker-compose.yml up -d
```

### **Step 4: Check Logs**
```bash
docker compose -f infra/docker-compose.yml logs
```

## 📞 Get Help

### **What to Share if You Need Help:**
1. **Docker Desktop status** (running/not running)
2. **Exact error message** you're seeing
3. **Output of**: `docker compose -f infra/docker-compose.yml ps`
4. **Output of**: `docker version`

### **Most Common Fix:**
90% of Docker issues are fixed by:
1. **Restarting Docker Desktop**
2. **Being in correct directory**
3. **Waiting 30 seconds after Docker starts**

**Your ZeroTrust-AI system will work once Docker is properly running!** 🚀
