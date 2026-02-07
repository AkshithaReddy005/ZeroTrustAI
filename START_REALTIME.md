# 🚀 ZeroTrust-AI Real-Time Dashboard Launch Guide

## 🎯 Quick Start Instructions

### **Step 1: Open Terminal**
- Press `Win + R` and type `cmd` or `powershell`
- Or open Command Prompt/PowerShell from Start Menu

### **Step 2: Navigate to Project**
```bash
cd "c:\Users\akshi\OneDrive\Documents\AKKI\projects\ZeroTrust-AI"
```

### **Step 3: Start WebSocket Server**
```bash
python services/detector/app/websocket_server.py
```

### **Step 4: Open Web Browser**
```
http://localhost:9000
```

## 🎨 What You'll See

### **🛡️ Professional Security Dashboard**
- Live threat detection feed
- Real-time metrics (flows, threats, blocked, accuracy)
- Interactive charts (timeline, severity distribution)
- Model performance monitoring
- One-click threat blocking

### **📊 Real-Time Features**
- Auto-refresh every second
- Color-coded severity levels
- WebSocket live updates
- Responsive design (mobile friendly)

## 🎮 Alternative: Demo with Simulated Threats

### **If You Want to See It in Action Immediately:**

#### **Step 1: Start WebSocket Server**
```bash
# Open Terminal 1
cd "c:\Users\akshi\OneDrive\Documents\AKKI\projects\ZeroTrust-AI"
python services/detector/app/websocket_server.py
```

#### **Step 2: Start Demo Script**
```bash
# Open Terminal 2 (new window)
cd "c:\Users\akshi\OneDrive\Documents\AKKI\projects\ZeroTrust-AI"
python demo_realtime.py
```

#### **Step 3: Watch the Magic**
```
Open browser: http://localhost:9000
You'll see:
- 🚨 Simulated threats appearing every 1-5 seconds
- 📊 Metrics updating in real-time
- 📈 Charts updating with new data
- 🎮 Interactive blocking working
```

## 🔧 Troubleshooting

### **If WebSocket Server Won't Start:**
```bash
# Check Python version (needs 3.7+)
python --version

# Check dependencies
pip install fastapi uvicorn websockets

# Check if port is available
netstat -an | findstr :9000
```

### **If Web Page Won't Load:**
```bash
# Check if server is running
curl http://localhost:9000

# Check browser console for errors
# Try different browser (Chrome, Firefox, Edge)
```

### **If No Threats Appear:**
```bash
# Run the demo script to generate test data
python demo_realtime.py

# Or check WebSocket connection in browser console
# Look for WebSocket connection status
```

## 🎯 Production Deployment

### **For Long-Running Use:**
```bash
# Use Docker for reliability
docker-compose -f docker-compose.web.yml up -d

# Access at:
http://localhost:9000 (main dashboard)
http://localhost:3000 (Grafana - optional)
```

## 📱 Mobile Access

### **From Other Devices:**
```
1. Ensure your firewall allows port 9000
2. Find your computer's IP address:
   ipconfig (Windows) or ifconfig (Linux/Mac)
3. Access from mobile: http://YOUR_IP:9000
```

## 🎉 Success Indicators

### **✅ Everything Working When You See:**
- WebSocket server starts without errors
- Web page loads at http://localhost:9000
- "Connected" status shows green
- Metrics appear in the header
- Threat feed shows (even if empty initially)

### **🚨 Live Threats When:**
- Demo script generates threats
- Real network traffic contains threats
- Threats appear in live feed
- Charts update automatically
- Block buttons work

## 🎯 Quick Commands Summary

```bash
# Start the magic:
cd "c:\Users\akshi\OneDrive\Documents\AKKI\projects\ZeroTrust-AI"
python services/detector/app/websocket_server.py

# In another terminal, generate demo threats:
python demo_realtime.py

# Open browser:
http://localhost:9000
```

Your ZeroTrust-AI real-time dashboard is ready to launch! 🚀
