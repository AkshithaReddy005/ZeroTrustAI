#!/usr/bin/env python3
"""
Simplified Sandbox Analysis Module for SOAR Command Center
Handles file upload, static analysis, and sandbox execution
Works on Windows without external dependencies
"""

import os
import hashlib
from datetime import datetime
import json
import shutil
from pathlib import Path

class SandboxAnalyzer:
    def __init__(self):
        self.upload_dir = Path("sandbox/uploads")
        self.reports_dir = Path("sandbox/reports")
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Suspicious strings to check
        self.suspicious_strings = [
            "cmd.exe", "powershell.exe", "rundll32.exe", "wscript.exe",
            "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
            "netsh.exe", "tasklist.exe", "whoami.exe", "systeminfo",
            "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
            "SetWindowsHookEx", "GetAsyncKeyState", "keylogger",
            "bitcoin", "malware", "trojan", "backdoor", "rootkit",
            "http://", "https://", "ftp://", "tcp://"
        ]

    def calculate_entropy(self, file_path):
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # Calculate entropy
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy / 8.0  # Normalize to 0-8 range
        except:
            return 0.0

    def check_suspicious_strings(self, file_path):
        """Check for suspicious strings in file"""
        found_strings = []
        try:
            with open(file_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore').lower()
            
            for s in self.suspicious_strings:
                if s in content:
                    found_strings.append(s)
        except:
            pass
        
        return found_strings

    def get_file_info(self, file_path):
        """Get basic file information"""
        try:
            stat = os.stat(file_path)
            file_size = stat.st_size
            
            # Get extension
            extension = Path(file_path).suffix.lower()
            
            # Simple file type detection based on extension
            file_type_map = {
                '.exe': 'PE32 executable',
                '.dll': 'PE32 dynamic-link library',
                '.pdf': 'PDF document',
                '.doc': 'Microsoft Word document',
                '.docx': 'Microsoft Word document',
                '.xls': 'Microsoft Excel spreadsheet',
                '.xlsx': 'Microsoft Excel spreadsheet',
                '.txt': 'Text file',
                '.bat': 'Batch file',
                '.ps1': 'PowerShell script',
                '.py': 'Python script',
                '.js': 'JavaScript file'
            }
            
            file_type = file_type_map.get(extension, f'Unknown file ({extension})')
            
            return {
                "file_size": file_size,
                "file_type": file_type,
                "extension": extension,
                "created_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat()
            }
        except Exception as e:
            return {"error": str(e)}

    def static_analysis(self, file_path):
        """Perform static analysis on uploaded file"""
        result = {}
        
        # Get file info
        result["file_info"] = self.get_file_info(file_path)
        
        # Calculate entropy
        result["entropy"] = self.calculate_entropy(file_path)
        
        # Check if packed
        result["packed"] = result["entropy"] > 7.5
        
        # Check suspicious strings
        result["suspicious_strings"] = self.check_suspicious_strings(file_path)
        
        # Calculate file hash
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                result["sha256"] = hashlib.sha256(content).hexdigest()
                result["md5"] = hashlib.md5(content).hexdigest()
        except:
            result["sha256"] = "unknown"
            result["md5"] = "unknown"
        
        return result

    def sandbox_execute(self, file_path):
        """Simulate sandbox execution"""
        report = {}
        
        # Simulated behavior analysis
        static_result = self.static_analysis(file_path)
        
        # Simulate different behaviors based on file characteristics
        report["process_created"] = True
        report["registry_modified"] = static_result["packed"] or len(static_result["suspicious_strings"]) > 3
        report["network_connection"] = any("http" in s or "tcp" in s for s in static_result["suspicious_strings"])
        report["c2_attempt"] = any("bitcoin" in s or "malware" in s for s in static_result["suspicious_strings"])
        report["file_dropped"] = static_result["packed"]
        report["suspicious_api_calls"] = len(static_result["suspicious_strings"]) > 2
        
        # Calculate risk score
        risk_factors = [
            report["process_created"],
            report["registry_modified"],
            report["network_connection"],
            report["c2_attempt"],
            report["file_dropped"],
            report["suspicious_api_calls"],
            static_result["packed"],
            len(static_result["suspicious_strings"]) > 5
        ]
        
        risk_score = sum(risk_factors) * 12.5  # Each factor worth 12.5 points
        report["risk_score"] = min(100, risk_score)
        
        # Determine verdict
        if report["risk_score"] >= 80:
            report["verdict"] = "MALICIOUS"
        elif report["risk_score"] >= 60:
            report["verdict"] = "SUSPICIOUS"
        else:
            report["verdict"] = "CLEAN"
        
        # Recommended action
        if report["verdict"] == "MALICIOUS":
            report["action"] = "BLOCK & ALERT"
        elif report["verdict"] == "SUSPICIOUS":
            report["action"] = "MONITOR & QUARANTINE"
        else:
            report["action"] = "ALLOW"
        
        return report

    def analyze_file(self, uploaded_file, filename):
        """Complete file analysis workflow"""
        try:
            # Save uploaded file
            file_path = self.upload_dir / filename
            with open(file_path, 'wb') as f:
                f.write(uploaded_file)
            
            # Perform static analysis
            static_result = self.static_analysis(file_path)
            
            # Perform sandbox execution
            sandbox_result = self.sandbox_execute(file_path)
            
            # Combine results
            analysis_report = {
                "filename": filename,
                "timestamp": datetime.now().isoformat(),
                "static_analysis": static_result,
                "sandbox_analysis": sandbox_result,
                "file_path": str(file_path)
            }
            
            # Save report
            report_path = self.reports_dir / f"{filename}_report.json"
            with open(report_path, 'w') as f:
                json.dump(analysis_report, f, indent=2)
            
            return analysis_report
            
        except Exception as e:
            return {"error": str(e)}

# FastAPI endpoints for sandbox
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="SOAR Sandbox Analysis", version="1.0.0")
analyzer = SandboxAnalyzer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/sandbox", response_class=HTMLResponse)
async def sandbox_ui():
    """Serve sandbox analysis UI"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOAR Sandbox Analysis</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    </head>
    <body class="bg-gray-900 text-white">
        <div class="container mx-auto p-6">
            <h1 class="text-3xl font-bold mb-8 text-center">
                <i class="fas fa-shield-virus"></i> SOAR Sandbox Analysis
            </h1>
            
            <!-- File Upload Section -->
            <div class="bg-gray-800 rounded-lg p-6 mb-8">
                <h2 class="text-xl font-semibold mb-4">
                    <i class="fas fa-upload"></i> Upload Suspicious File
                </h2>
                <div class="border-2 border-dashed border-gray-600 rounded-lg p-8 text-center">
                    <input type="file" id="fileInput" class="hidden" />
                    <label for="fileInput" class="cursor-pointer">
                        <i class="fas fa-cloud-upload-alt text-4xl text-blue-400 mb-4"></i>
                        <p class="text-lg">Click to upload or drag and drop</p>
                        <p class="text-sm text-gray-400">Supports EXE, DLL, PDF, DOC, etc.</p>
                    </label>
                </div>
                <button onclick="uploadFile()" class="mt-4 bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded-lg">
                    <i class="fas fa-play"></i> Analyze File
                </button>
            </div>
            
            <!-- Analysis Results -->
            <div id="results" class="hidden">
                <!-- Static Analysis -->
                <div class="bg-gray-800 rounded-lg p-6 mb-6">
                    <h3 class="text-xl font-semibold mb-4">
                        <i class="fas fa-search"></i> Static Analysis
                    </h3>
                    <div id="staticResults"></div>
                </div>
                
                <!-- Sandbox Analysis -->
                <div class="bg-gray-800 rounded-lg p-6 mb-6">
                    <h3 class="text-xl font-semibold mb-4">
                        <i class="fas fa-vial"></i> Sandbox Analysis
                    </h3>
                    <div id="sandboxResults"></div>
                </div>
                
                <!-- Final Report -->
                <div id="finalReport" class="bg-gray-800 rounded-lg p-6">
                    <h3 class="text-xl font-semibold mb-4">
                        <i class="fas fa-file-alt"></i> Analysis Report
                    </h3>
                    <div id="reportContent"></div>
                </div>
            </div>
        </div>
        
        <script>
            async function uploadFile() {
                const fileInput = document.getElementById('fileInput');
                const file = fileInput.files[0];
                
                if (!file) {
                    alert('Please select a file first');
                    return;
                }
                
                const formData = new FormData();
                formData.append('file', file);
                
                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const result = await response.json();
                    displayResults(result);
                } catch (error) {
                    console.error('Error:', error);
                    alert('Analysis failed');
                }
            }
            
            function displayResults(result) {
                document.getElementById('results').classList.remove('hidden');
                
                // Static Analysis
                const staticHtml = `
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <span class="text-gray-400">File Type:</span>
                            <span class="ml-2">${result.static_analysis.file_info.file_type}</span>
                        </div>
                        <div>
                            <span class="text-gray-400">File Size:</span>
                            <span class="ml-2">${result.static_analysis.file_info.file_size} bytes</span>
                        </div>
                        <div>
                            <span class="text-gray-400">Entropy:</span>
                            <span class="ml-2 ${result.static_analysis.entropy > 7.5 ? 'text-red-400' : 'text-green-400'}">
                                ${result.static_analysis.entropy.toFixed(2)}
                            </span>
                        </div>
                        <div>
                            <span class="text-gray-400">Packed:</span>
                            <span class="ml-2 ${result.static_analysis.packed ? 'text-red-400' : 'text-green-400'}">
                                ${result.static_analysis.packed ? 'YES' : 'NO'}
                            </span>
                        </div>
                    </div>
                    <div class="mt-4">
                        <span class="text-gray-400">Suspicious Strings:</span>
                        <div class="mt-2">
                            ${result.static_analysis.suspicious_strings.map(s => 
                                `<span class="bg-red-600 px-2 py-1 rounded text-sm mr-2">${s}</span>`
                            ).join('')}
                        </div>
                    </div>
                `;
                document.getElementById('staticResults').innerHTML = staticHtml;
                
                // Sandbox Analysis
                const sandboxHtml = `
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <span class="text-gray-400">Process Created:</span>
                            <span class="ml-2 ${result.sandbox_analysis.process_created ? 'text-red-400' : 'text-green-400'}">
                                ${result.sandbox_analysis.process_created ? 'YES' : 'NO'}
                            </span>
                        </div>
                        <div>
                            <span class="text-gray-400">Registry Modified:</span>
                            <span class="ml-2 ${result.sandbox_analysis.registry_modified ? 'text-red-400' : 'text-green-400'}">
                                ${result.sandbox_analysis.registry_modified ? 'YES' : 'NO'}
                            </span>
                        </div>
                        <div>
                            <span class="text-gray-400">Network Connection:</span>
                            <span class="ml-2 ${result.sandbox_analysis.network_connection ? 'text-red-400' : 'text-green-400'}">
                                ${result.sandbox_analysis.network_connection ? 'YES' : 'NO'}
                            </span>
                        </div>
                        <div>
                            <span class="text-gray-400">C2 Attempt:</span>
                            <span class="ml-2 ${result.sandbox_analysis.c2_attempt ? 'text-red-400' : 'text-green-400'}">
                                ${result.sandbox_analysis.c2_attempt ? 'YES' : 'NO'}
                            </span>
                        </div>
                        <div>
                            <span class="text-gray-400">File Dropped:</span>
                            <span class="ml-2 ${result.sandbox_analysis.file_dropped ? 'text-red-400' : 'text-green-400'}">
                                ${result.sandbox_analysis.file_dropped ? 'YES' : 'NO'}
                            </span>
                        </div>
                        <div>
                            <span class="text-gray-400">Suspicious API Calls:</span>
                            <span class="ml-2 ${result.sandbox_analysis.suspicious_api_calls ? 'text-red-400' : 'text-green-400'}">
                                ${result.sandbox_analysis.suspicious_api_calls ? 'YES' : 'NO'}
                            </span>
                        </div>
                    </div>
                `;
                document.getElementById('sandboxResults').innerHTML = sandboxHtml;
                
                // Final Report
                const verdictColor = result.sandbox_analysis.verdict === 'MALICIOUS' ? 'text-red-400' : 
                                   result.sandbox_analysis.verdict === 'SUSPICIOUS' ? 'text-yellow-400' : 'text-green-400';
                
                const reportHtml = `
                    <div class="text-center">
                        <div class="mb-6">
                            <span class="text-gray-400">Final Risk Score:</span>
                            <span class="text-3xl font-bold ml-2 ${verdictColor}">
                                ${result.sandbox_analysis.risk_score}/100
                            </span>
                        </div>
                        <div class="mb-6">
                            <span class="text-gray-400">Verdict:</span>
                            <span class="text-2xl font-bold ml-2 ${verdictColor}">
                                ${result.sandbox_analysis.verdict}
                            </span>
                        </div>
                        <div class="mb-6">
                            <span class="text-gray-400">Action Taken:</span>
                            <span class="text-xl font-bold ml-2 text-blue-400">
                                ${result.sandbox_analysis.action}
                            </span>
                        </div>
                        <div class="mt-8">
                            <span class="text-gray-400">SHA256:</span>
                            <span class="text-sm ml-2 font-mono">${result.static_analysis.sha256}</span>
                        </div>
                    </div>
                `;
                document.getElementById('reportContent').innerHTML = reportHtml;
            }
        </script>
    </body>
    </html>
    """

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """Analyze uploaded file"""
    try:
        content = await file.read()
        filename = file.filename or "unknown_file"
        result = analyzer.analyze_file(content, filename)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

if __name__ == "__main__":
    print("🧪 SOAR Sandbox Analyzer Starting...")
    print("📂 Upload directory: sandbox/uploads")
    print("📄 Reports directory: sandbox/reports")
    print("🌐 Server: http://localhost:8001")
    print("🔗 API: http://localhost:8001/analyze")
    uvicorn.run(app, host="0.0.0.0", port=8001)
