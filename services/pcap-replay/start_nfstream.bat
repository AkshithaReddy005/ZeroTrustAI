@echo off
REM NFStream Real-time PCAP Processor Startup Script (Windows)
REM This script starts the complete nfstream-based flow processing system

echo 🚀 Starting ZeroTrust-AI NFStream Real-time Flow Processor
echo ==========================================================

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

REM Create data directories if they don't exist
if not exist "data" mkdir data
if not exist "data\raw" mkdir data\raw
if not exist "data\processed" mkdir data\processed

echo 📁 Data directories created/verified

REM Check if there are PCAP files in data/raw
dir /b data\raw\*.pcap data\raw\*.pcapng >nul 2>&1
if errorlevel 1 (
    echo ⚠️  No PCAP files found in data\raw directory
    echo    Please add PCAP files to data\raw directory for processing
    echo    Example: copy your-pcap-file.pcap data\raw\
) else (
    echo 📊 PCAP files found in data\raw directory
)

echo.
echo 🔧 Configuration:
echo    - WebSocket Server: http://localhost:9000
echo    - Dashboard: http://localhost:9000
echo    - Throttle: 100ms between flows
echo    - Demo Mode: Enabled
echo.

REM Start the services
echo 🔄 Starting NFStream services...
docker-compose -f docker-compose.nfstream.yml up --build

echo.
echo ✅ Services stopped
echo.
echo 📊 To view the dashboard:
echo    Open http://localhost:9000 in your browser
echo.
echo 📝 To add more PCAP files:
echo    Copy .pcap or .pcapng files to data\raw\
echo    The system will automatically detect and process them
echo.
echo 🛠️  To check logs:
echo    docker-compose -f docker-compose.nfstream.yml logs -f

pause
