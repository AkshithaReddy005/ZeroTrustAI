#!/bin/bash

# NFStream Real-time PCAP Processor Startup Script
# This script starts the complete nfstream-based flow processing system

echo "🚀 Starting ZeroTrust-AI NFStream Real-time Flow Processor"
echo "=========================================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create data directories if they don't exist
mkdir -p data/raw data/processed

echo "📁 Data directories created/verified"

# Check if there are PCAP files in data/raw
PCAP_COUNT=$(find data/raw -name "*.pcap" -o -name "*.pcapng" | wc -l)
if [ $PCAP_COUNT -eq 0 ]; then
    echo "⚠️  No PCAP files found in data/raw directory"
    echo "   Please add PCAP files to data/raw directory for processing"
    echo "   Example: cp your-pcap-file.pcap data/raw/"
else
    echo "📊 Found $PCAP_COUNT PCAP file(s) in data/raw"
fi

echo ""
echo "🔧 Configuration:"
echo "   - WebSocket Server: http://localhost:9000"
echo "   - Dashboard: http://localhost:9000"
echo "   - Throttle: 100ms between flows"
echo "   - Demo Mode: Enabled"
echo ""

# Start the services
echo "🔄 Starting NFStream services..."
docker-compose -f docker-compose.nfstream.yml up --build

echo ""
echo "✅ Services stopped"
echo ""
echo "📊 To view the dashboard:"
echo "   Open http://localhost:9000 in your browser"
echo ""
echo "📝 To add more PCAP files:"
echo "   Copy .pcap or .pcapng files to data/raw/"
echo "   The system will automatically detect and process them"
echo ""
echo "🛠️  To check logs:"
echo "   docker-compose -f docker-compose.nfstream.yml logs -f"
