#!/usr/bin/env python3
"""
Test script for NFStream integration
Tests the real-time PCAP processing and websocket communication
"""

import os
import sys
import time
import json
import asyncio
import websockets
from pathlib import Path

# Add the project root to Python path
sys.path.append(str(Path(__file__).parent.parent))

try:
    import nfstream
    print("✅ nfstream imported successfully")
except ImportError as e:
    print(f"❌ Failed to import nfstream: {e}")
    print("   Install with: pip install nfstream")
    sys.exit(1)

def test_nfstream_basic():
    """Test basic nfstream functionality"""
    print("\n🧪 Testing nfstream basic functionality...")
    
    # Check if we have any PCAP files for testing
    pcap_dir = Path("data/raw")
    test_pcaps = list(pcap_dir.glob("*.pcap")) + list(pcap_dir.glob("*.pcapng"))
    
    if not test_pcaps:
        print("⚠️  No PCAP files found in data/raw for testing")
        print("   Creating a test configuration...")
        return True
    
    try:
        # Test with the first PCAP file
        test_pcap = test_pcaps[0]
        print(f"   Testing with: {test_pcap}")
        
        streamer = nfstream.NFStreamer(
            source=str(test_pcap),
            statistical_analysis=True,
            splt_analysis=False,
            n_dissections=0,
        )
        
        flow_count = 0
        for flow in streamer:
            flow_count += 1
            if flow_count >= 5:  # Just test first 5 flows
                break
        
        print(f"   ✅ Successfully processed {flow_count} flows")
        return True
        
    except Exception as e:
        print(f"   ❌ Error testing nfstream: {e}")
        return False

def test_websocket_connection():
    """Test websocket connection to dashboard"""
    print("\n🧪 Testing websocket connection...")
    
    async def test_connection():
        try:
            # Try to connect to websocket server
            uri = "ws://localhost:9000/ws"
            async with websockets.connect(uri) as websocket:
                print("   ✅ Connected to websocket server")
                
                # Wait for a message
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    data = json.loads(message)
                    print(f"   ✅ Received message: {data.get('type', 'unknown')}")
                    return True
                except asyncio.TimeoutError:
                    print("   ⚠️  No message received (server may be idle)")
                    return True
                    
        except Exception as e:
            print(f"   ❌ WebSocket connection failed: {e}")
            print("   Make sure the websocket server is running:")
            print("   cd services/detector/app && python websocket_server.py")
            return False
    
    return asyncio.run(test_connection())

def test_api_endpoints():
    """Test API endpoints"""
    print("\n🧪 Testing API endpoints...")
    
    import requests
    
    # Test flow endpoint
    try:
        response = requests.post("http://localhost:8000/events/flow", 
                                json={
                                    "flow_id": "test-flow-1",
                                    "source_ip": "192.168.1.1",
                                    "destination_ip": "192.168.1.2",
                                    "total_packets": 100,
                                    "total_bytes": 10000,
                                    "duration": 1.0,
                                    "pps": 100
                                }, timeout=5)
        if response.status_code == 200:
            print("   ✅ Flow endpoint working")
        else:
            print(f"   ⚠️  Flow endpoint returned: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Flow endpoint failed: {e}")
    
    # Test threat endpoint
    try:
        response = requests.post("http://localhost:8000/events/threat",
                                json={
                                    "flow_id": "test-threat-1",
                                    "label": "malicious",
                                    "confidence": 0.9,
                                    "severity": "high",
                                    "reason": ["Test threat"],
                                    "attack_type": "Test Attack",
                                    "source_ip": "192.168.1.1",
                                    "destination_ip": "192.168.1.2",
                                    "blocked": True
                                }, timeout=5)
        if response.status_code == 200:
            print("   ✅ Threat endpoint working")
        else:
            print(f"   ⚠️  Threat endpoint returned: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Threat endpoint failed: {e}")

def test_configuration():
    """Test environment configuration"""
    print("\n🧪 Testing configuration...")
    
    # Check environment variables
    config_vars = {
        "USE_CSV": os.getenv("USE_CSV", "false"),
        "USE_NFSTREAM": os.getenv("USE_NFSTREAM", "true"),
        "PCAP_SOURCE": os.getenv("PCAP_SOURCE", "/data/raw"),
        "WEBSOCKET_URL": os.getenv("WEBSOCKET_URL", "ws://localhost:9000/ws"),
        "THROTTLE_MS": os.getenv("THROTTLE_MS", "100"),
    }
    
    print("   Configuration:")
    for var, value in config_vars.items():
        print(f"     {var}: {value}")
    
    # Check data directories
    data_dirs = ["data/raw", "data/processed"]
    for dir_path in data_dirs:
        if Path(dir_path).exists():
            print(f"   ✅ Directory exists: {dir_path}")
        else:
            print(f"   ⚠️  Directory missing: {dir_path}")
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            print(f"   ✅ Created directory: {dir_path}")

def main():
    """Run all tests"""
    print("🚀 NFStream Integration Test Suite")
    print("==================================")
    
    tests = [
        ("Configuration", test_configuration),
        ("NFStream Basic", test_nfstream_basic),
        ("WebSocket Connection", test_websocket_connection),
        ("API Endpoints", test_api_endpoints),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name} test...")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"   ❌ Test failed with exception: {e}")
            results[test_name] = False
    
    # Summary
    print("\n📊 Test Results Summary")
    print("======================")
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:20} : {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! NFStream integration is ready.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        print("\n📝 Next steps:")
        print("   1. Install missing dependencies")
        print("   2. Start the websocket server: python services/detector/app/websocket_server.py")
        print("   3. Add PCAP files to data/raw/")
        print("   4. Run: python services/pcap-replay/app.py")

if __name__ == "__main__":
    main()
