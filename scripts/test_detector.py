#!/usr/bin/env python3
"""
Test script to verify detector behavior with different traffic patterns.
Helps test multiple use cases: benign, ddos, scan.
"""

import requests
import json
import time

DETECTOR_URL = "http://192.168.137.222:9000/detect"  # Change to your detector laptop IP

def test_payload(name, payload):
    """Test a single payload and print results"""
    print(f"\n=== Testing {name.upper()} ===")
    try:
        response = requests.post(DETECTOR_URL, json=payload, headers={"Content-Type": "application/json"})
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Status: {response.status_code}")
            print(f"🏷️ Label: {data.get('label', 'N/A')}")
            
            # Handle confidence score safely
            confidence = data.get('confidence', 0)
            if confidence != 'N/A' and confidence is not None:
                print(f"📊 Confidence: {float(confidence):.3f}")
            else:
                print(f"📊 Confidence: N/A")
            
            # Handle anomaly score safely
            anomaly_score = data.get('anomaly_score', 0)
            if anomaly_score != 'N/A' and anomaly_score is not None:
                print(f"🎯 Anomaly Score: {float(anomaly_score):.3f}")
            else:
                print(f"🎯 Anomaly Score: N/A")
            
            print(f"🔍 Reason: {data.get('reason', [])}")
            print(f"🌐 Severity: {data.get('severity', 'N/A')}")
            
            # Handle metadata safely
            metadata = data.get('metadata', {})
            if isinstance(metadata, dict):
                splt_iso_score = metadata.get('splt_iso_score', 0)
                if splt_iso_score != 'N/A' and splt_iso_score is not None:
                    print(f"📋 SPLT ISO Score: {float(splt_iso_score):.3f}")
                else:
                    print(f"📋 SPLT ISO Score: N/A")
                
                # Print other metadata if available
                behavioral_hash = metadata.get('behavioral_hash', 'N/A')
                if behavioral_hash != 'N/A':
                    print(f"🔐 Behavioral Hash: {behavioral_hash}")
            else:
                print(f"📋 SPLT ISO Score: N/A")
                print(f"🔐 Behavioral Hash: N/A")
            
            # Add use case specific analysis
            print(f"\n📈 Use Case Analysis:")
            if data.get('label') == 'benign':
                print(f"   ✅ Normal traffic detected - low anomaly score")
            elif data.get('label') == 'malicious':
                print(f"   ⚠️  Anomalous traffic detected - high anomaly score")
                if 'splt_isoforest_anomalous' in data.get('reason', []):
                    print(f"   🎯 SPLT behavioral pattern flagged as suspicious")
                if 'known_malicious_pattern' in data.get('reason', []):
                    print(f"   🔥 Known malicious pattern detected")
            
        else:
            print(f"❌ Error: HTTP {response.status_code}")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ Exception: {e}")
    print("=" * 70)

def main():
    print("🚀 Zero-IP Detector Test Suite")
    print("Testing multiple traffic patterns against detector...\n")
    
    # Test 1: Truly benign traffic
    benign_payload = {
        "flow_id": "benign-test-1",
        "total_packets": 100,
        "total_bytes": 80000,
        "avg_packet_size": 800,
        "std_packet_size": 10,
        "duration": 4.0,
        "pps": 25,
        "avg_entropy": 4.0,
        "syn_count": 2,
        "fin_count": 1,
        "splt_len": [800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800, 800],
        "splt_iat": [0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040, 0.040]
    }
    
    # Test 2: DDoS-like traffic (high packets, burst pattern)
    ddos_payload = {
        "flow_id": "ddos-test-1",
        "total_packets": 500,
        "total_bytes": 250000,
        "avg_packet_size": 500,
        "std_packet_size": 100,
        "duration": 2.0,
        "pps": 250,
        "avg_entropy": 6.5,
        "syn_count": 50,
        "fin_count": 5,
        "splt_len": [1500, 1400, 1300, 1200, 1100, 1000, 900, 800, 700, 600, 500, 400, 300, 200, 150, 100, 80, 60, 40, 20, 10, 5],
        "splt_iat": [0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.010, 0.011, 0.012, 0.013, 0.014, 0.015, 0.016, 0.017, 0.018, 0.019, 0.020, 0.021, 0.022, 0.023, 0.024, 0.025, 0.026, 0.027, 0.028, 0.029, 0.030]
    }
    
    # Test 3: Scan-like traffic (port scan pattern)
    scan_payload = {
        "flow_id": "scan-test-1",
        "total_packets": 200,
        "total_bytes": 40000,
        "avg_packet_size": 200,
        "std_packet_size": 50,
        "duration": 10.0,
        "pps": 20,
        "avg_entropy": 5.5,
        "syn_count": 100,
        "fin_count": 20,
        "splt_len": [200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200],
        "splt_iat": [0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050, 0.050]
    }
    
    # Test 4: Your original sample (anomalous pattern)
    original_payload = {
        "flow_id": "test-1",
        "total_packets": 150,
        "total_bytes": 120000,
        "avg_packet_size": 800,
        "std_packet_size": 50,
        "duration": 1.2,
        "pps": 125,
        "avg_entropy": 4.2,
        "syn_count": 3,
        "fin_count": 1,
        "splt_len": [120, 115, 110, 105, 100, 95, 90, 85, 80, 75, 70, 65, 55, 45, 35, 25, 15],
        "splt_iat": [0.008, 0.009, 0.011, 0.012, 0.013, 0.015, 0.017, 0.019, 0.021, 0.023, 0.025, 0.027, 0.029, 0.031, 0.033, 0.035, 0.037, 0.039, 0.041, 0.043, 0.045]
    }
    
    # Run all tests
    test_payload("Benign (steady)", benign_payload)
    time.sleep(1)
    
    test_payload("DDoS (burst)", ddos_payload)
    time.sleep(1)
    
    test_payload("Scan (port)", scan_payload)
    time.sleep(1)
    
    test_payload("Original (anomalous)", original_payload)
    
    print(f"\n🎯 Test Complete! Check results above.")
    print("📋 Expected: Benign should be 'benign', DDoS/Scan/Original should be 'malicious'")

if __name__ == "__main__":
    main()
