#!/usr/bin/env python3
"""
ZeroTrust-AI SOAR Demo
Demonstrates manual override capabilities for IP blocking/unblocking
"""

import requests
import time
import json
from datetime import datetime

# Configuration
DETECTOR_URL = "http://localhost:9000"
SOAR_BASE_URL = f"{DETECTOR_URL}/soar"

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'='*60}")
    print(f"🔧 {title}")
    print('='*60)

def print_response(response, description):
    """Print formatted API response"""
    print(f"\n📋 {description}:")
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=2))
    else:
        print(f"❌ Error {response.status_code}: {response.text}")

def check_service_health():
    """Check if the detector service is running"""
    try:
        response = requests.get(f"{DETECTOR_URL}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Detector service is running")
            return True
        else:
            print(f"❌ Detector service returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to detector service: {e}")
        return False

def generate_malicious_flow(ip_address: str):
    """Generate a malicious flow to create risk data"""
    return {
        "flow_id": f"test_flow_{ip_address}_{int(time.time())}",
        "src_ip": ip_address,
        "dst_ip": "10.0.0.1",
        "src_port": 45678,
        "dst_port": 443,
        "protocol": "TCP",
        "total_packets": 1247,
        "total_bytes": 85000,
        "avg_packet_size": 68.2,
        "std_packet_size": 15.3,
        "duration": 15.3,
        "pps": 81.5,
        "avg_entropy": 6.8,  # High entropy for malicious
        "syn_count": 10,     # Many SYNs for suspicious
        "fin_count": 0,
        # Add SPLT sequences to trigger advanced models
        "packet_lengths": [1500, 1200, 1500, 64, 1500, 1200, 1500, 64, 1500, 1200] * 2,
        "inter_arrival_times": [0.001, 0.005, 0.002, 0.01, 0.001, 0.005, 0.002, 0.01, 0.001, 0.005] * 2
    }

def create_risk_data(ip_address: str):
    """Create risk data for an IP by sending malicious flow"""
    print_section(f"Creating Risk Data for {ip_address}")
    
    flow = generate_malicious_flow(ip_address)
    
    try:
        response = requests.post(f"{DETECTOR_URL}/detect", json=flow, timeout=10)
        print_response(response, "Detection Result")
        
        if response.status_code == 200:
            result = response.json()
            if result.get("label") == "malicious":
                print(f"✅ Successfully created malicious risk data for {ip_address}")
                return True
            else:
                print(f"⚠️  Flow was classified as benign, trying again...")
                # Try with more suspicious parameters
                flow["avg_entropy"] = 7.5
                flow["syn_count"] = 20
                response = requests.post(f"{DETECTOR_URL}/detect", json=flow, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    if result.get("label") == "malicious":
                        print(f"✅ Successfully created malicious risk data for {ip_address}")
                        return True
        
        print(f"❌ Could not create risk data for {ip_address}")
        return False
        
    except Exception as e:
        print(f"❌ Error creating risk data: {e}")
        return False

def check_ip_risk(ip_address: str):
    """Check current risk status of an IP"""
    try:
        response = requests.get(f"{SOAR_BASE_URL}/risk/{ip_address}", timeout=5)
        print_response(response, f"Risk Status for {ip_address}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error checking IP risk: {e}")
        return False

def block_ip(ip_address: str, reason: str = "Manual SOAR demonstration"):
    """Block an IP address"""
    print_section(f"Blocking IP: {ip_address}")
    
    block_data = {
        "ip_address": ip_address,
        "reason": reason,
        "duration_hours": 24,
        "blocked_by": "SOAR_demo"
    }
    
    try:
        response = requests.post(f"{SOAR_BASE_URL}/block", json=block_data, timeout=5)
        print_response(response, "Block IP Response")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error blocking IP: {e}")
        return False

def unblock_ip(ip_address: str):
    """Unblock an IP address"""
    print_section(f"Unblocking IP: {ip_address}")
    
    unblock_data = {
        "ip_address": ip_address,
        "unblocked_by": "SOAR_demo"
    }
    
    try:
        response = requests.post(f"{SOAR_BASE_URL}/unblock", json=unblock_data, timeout=5)
        print_response(response, "Unblock IP Response")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error unblocking IP: {e}")
        return False

def list_blocked_ips():
    """List all currently blocked IPs"""
    print_section("Currently Blocked IPs")
    
    try:
        response = requests.get(f"{SOAR_BASE_URL}/blocked", timeout=5)
        print_response(response, "Blocked IPs List")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error listing blocked IPs: {e}")
        return False

def get_blocked_ip_details(ip_address: str):
    """Get detailed information about a blocked IP"""
    try:
        response = requests.get(f"{SOAR_BASE_URL}/blocked/{ip_address}", timeout=5)
        print_response(response, f"Blocked IP Details for {ip_address}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error getting blocked IP details: {e}")
        return False

def main():
    """Run the complete SOAR demonstration"""
    print("🚀 ZeroTrust-AI SOAR (Security Orchestration, Automation, and Response) Demo")
    print("📋 This demonstrates manual override capabilities for IP blocking/unblocking")
    print("🌐 Make sure the detector service is running on http://localhost:9000")
    print("⚠️  Press Ctrl+C to stop at any time")
    
    # Check if service is running
    if not check_service_health():
        print("\n❌ Please start the detector service first:")
        print("   docker compose -f infra/docker-compose.yml up -d")
        return
    
    # Test IP addresses
    test_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
    
    try:
        for i, ip in enumerate(test_ips, 1):
            print(f"\n🔄 Test {i}/{len(test_ips)}: IP {ip}")
            
            # Step 1: Create risk data
            if not create_risk_data(ip):
                print(f"⚠️  Skipping {ip} - could not create risk data")
                continue
            
            # Wait a moment for data to be stored
            time.sleep(1)
            
            # Step 2: Check risk status
            check_ip_risk(ip)
            
            # Step 3: Block the IP
            if block_ip(ip, f"SOAR demonstration test {i}"):
                # Step 4: Verify IP is blocked
                time.sleep(1)
                check_ip_risk(ip)
                
                # Step 5: Get blocked IP details
                get_blocked_ip_details(ip)
                
                # Step 6: Unblock the IP
                if i == len(test_ips):  # Only unblock the last one
                    unblock_ip(ip)
                    time.sleep(1)
                    check_ip_risk(ip)  # Verify risk data is restored
        
        # List all blocked IPs
        list_blocked_ips()
        
        print_section("SOAR Demo Completed")
        print("✅ Manual override capabilities demonstrated:")
        print("   • Risk data creation and tracking")
        print("   • Manual IP blocking with reason tracking")
        print("   • Risk data removal during block")
        print("   • IP unblocking with risk data restoration")
        print("   • Complete audit trail of all actions")
        print("\n📊 The SOAR system provides:")
        print("   • Manual override of automated decisions")
        print("   • Complete audit trail for compliance")
        print("   • Risk decay preservation during blocks")
        print("   • Flexible blocking duration management")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")

if __name__ == "__main__":
    main()
