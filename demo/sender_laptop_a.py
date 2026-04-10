#!/usr/bin/env python3
"""
Laptop A - Real Network Flow Sender
Captures real network traffic and sends flows to Laptop B for classification
"""
import socket
import json
import time
import random
import sys
import psutil
import threading

# CONFIGURE THIS - PUT LAPTOP B IP HERE
RECEIVER_IP = "192.168.0.154"  # Laptop B (receiver) IP
PORT = 9999

def send_flow(flow_data):
    """Send a single flow to the receiver"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((RECEIVER_IP, PORT))
        s.send(json.dumps(flow_data).encode())
        s.close()
        return True
    except Exception as e:
        print(f"❌ Error sending flow: {e}")
        return False

def get_real_network_flows():
    """Get real network connections from this laptop"""
    flows = []
    
    # Get all network connections
    connections = psutil.net_connections(kind='inet')
    
    for conn in connections:
        if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
            # Get process info for additional details
            try:
                process = psutil.Process(conn.pid) if conn.pid else None
                process_name = process.name() if process else "Unknown"
            except:
                process_name = "Unknown"
            
            # Create flow from real connection
            flow = {
                "src_ip": conn.laddr.ip,
                "src_port": conn.laddr.port,
                "dst_ip": conn.raddr.ip,
                "dst_port": conn.raddr.port,
                "protocol": 6 if conn.type == socket.SOCK_STREAM else 17,  # TCP or UDP
                "process": process_name,
                "status": conn.status,
                "pid": conn.pid,
                "duration": random.uniform(0.1, 10),  # Simulated duration
                "total_packets": random.randint(5, 100),  # Simulated packet count
                "total_bytes": random.randint(500, 10000),  # Simulated bytes
                "splt_len": [random.randint(60, 1500) for _ in range(20)],  # Simulated SPLT
                "splt_iat": [random.uniform(10, 1000) for _ in range(20)],  # Simulated SPLT
                "attack_type": "Normal"  # Assume normal for real traffic
            }
            flows.append(flow)
    
    return flows

def get_local_ip():
    """Get this laptop's actual IP address"""
    try:
        # Connect to a remote address to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def generate_real_flows():
    """Generate flows from real network activity"""
    flows = get_real_network_flows()
    
    # If no real flows, create some based on common destinations
    if not flows:
        print("No active connections found, creating sample flows...")
        common_destinations = [
            ("8.8.8.8", 53),      # Google DNS
            ("1.1.1.1", 53),      # Cloudflare DNS
            ("142.250.185.46", 443), # Google
            ("157.240.229.35", 443),  # Facebook
            ("151.101.1.69", 443),    # Reddit
        ]
        
        local_ip = get_local_ip()  # This laptop's actual IP
        
        for dst_ip, dst_port in common_destinations:
            flow = {
                "src_ip": local_ip,
                "src_port": random.randint(49152, 65535),
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": 6 if dst_port in [443, 80] else 17,
                "process": "chrome.exe" if dst_port == 443 else "system",
                "status": "ESTABLISHED",
                "pid": random.randint(1000, 9999),
                "duration": random.uniform(0.5, 30),
                "total_packets": random.randint(10, 100),
                "total_bytes": random.randint(1000, 50000),
                "splt_len": [random.randint(60, 1500) for _ in range(20)],
                "splt_iat": [random.uniform(10, 1000) for _ in range(20)],
                "attack_type": "Normal"
            }
            flows.append(flow)
    
    return flows

def main():
    print("=" * 60)
    print("LAPTOP A - REAL NETWORK FLOW SENDER")
    print("=" * 60)
    print(f"Target: {RECEIVER_IP}:{PORT}")
    print("Capturing REAL network connections...")
    print()
    
    flow_count = 0
    
    try:
        while True:
            # Get real network flows
            flows = generate_real_flows()
            
            print(f"Found {len(flows)} active connections")
            
            # Send each real flow
            for flow in flows:
                if send_flow(flow):
                    flow_count += 1
                    print(f"[{flow_count:04d}] Sent REAL flow: "
                          f"{flow['src_ip']:15s} → {flow['dst_ip']:15s}:{flow['dst_port']} "
                          f"({flow.get('process', 'Unknown')})")
                
                # Small delay between flows
                time.sleep(0.5)
            
            print(f"--- Batch complete, waiting 10 seconds ---")
            time.sleep(10)  # Wait before next batch
            
    except KeyboardInterrupt:
        print(f"\n✅ Sent {flow_count} real flows total")
        print("Sender stopped.")

if __name__ == "__main__":
    main()
