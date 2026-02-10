#!/usr/bin/env python3
"""
Live Wi-Fi Packet Sniffer for ZeroTrust-AI Combat Demo
Replaces file-based collector with real-time Wi-Fi packet capture
"""

import time
import json
import requests
import threading
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import argparse
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'detector', 'app'))

class LiveWiFiSniffer:
    def __init__(self, detector_url="http://localhost:9000", interface="Wi-Fi"):
        self.detector_url = detector_url
        self.interface = interface
        self.running = False
        self.packet_buffer = deque(maxlen=100)
        self.flow_cache = defaultdict(dict)
        self.last_cleanup = time.time()
        self.stats = {
            'total_packets': 0,
            'malicious_flows': 0,
            'blocked_ips': set(),
            'start_time': time.time()
        }
        
    def extract_packet_features(self, pkt):
        """Extract features from real Wi-Fi packet"""
        if not pkt.haslayer(IP):
            return None
            
        try:
            # Basic IP information
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
            packet_len = len(pkt)
            timestamp = float(pkt.time)
            
            # Extract protocol-specific info
            src_port = dst_port = 0
            flags = 0
            
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = pkt[TCP].flags
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                src_port = dst_port = 0  # ICMP doesn't have ports
            
            # Update flow statistics
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            
            if flow_key not in self.flow_cache:
                self.flow_cache[flow_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'start_time': timestamp,
                    'packet_lengths': [],
                    'inter_arrival_times': [],
                    'packet_count': 0,
                    'total_bytes': 0,
                    'last_packet_time': timestamp,
                    'syn_count': 0,
                    'fin_count': 0,
                    'rst_count': 0,
                    'udp_count': 0,
                    'icmp_count': 0
                }
            
            flow = self.flow_cache[flow_key]
            
            # Calculate inter-arrival time
            if flow['packet_count'] > 0:
                iat = timestamp - flow['last_packet_time']
                flow['inter_arrival_times'].append(iat)
            
            # Update packet statistics
            flow['packet_lengths'].append(packet_len)
            flow['packet_count'] += 1
            flow['total_bytes'] += packet_len
            flow['last_packet_time'] = timestamp
            
            # Count packet types
            if pkt.haslayer(TCP):
                if flags & 0x02:  # SYN flag
                    flow['syn_count'] += 1
                if flags & 0x01:  # FIN flag
                    flow['fin_count'] += 1
                if flags & 0x04:  # RST flag
                    flow['rst_count'] += 1
            elif pkt.haslayer(UDP):
                flow['udp_count'] += 1
            elif pkt.haslayer(ICMP):
                flow['icmp_count'] += 1
            
            # Keep only last 20 packets for SPLT
            if len(flow['packet_lengths']) > 20:
                flow['packet_lengths'] = flow['packet_lengths'][-20:]
            if len(flow['inter_arrival_times']) > 20:
                flow['inter_arrival_times'] = flow['inter_arrival_times'][-20:]
            
            return flow_key, flow
            
        except Exception as e:
            print(f"❌ Error extracting features: {e}")
            return None
    
    def create_flow_features(self, flow_key, flow):
        """Create FlowFeatures object for detector"""
        try:
            # Calculate derived statistics
            duration = flow['last_packet_time'] - flow['start_time']
            avg_packet_size = flow['total_bytes'] / max(flow['packet_count'], 1)
            
            # Calculate standard deviation of packet sizes
            if len(flow['packet_lengths']) > 1:
                mean_size = sum(flow['packet_lengths']) / len(flow['packet_lengths'])
                variance = sum((x - mean_size) ** 2 for x in flow['packet_lengths']) / len(flow['packet_lengths'])
                std_packet_size = variance ** 0.5
            else:
                std_packet_size = 0
            
            # Calculate packets per second
            pps = flow['packet_count'] / max(duration, 0.001)
            
            # Calculate entropy (simplified)
            if len(flow['packet_lengths']) > 1:
                unique_sizes = set(flow['packet_lengths'])
                entropy = len(unique_sizes) / len(flow['packet_lengths'])
            else:
                entropy = 0
            
            # Create flow features dict
            flow_features = {
                "flow_id": f"wifi-{flow_key}-{int(time.time())}",
                "src_ip": flow['src_ip'],
                "dst_ip": flow['dst_ip'],
                "src_port": flow['src_port'],
                "dst_port": flow['dst_port'],
                "protocol": flow['protocol'],
                "total_packets": flow['packet_count'],
                "total_bytes": flow['total_bytes'],
                "avg_packet_size": avg_packet_size,
                "std_packet_size": std_packet_size,
                "duration": duration,
                "pps": pps,
                "avg_entropy": entropy,
                "syn_count": flow['syn_count'],
                "fin_count": flow['fin_count'],
                "splt_len": flow['packet_lengths'][:20],  # SPLT packet lengths
                "splt_iat": flow['inter_arrival_times'][:20]  # SPLT inter-arrival times
            }
            
            return flow_features
            
        except Exception as e:
            print(f"❌ Error creating flow features: {e}")
            return None
    
    def send_to_detector(self, flow_features):
        """Send flow features to detector API"""
        try:
            response = requests.post(
                f"{self.detector_url}/detect",
                json=flow_features,
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                self.handle_detection_result(flow_features, result)
                return True
            else:
                print(f"❌ Detector API error: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending to detector: {e}")
            return False
    
    def handle_detection_result(self, flow_features, result):
        """Handle detection result and take action"""
        src_ip = flow_features['src_ip']
        label = result.get('label', 'benign')
        severity = result.get('severity', 'LOW')
        confidence = result.get('confidence', 0.0)
        reasons = result.get('reason', [])
        metadata = result.get('metadata', {})
        
        print(f"\n🔍 Detection Result:")
        print(f"   📍 Source: {src_ip}")
        print(f"   🎯 Label: {label}")
        print(f"   ⚠️  Severity: {severity}")
        print(f"   📊 Confidence: {confidence:.2f}")
        print(f"   📝 Reasons: {', '.join(reasons)}")
        
        # Check for behavioral pattern match
        if metadata and 'behavioral_hash' in metadata:
            behavioral_hash = metadata['behavioral_hash']
            print(f"   🔑 Behavioral Hash: {behavioral_hash}")
            
            if 'pattern_first_seen' in metadata:
                print(f"   ⏰ Pattern First Seen: {metadata['pattern_first_seen']}")
                print(f"   🚨 ZERO-IP EVASION PREVENTED!")
        
        # Update statistics
        self.stats['total_packets'] += flow_features['total_packets']
        
        if label == 'malicious':
            self.stats['malicious_flows'] += 1
            
            if severity in ['HIGH', 'CRITICAL']:
                self.stats['blocked_ips'].add(src_ip)
                
                # Execute blocking action
                self.execute_block_action(src_ip, severity, reasons)
    
    def execute_block_action(self, src_ip, severity, reasons):
        """Execute actual blocking action on the system"""
        print(f"\n🚨 EXECUTING BLOCK ACTION:")
        print(f"   🎯 Target IP: {src_ip}")
        print(f"   ⚠️  Severity: {severity}")
        print(f"   📝 Reasons: {', '.join(reasons)}")
        
        try:
            import platform
            system = platform.system()
            
            if system == "Windows":
                # Windows firewall block
                cmd = f'netsh advfirewall firewall add rule name="ZeroTrust-Block-{src_ip}" dir=in action=block remoteip={src_ip}'
                print(f"   🔧 Windows Command: {cmd}")
                os.system(cmd)
                
            elif system == "Linux":
                # Linux iptables block
                cmd = f'sudo iptables -A INPUT -s {src_ip} -j DROP'
                print(f"   🔧 Linux Command: {cmd}")
                os.system(cmd)
                
            print(f"   ✅ Block command executed!")
            
        except Exception as e:
            print(f"   ❌ Error executing block: {e}")
    
    def cleanup_old_flows(self):
        """Clean up old flows to prevent memory leaks"""
        current_time = time.time()
        
        if current_time - self.last_cleanup > 60:  # Cleanup every minute
            expired_flows = []
            
            for flow_key, flow in self.flow_cache.items():
                if current_time - flow['last_packet_time'] > 300:  # 5 minutes timeout
                    expired_flows.append(flow_key)
            
            for flow_key in expired_flows:
                del self.flow_cache[flow_key]
            
            self.last_cleanup = current_time
            print(f"🧹 Cleaned up {len(expired_flows)} expired flows")
    
    def process_packet(self, pkt):
        """Process individual packet"""
        if not self.running:
            return
        
        result = self.extract_packet_features(pkt)
        if result:
            flow_key, flow = result
            
            # Only process flows with enough packets
            if flow['packet_count'] >= 5:  # Minimum packets for analysis
                flow_features = self.create_flow_features(flow_key, flow)
                if flow_features:
                    self.send_to_detector(flow_features)
    
    def print_stats(self):
        """Print current statistics"""
        runtime = time.time() - self.stats['start_time']
        print(f"\n📊 Live Statistics (Runtime: {runtime:.1f}s):")
        print(f"   📦 Total Packets: {self.stats['total_packets']}")
        print(f"   🚨 Malicious Flows: {self.stats['malicious_flows']}")
        print(f"   🚫 Blocked IPs: {len(self.stats['blocked_ips'])}")
        print(f"   🔍 Active Flows: {len(self.flow_cache)}")
        
        if self.stats['blocked_ips']:
            print(f"   🎯 Blocked IPs: {', '.join(self.stats['blocked_ips'])}")
    
    def start_sniffing(self):
        """Start the Wi-Fi packet sniffing"""
        print(f"🔥 Starting ZeroTrust-AI Live Wi-Fi Sniffer")
        print(f"📡 Interface: {self.interface}")
        print(f"🎯 Detector URL: {self.detector_url}")
        print(f"⚡ Ready to detect attacks in real-time!")
        print("=" * 60)
        
        self.running = True
        
        # Start statistics thread
        stats_thread = threading.Thread(target=self.stats_loop, daemon=True)
        stats_thread.start()
        
        try:
            # Start packet sniffing
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                filter="ip",  # Only IP packets
                store=0,      # Don't store packets in memory
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("\n🛑 Stopping sniffer...")
        except Exception as e:
            print(f"❌ Sniffing error: {e}")
        finally:
            self.running = False
            print("👋 Sniffer stopped")
    
    def stats_loop(self):
        """Background thread for printing statistics"""
        while self.running:
            time.sleep(10)  # Print stats every 10 seconds
            self.print_stats()
            self.cleanup_old_flows()

def main():
    parser = argparse.ArgumentParser(description="ZeroTrust-AI Live Wi-Fi Sniffer")
    parser.add_argument("--interface", "-i", default="Wi-Fi", help="Wi-Fi interface name")
    parser.add_argument("--detector", "-d", default="http://localhost:9000", help="Detector API URL")
    parser.add_argument("--test", "-t", action="store_true", help="Test mode with simulated traffic")
    
    args = parser.parse_args()
    
    # Check if Scapy can access the interface
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        if args.interface not in interfaces:
            print(f"❌ Interface '{args.interface}' not found!")
            print(f"📡 Available interfaces: {interfaces}")
            print("💡 On Windows, try: --interface \"Wi-Fi\" or \"Ethernet\"")
            print("💡 On Linux, try: --interface wlan0 or eth0")
            return
    except ImportError:
        print("❌ Scapy not properly installed!")
        print("💡 On Windows, install Npcap: https://npcap.com/")
        print("💡 On Linux, install: pip install scapy")
        return
    
    sniffer = LiveWiFiSniffer(detector_url=args.detector, interface=args.interface)
    
    if args.test:
        print("🧪 Test mode - sending simulated traffic")
        sniffer.test_mode()
    else:
        sniffer.start_sniffing()

if __name__ == "__main__":
    main()
