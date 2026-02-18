#!/usr/bin/env python3
"""Debug PCAP file to understand structure"""

import dpkt
import socket

def debug_pcap(pcap_path):
    """Debug PCAP file structure"""
    print(f"🔍 Debugging: {pcap_path}")
    
    try:
        with open(pcap_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            packet_count = 0
            ip_count = 0
            tcp_count = 0
            udp_count = 0
            
            for timestamp, buf in pcap:
                packet_count += 1
                if packet_count > 10:  # Only check first 10 packets
                    break
                    
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    print(f"Packet {packet_count}: Type={eth.type}")
                    
                    if hasattr(eth, 'ip'):
                        ip_count += 1
                        ip = eth.ip
                        print(f"  IP: {socket.inet_ntoa(ip.src)} -> {socket.inet_ntoa(ip.dst)}")
                        print(f"  Protocol: {ip.p}")
                        
                        if hasattr(ip, 'tcp'):
                            tcp_count += 1
                            tcp = ip.tcp
                            print(f"  TCP: {tcp.sport} -> {tcp.dport}")
                        elif hasattr(ip, 'udp'):
                            udp_count += 1
                            udp = ip.udp
                            print(f"  UDP: {udp.sport} -> {udp.dport}")
                    else:
                        print(f"  No IP layer found")
                        
                except Exception as e:
                    print(f"  Error parsing packet: {e}")
                    
            print(f"\nSummary:")
            print(f"  Total packets: {packet_count}")
            print(f"  IP packets: {ip_count}")
            print(f"  TCP packets: {tcp_count}")
            print(f"  UDP packets: {udp_count}")
            
    except Exception as e:
        print(f"❌ Error reading PCAP: {e}")

# Test one file
debug_pcap("C:/Users/akshi/Downloads/botnet-capture-20110811-neris (1).pcap")
