#!/usr/bin/env python3
"""
NFStream to WebSocket Bridge
Real-time PCAP flow extraction with direct websocket communication to dashboard
"""

import os
import sys
import asyncio
import websockets
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

import nfstream

# Configuration
WEBSOCKET_URL = os.getenv("WEBSOCKET_URL", "ws://localhost:9000/ws")
PCAP_SOURCE = os.getenv("PCAP_SOURCE", "/data/raw")
THROTTLE_MS = int(os.getenv("THROTTLE_MS", "100"))
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
DEMO_RATE = float(os.getenv("DEMO_RATE", "0.1"))

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NFStreamWebSocketBridge:
    def __init__(self):
        self.websocket = None
        self.running = False
        self.flow_count = 0
        self.threat_count = 0
        
    async def connect_websocket(self):
        """Connect to websocket server"""
        try:
            self.websocket = await websockets.connect(WEBSOCKET_URL)
            logger.info(f"Connected to websocket: {WEBSOCKET_URL}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to websocket: {e}")
            return False
    
    def detect_threat(self, flow_data: Dict[str, Any]) -> tuple[bool, str, str]:
        """Simple threat detection based on flow characteristics"""
        reasons = []
        threat_level = 0
        
        # High packet rate
        pps = flow_data.get("pps", 0)
        if pps > 1000:
            reasons.append("High packet rate")
            threat_level += 2
        
        # Unusual port
        dst_port = flow_data.get("dst_port", 0)
        suspicious_ports = [22, 3389, 1433, 3306, 5900, 6379, 27017]
        if dst_port in suspicious_ports:
            reasons.append("Unusual destination port")
            threat_level += 1
        
        # High byte count
        total_bytes = flow_data.get("total_bytes", 0)
        if total_bytes > 5000000:  # 5MB
            reasons.append("Large data transfer")
            threat_level += 1
        
        # Long duration with high packet count
        duration = flow_data.get("duration", 0)
        total_packets = flow_data.get("total_packets", 0)
        if duration > 300 and total_packets > 10000:  # 5 minutes, 10k packets
            reasons.append("Suspicious persistence")
            threat_level += 1
        
        is_threat = threat_level >= 2 or (threat_level >= 1 and DEMO_MODE and time.random() < DEMO_RATE)
        
        if is_threat:
            severity = "high" if threat_level >= 3 else "medium"
            attack_type = "Data Exfiltration" if total_bytes > 5000000 else "Port Scan" if dst_port in suspicious_ports else "DDoS" if pps > 1000 else "Suspicious Activity"
        else:
            severity = "low"
            attack_type = "Normal Traffic"
        
        return is_threat, severity, attack_type
    
    async def send_flow_update(self, flow_data: Dict[str, Any]):
        """Send flow update to dashboard"""
        if not self.websocket:
            return
        
        try:
            # Detect threats
            is_threat, severity, attack_type = self.detect_threat(flow_data)
            
            if is_threat:
                self.threat_count += 1
                message = {
                    "type": "new_threat",
                    "data": {
                        "flow_id": flow_data["flow_id"],
                        "label": "malicious",
                        "confidence": 0.85,
                        "severity": severity,
                        "reason": [f"Real-time detection: {attack_type}"],
                        "attack_type": attack_type,
                        "source_ip": flow_data["src_ip"],
                        "destination_ip": flow_data["dst_ip"],
                        "blocked": severity == "high",
                        "timestamp": datetime.now().isoformat(),
                    }
                }
            else:
                message = {
                    "type": "flow_update",
                    "data": {
                        "flow_id": flow_data["flow_id"],
                        "src_ip": flow_data["src_ip"],
                        "dst_ip": flow_data["dst_ip"],
                        "src_port": flow_data["src_port"],
                        "dst_port": flow_data["dst_port"],
                        "protocol": flow_data["protocol"],
                        "total_packets": flow_data["total_packets"],
                        "total_bytes": flow_data["total_bytes"],
                        "duration": flow_data["duration"],
                        "pps": flow_data["pps"],
                        "timestamp": datetime.now().isoformat(),
                    }
                }
            
            await self.websocket.send(json.dumps(message))
            
        except Exception as e:
            logger.debug(f"Failed to send flow update: {e}")
    
    def process_nfstream_flow(self, flow) -> Dict[str, Any]:
        """Process nfstream flow object"""
        self.flow_count += 1
        
        # Extract flow metrics
        duration = float(flow.bidirectional_duration_ms) / 1000.0 if hasattr(flow, 'bidirectional_duration_ms') else 0.001
        total_packets = int(getattr(flow, 'bidirectional_packets', 0) or 0)
        total_bytes = int(getattr(flow, 'bidirectional_bytes', 0) or 0)
        pps = total_packets / duration if duration > 0 else 0
        avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
        
        flow_data = {
            "flow_id": f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}/{flow.protocol}",
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": int(flow.src_port),
            "dst_port": int(flow.dst_port),
            "protocol": int(flow.protocol),
            "duration": duration,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "avg_packet_size": avg_packet_size,
            "pps": pps,
        }
        
        return flow_data
    
    async def process_pcap_file(self, pcap_path: str):
        """Process a single PCAP file with nfstream"""
        logger.info(f"Processing PCAP file: {pcap_path}")
        
        try:
            streamer = nfstream.NFStreamer(
                source=pcap_path,
                statistical_analysis=True,
                splt_analysis=False,
                n_dissections=0,
                idle_timeout=30,
                active_timeout=300,
            )
            
            for flow in streamer:
                if not self.running:
                    break
                
                flow_data = self.process_nfstream_flow(flow)
                await self.send_flow_update(flow_data)
                
                # Throttle for real-time effect
                await asyncio.sleep(THROTTLE_MS / 1000.0)
                
        except Exception as e:
            logger.error(f"Error processing PCAP {pcap_path}: {e}")
    
    async def monitor_pcap_directory(self):
        """Monitor directory for new PCAP files"""
        pcap_dir = Path(PCAP_SOURCE)
        processed_files = set()
        
        while self.running:
            try:
                # Find PCAP files
                pcap_files = list(pcap_dir.glob("*.pcap")) + list(pcap_dir.glob("*.pcapng"))
                
                for pcap_file in pcap_files:
                    if str(pcap_file) not in processed_files:
                        logger.info(f"Found new PCAP file: {pcap_file}")
                        await self.process_pcap_file(str(pcap_file))
                        processed_files.add(str(pcap_file))
                        
                        # Send summary
                        if self.websocket:
                            summary = {
                                "type": "processing_summary",
                                "data": {
                                    "file": pcap_file.name,
                                    "flows_processed": self.flow_count,
                                    "threats_detected": self.threat_count,
                                    "timestamp": datetime.now().isoformat(),
                                }
                            }
                            await self.websocket.send(json.dumps(summary))
                
                # Wait before checking again
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Error monitoring directory: {e}")
                await asyncio.sleep(10)
    
    async def start(self):
        """Start the bridge"""
        self.running = True
        logger.info("Starting NFStream WebSocket Bridge")
        
        # Connect to websocket
        if not await self.connect_websocket():
            logger.error("Failed to connect to websocket")
            return
        
        # Start monitoring
        await self.monitor_pcap_directory()
    
    def stop(self):
        """Stop the bridge"""
        self.running = False
        logger.info("NFStream WebSocket Bridge stopped")

async def main():
    """Main entry point"""
    bridge = NFStreamWebSocketBridge()
    
    try:
        await bridge.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        bridge.stop()

if __name__ == "__main__":
    asyncio.run(main())
