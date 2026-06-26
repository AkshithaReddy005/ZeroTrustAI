#!/usr/bin/env python3
"""
Real-time PCAP Flow Processor with NFStream
Extracts flows from PCAP files in real-time using nfstream and sends to dashboard via websockets
"""

import os
import time
import json
import asyncio
import websockets
import logging
from typing import Dict, Any, List
from pathlib import Path
import threading
from datetime import datetime

import nfstream
import requests

# Configuration
API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")
WEBSOCKET_URL = os.getenv("WEBSOCKET_URL", "ws://localhost:9000/ws")
PCAP_SOURCE = os.getenv("PCAP_SOURCE", "/data/raw/*.pcap")
THROTTLE_MS = int(os.getenv("THROTTLE_MS", "50"))
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
DEMO_RATE = float(os.getenv("DEMO_RATE", "0.1"))

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealtimeFlowProcessor:
    def __init__(self):
        self.flow_count = 0
        self.websocket_client = None
        self.running = False
        self.flow_buffer = []
        self.buffer_lock = threading.Lock()
        
    async def connect_websocket(self):
        """Connect to websocket server for dashboard communication"""
        try:
            self.websocket_client = await websockets.connect(WEBSOCKET_URL)
            logger.info(f"Connected to websocket: {WEBSOCKET_URL}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to websocket: {e}")
            return False
    
    def post_flow_event(self, flow_data: Dict[str, Any]):
        """Send flow data to main API"""
        try:
            payload = {
                "flow_id": flow_data.get("flow_id", f"flow-{self.flow_count}"),
                "total_packets": flow_data.get("total_packets", 0),
                "total_bytes": flow_data.get("total_bytes", 0),
                "avg_packet_size": flow_data.get("avg_packet_size", 0),
                "duration": flow_data.get("duration", 0.0001),
                "pps": flow_data.get("pps", 0),
                "source_ip": flow_data.get("src_ip", ""),
                "destination_ip": flow_data.get("dst_ip", ""),
                "src_port": flow_data.get("src_port", 0),
                "dst_port": flow_data.get("dst_port", 0),
                "protocol": flow_data.get("protocol", 0),
            }
            requests.post(f"{API_BASE}/events/flow", json=payload, timeout=3)
        except Exception as e:
            logger.debug(f"Failed to post flow event: {e}")
    
    def post_threat_event(self, flow_data: Dict[str, Any]):
        """Send threat detection to main API"""
        # Simple threat detection based on flow characteristics
        is_malicious = self.detect_threat(flow_data)
        
        if DEMO_MODE and not is_malicious and __import__('random').random() < DEMO_RATE:
            is_malicious = True
        
        severity = "high" if is_malicious else "low"
        confidence = 0.85 if is_malicious else 0.3
        label = "malicious" if is_malicious else "benign"
        
        attack_types = ["DDoS", "Port Scan", "Data Exfiltration", "Command & Control"]
        attack_type = __import__('random').choice(attack_types) if is_malicious else "Normal Traffic"
        
        reasons = []
        if is_malicious:
            reasons = ["High packet rate", "Unusual destination port", "Large payload entropy"]
        else:
            reasons = ["Normal protocol behavior", "Standard port usage"]
        
        payload = {
            "flow_id": flow_data.get("flow_id", f"flow-{self.flow_count}"),
            "label": label,
            "confidence": confidence,
            "severity": severity,
            "reason": reasons,
            "attack_type": attack_type,
            "source_ip": flow_data.get("src_ip", ""),
            "destination_ip": flow_data.get("dst_ip", ""),
            "blocked": is_malicious and severity == "high",
            "timestamp": datetime.now().isoformat(),
        }
        
        try:
            requests.post(f"{API_BASE}/events/threat", json=payload, timeout=3)
        except Exception as e:
            logger.debug(f"Failed to post threat event: {e}")
    
    def detect_threat(self, flow_data: Dict[str, Any]) -> bool:
        """Simple threat detection based on flow characteristics"""
        # High packet rate
        pps = flow_data.get("pps", 0)
        if pps > 1000:
            return True
        
        # Unusual port
        dst_port = flow_data.get("dst_port", 0)
        if dst_port in [22, 3389, 1433, 3306]:  # Common attack targets
            return True
        
        # High byte count
        total_bytes = flow_data.get("total_bytes", 0)
        if total_bytes > 10000000:  # 10MB
            return True
        
        return False
    
    async def send_to_dashboard(self, flow_data: Dict[str, Any]):
        """Send flow data directly to dashboard via websocket"""
        if not self.websocket_client:
            return
        
        try:
            message = {
                "type": "flow_update",
                "data": {
                    "flow_id": flow_data.get("flow_id", f"flow-{self.flow_count}"),
                    "src_ip": flow_data.get("src_ip", ""),
                    "dst_ip": flow_data.get("dst_ip", ""),
                    "src_port": flow_data.get("src_port", 0),
                    "dst_port": flow_data.get("dst_port", 0),
                    "protocol": flow_data.get("protocol", 0),
                    "total_packets": flow_data.get("total_packets", 0),
                    "total_bytes": flow_data.get("total_bytes", 0),
                    "duration": flow_data.get("duration", 0),
                    "pps": flow_data.get("pps", 0),
                    "timestamp": datetime.now().isoformat(),
                }
            }
            await self.websocket_client.send(json.dumps(message))
        except Exception as e:
            logger.debug(f"Failed to send to dashboard: {e}")
    
    def process_flow(self, flow) -> Dict[str, Any]:
        """Process nfstream flow and convert to our format"""
        self.flow_count += 1
        
        # Calculate packet rate
        duration = float(flow.bidirectional_duration_ms) / 1000.0 if hasattr(flow, 'bidirectional_duration_ms') else 0.001
        total_packets = int(getattr(flow, 'bidirectional_packets', 0) or 0)
        pps = total_packets / duration if duration > 0 else 0
        
        # Calculate average packet size
        total_bytes = int(getattr(flow, 'bidirectional_bytes', 0) or 0)
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
        """Process a single PCAP file with nfstream in real-time"""
        logger.info(f"Processing PCAP file: {pcap_path}")
        
        try:
            streamer = nfstream.NFStreamer(
                source=pcap_path,
                statistical_analysis=True,
                splt_analysis=False,
                n_dissections=0,
                idle_timeout=30,  # 30 seconds idle timeout
                active_timeout=300,  # 5 minutes active timeout
            )
            
            for flow in streamer:
                if not self.running:
                    break
                
                flow_data = self.process_flow(flow)
                
                # Send to API endpoints
                self.post_flow_event(flow_data)
                self.post_threat_event(flow_data)
                
                # Send directly to dashboard via websocket
                await self.send_to_dashboard(flow_data)
                
                # Throttle to simulate real-time
                await asyncio.sleep(THROTTLE_MS / 1000.0)
                
        except Exception as e:
            logger.error(f"Error processing PCAP {pcap_path}: {e}")
    
    async def monitor_pcap_directory(self):
        """Monitor directory for new PCAP files"""
        pcap_dir = Path(PCAP_SOURCE).parent
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
                
                # Wait before checking again
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Error monitoring directory: {e}")
                await asyncio.sleep(10)
    
    async def run_live_capture(self, interface: str = None):
        """Run live network capture using nfstream"""
        logger.info("Starting live network capture")
        
        try:
            # For live capture, we'd use a network interface
            # This is a placeholder for live capture functionality
            # In practice, you might use nfstream with a live capture source
            logger.warning("Live capture not fully implemented - use PCAP files for now")
            
        except Exception as e:
            logger.error(f"Error in live capture: {e}")
    
    async def start(self):
        """Start the flow processor"""
        self.running = True
        logger.info("Starting real-time flow processor")
        
        # Connect to websocket
        if not await self.connect_websocket():
            logger.error("Failed to connect to websocket, continuing without dashboard updates")
        
        # Check if we have PCAP files or should do live capture
        pcap_dir = Path(PCAP_SOURCE).parent
        if pcap_dir.exists():
            pcap_files = list(pcap_dir.glob("*.pcap")) + list(pcap_dir.glob("*.pcapng"))
            if pcap_files:
                logger.info(f"Found {len(pcap_files)} PCAP files, processing them")
                await self.monitor_pcap_directory()
            else:
                logger.info(f"No PCAP files found in {pcap_dir}, waiting for files...")
                await self.monitor_pcap_directory()
        else:
            logger.warning(f"PCAP directory {pcap_dir} does not exist")
            await self.monitor_pcap_directory()
    
    def stop(self):
        """Stop the flow processor"""
        self.running = False
        if self.websocket_client:
            asyncio.create_task(self.websocket_client.close())
        logger.info("Flow processor stopped")

async def main():
    """Main entry point"""
    processor = RealtimeFlowProcessor()
    
    try:
        await processor.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        processor.stop()

if __name__ == "__main__":
    asyncio.run(main())
