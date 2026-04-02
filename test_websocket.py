#!/usr/bin/env python3
"""
Simple WebSocket connection test
"""

import asyncio
import websockets
import json

async def test_websocket():
    try:
        print("🔌 Connecting to WebSocket...")
        uri = "ws://localhost:9000/ws"
        async with websockets.connect(uri) as websocket:
            print("✅ Connected to WebSocket!")
            
            # Wait for messages
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                data = json.loads(message)
                print(f"📨 Received message: {data.get('type', 'unknown')}")
                return True
            except asyncio.TimeoutError:
                print("⏰ No message received (server may be idle)")
                return True
                
    except Exception as e:
        print(f"❌ WebSocket connection failed: {e}")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_websocket())
    if result:
        print("🎉 WebSocket test passed!")
    else:
        print("💥 WebSocket test failed!")
