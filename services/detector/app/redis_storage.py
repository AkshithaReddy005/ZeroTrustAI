#!/usr/bin/env python3
"""
Redis Storage for Zero Trust Threat Events
Stores all dashboard events in Redis for persistence and analytics
"""

import json
import redis
from datetime import datetime
from typing import Dict, List, Any

class RedisThreatStorage:
    def __init__(self, host='localhost', port=6379, db=0, password=None):
        self.redis_client = redis.Redis(
            host=host, 
            port=port, 
            db=db, 
            password=password,
            decode_responses=True
        )
        self.events_key = "zero_trust:events"
        self.metrics_key = "zero_trust:metrics"
        
    def store_event(self, event: Dict[str, Any]) -> bool:
        """Store a single threat event in Redis"""
        try:
            timestamp = datetime.now().isoformat()
            event['stored_at'] = timestamp
            
            # Store in list (latest first)
            self.redis_client.lpush(self.events_key, json.dumps(event))
            
            # Keep only last 10000 events to prevent memory issues
            self.redis_client.ltrim(self.events_key, 0, 9999)
            
            # Update metrics
            self._update_metrics(event)
            
            return True
        except Exception as e:
            print(f"Redis store error: {e}")
            return False
    
    def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent threat events"""
        try:
            events = self.redis_client.lrange(self.events_key, 0, limit - 1)
            return [json.loads(event) for event in events]
        except Exception as e:
            print(f"Redis get events error: {e}")
            return []
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics"""
        try:
            metrics = self.redis_client.hgetall(self.metrics_key)
            return {k: int(v) for k, v in metrics.items()}
        except Exception as e:
            print(f"Redis get metrics error: {e}")
            return {}
    
    def _update_metrics(self, event: Dict[str, Any]):
        """Update aggregated metrics"""
        try:
            # Basic counters
            self.redis_client.hincrby(self.metrics_key, 'total_events', 1)
            
            if event.get('label') == 'malicious':
                self.redis_client.hincrby(self.metrics_key, 'malicious_events', 1)
            else:
                self.redis_client.hincrby(self.metrics_key, 'benign_events', 1)
            
            # Severity counters
            severity = event.get('severity', 'low')
            self.redis_client.hincrby(self.metrics_key, f'severity_{severity}', 1)
            
            # Attack type counters
            attack_type = event.get('attack_type', 'unknown')
            self.redis_client.hincrby(self.metrics_key, f'attack_{attack_type}', 1)
            
        except Exception as e:
            print(f"Redis metrics update error: {e}")

# Singleton instance
redis_storage = RedisThreatStorage()
