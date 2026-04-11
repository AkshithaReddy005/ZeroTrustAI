#!/usr/bin/env python3
"""
InfluxDB Storage for Zero Trust Threat Events
Time-series database for advanced analytics and monitoring
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

class InfluxThreatStorage:
    def __init__(self, url="http://localhost:8086", token="your-token-here", org="zero-trust", bucket="threats"):
        self.client = InfluxDBClient(url=url, token=token, org=org)
        self.bucket = bucket
        self.org = org
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.query_api = self.client.query_api()
        
    def store_event(self, event: Dict[str, Any]) -> bool:
        """Store a single threat event in InfluxDB"""
        try:
            # Create point with tags and fields
            point = Point("threat_event") \
                .tag("flow_id", event.get('flow_id', 'unknown')) \
                .tag("label", event.get('label', 'unknown')) \
                .tag("severity", event.get('severity', 'medium')) \
                .tag("attack_type", event.get('attack_type', 'unknown')) \
                .tag("source_ip", event.get('source_ip', 'unknown')) \
                .tag("destination_ip", event.get('destination_ip', 'unknown')) \
                .field("confidence", float(event.get('confidence', 0.0))) \
                .field("blocked", bool(event.get('blocked', False))) \
                .field("metadata", json.dumps(event.get('metadata', {}))) \
                .time(datetime.now())
            
            # Add reason as separate points for analysis
            for reason in event.get('reason', []):
                point = Point("threat_reason") \
                    .tag("flow_id", event.get('flow_id', 'unknown')) \
                    .tag("label", event.get('label', 'unknown')) \
                    .tag("reason", reason) \
                    .field("count", 1) \
                    .time(datetime.now())
            
            self.write_api.write(bucket=self.bucket, record=point)
            return True
            
        except Exception as e:
            print(f"InfluxDB store error: {e}")
            return False
    
    def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent threat events from InfluxDB"""
        try:
            query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: -1h)
                |> filter(fn: (r) => r["_measurement"] == "threat_event")
                |> sort(columns: ["_time"], desc: true)
                |> limit(n: {limit})
            '''
            
            result = self.query_api.query(query)
            events = []
            
            for table in result:
                for record in table.records:
                    event = {
                        'timestamp': record.get_time().isoformat(),
                        'flow_id': record.values.get('flow_id'),
                        'label': record.values.get('label'),
                        'severity': record.values.get('severity'),
                        'attack_type': record.values.get('attack_type'),
                        'source_ip': record.values.get('source_ip'),
                        'destination_ip': record.values.get('destination_ip'),
                        'confidence': record.values.get('confidence'),
                        'blocked': record.values.get('blocked'),
                        'metadata': json.loads(record.values.get('metadata', '{}'))
                    }
                    events.append(event)
            
            return events
            
        except Exception as e:
            print(f"InfluxDB get events error: {e}")
            return []
    
    def get_metrics(self, time_range: str = "-1h") -> Dict[str, Any]:
        """Get aggregated metrics from InfluxDB"""
        try:
            # Total events
            total_query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: {time_range})
                |> filter(fn: (r) => r["_measurement"] == "threat_event")
                |> count()
            '''
            
            # Malicious vs benign
            label_query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: {time_range})
                |> filter(fn: (r) => r["_measurement"] == "threat_event")
                |> group(columns: ["label"])
                |> count()
            '''
            
            # Severity distribution
            severity_query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: {time_range})
                |> filter(fn: (r) => r["_measurement"] == "threat_event")
                |> group(columns: ["severity"])
                |> count()
            '''
            
            # Attack type distribution
            attack_query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: {time_range})
                |> filter(fn: (r) => r["_measurement"] == "threat_event")
                |> filter(fn: (r) => r["label"] == "malicious")
                |> group(columns: ["attack_type"])
                |> count()
            '''
            
            # Execute queries
            total_result = self.query_api.query(total_query)
            label_result = self.query_api.query(label_query)
            severity_result = self.query_api.query(severity_query)
            attack_result = self.query_api.query(attack_query)
            
            metrics = {}
            
            # Process total
            for table in total_result:
                for record in table.records:
                    metrics['total_events'] = record.get_value()
            
            # Process labels
            metrics['malicious_events'] = 0
            metrics['benign_events'] = 0
            for table in label_result:
                for record in table.records:
                    label = record.values.get('label')
                    if label == 'malicious':
                        metrics['malicious_events'] = record.get_value()
                    elif label == 'benign':
                        metrics['benign_events'] = record.get_value()
            
            # Process severity
            for table in severity_result:
                for record in table.records:
                    severity = record.values.get('severity')
                    metrics[f'severity_{severity}'] = record.get_value()
            
            # Process attack types
            for table in attack_result:
                for record in table.records:
                    attack_type = record.values.get('attack_type')
                    metrics[f'attack_{attack_type}'] = record.get_value()
            
            return metrics
            
        except Exception as e:
            print(f"InfluxDB metrics error: {e}")
            return {}
    
    def get_time_series(self, measurement: str, field: str, time_range: str = "-1h") -> List[Dict]:
        """Get time series data for charts"""
        try:
            query = f'''
            from(bucket: "{self.bucket}")
                |> range(start: {time_range})
                |> filter(fn: (r) => r["_measurement"] == "{measurement}")
                |> filter(fn: (r) => r["_field"] == "{field}")
                |> aggregateWindow(every: 1m, fn: mean, createEmpty: false)
                |> yield(name: "mean")
            '''
            
            result = self.query_api.query(query)
            series = []
            
            for table in result:
                for record in table.records:
                    series.append({
                        'timestamp': record.get_time().isoformat(),
                        'value': record.get_value()
                    })
            
            return series
            
        except Exception as e:
            print(f"InfluxDB time series error: {e}")
            return []

# Singleton instance
influx_storage = InfluxThreatStorage()
