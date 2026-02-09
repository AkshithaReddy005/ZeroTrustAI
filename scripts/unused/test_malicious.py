import requests

malicious_flow = {
    "flow_id": "malicious-1",
    "total_packets": 5000,
    "total_bytes": 800000,
    "avg_packet_size": 160.0,
    "std_packet_size": 250.0,
    "duration": 0.2,
    "pps": 25000.0,
    "avg_entropy": 7.8,
    "syn_count": 50,
    "fin_count": 0,
}

print("Testing malicious flow...")
r = requests.post("http://localhost:9000/detect", json=malicious_flow)
print("Result:", r.json())
