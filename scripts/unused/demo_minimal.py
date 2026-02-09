import time
import requests

API = "http://localhost:8000"
DETECTOR = "http://localhost:9000"


def wait_for_service(url: str, timeout: int = 60):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=3)
            if r.ok:
                return True
        except Exception:
            pass
        time.sleep(1)
    raise TimeoutError(f"Service not ready: {url}")


def main():
    print("Waiting for services...")
    wait_for_service(f"{DETECTOR}/health")

    print("Training detector (bootstrapped)...")
    r = requests.post(f"{DETECTOR}/train", json={})
    r.raise_for_status()
    print("Train response:", r.json())

    sample_flow = {
        "flow_id": "demo-1",
        "total_packets": 120,
        "total_bytes": 35000,
        "avg_packet_size": 400.0,
        "std_packet_size": 80.0,
        "duration": 0.8,
        "pps": 150.0,
        "avg_entropy": 5.2,
        "syn_count": 2,
        "fin_count": 1,
    }

    print("Detecting sample flow...")
    r = requests.post(f"{DETECTOR}/detect", json=sample_flow)
    r.raise_for_status()
    result = r.json()
    print("Detect result:", result)

    try:
        print("Posting flow to API Gateway (if wired for incidents)...")
        r2 = requests.post(f"{API}/events/flow", json=sample_flow, timeout=5)
        if r2.ok:
            print("API flow accepted:", r2.json())
        else:
            print("API flow post failed:", r2.status_code, r2.text)
    except Exception as e:
        print("API not reachable or endpoint not present:", e)


if __name__ == "__main__":
    main()
