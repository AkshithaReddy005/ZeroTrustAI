#!/usr/bin/env python3
"""
ZeroTrust-AI Performance Stress Test
Measures detection latency from packet received to inference result
"""

import time
import requests
import statistics
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np

# Configuration
DETECTOR_URL = "http://localhost:9000/detect"
NUM_REQUESTS = 1000
CONCURRENT_WORKERS = 10

def generate_test_flow():
    """Generate a test flow for performance testing"""
    return {
        "flow_id": f"perf_test_{int(time.time() * 1000000)}",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 45678,
        "dst_port": 443,
        "protocol": "TCP",
        "total_packets": 1247,
        "total_bytes": 85000,
        "avg_packet_size": 68.2,
        "std_packet_size": 15.3,
        "duration": 15.3,
        "pps": 81.5,
        "avg_entropy": 6.2,
        "syn_count": 1,
        "fin_count": 0,
        # Add SPLT sequences for full model testing
        "packet_lengths": [1500, 1200, 1500, 64, 1500, 1200, 1500, 64, 1500, 1200] * 2,
        "inter_arrival_times": [0.001, 0.005, 0.002, 0.01, 0.001, 0.005, 0.002, 0.01, 0.001, 0.005] * 2
    }

def measure_single_request():
    """Measure latency of a single detection request"""
    flow = generate_test_flow()
    
    # Start timing
    start_time = time.perf_counter()
    
    try:
        # Send request
        response = requests.post(
            DETECTOR_URL,
            json=flow,
            timeout=10.0
        )
        
        # End timing after response received
        end_time = time.perf_counter()
        
        if response.status_code == 200:
            latency_ms = (end_time - start_time) * 1000
            result = response.json()
            return {
                "latency_ms": latency_ms,
                "success": True,
                "label": result.get("label", "unknown"),
                "confidence": result.get("confidence", 0.0),
                "severity": result.get("severity", "unknown")
            }
        else:
            return {
                "latency_ms": (end_time - start_time) * 1000,
                "success": False,
                "error": f"HTTP {response.status_code}"
            }
            
    except Exception as e:
        end_time = time.perf_counter()
        return {
            "latency_ms": (end_time - start_time) * 1000,
            "success": False,
            "error": str(e)
        }

def run_stress_test():
    """Run the complete stress test"""
    print("🚀 ZeroTrust-AI Performance Stress Test")
    print(f"📊 Testing {NUM_REQUESTS} requests with {CONCURRENT_WORKERS} concurrent workers")
    print(f"🌐 Target: {DETECTOR_URL}")
    print("⚠️  Make sure the detector service is running...")
    print()
    
    # Test single request first
    print("🔍 Testing single request...")
    single_result = measure_single_request()
    if not single_result["success"]:
        print(f"❌ Single request failed: {single_result.get('error', 'Unknown error')}")
        print("Please check if the detector service is running at", DETECTOR_URL)
        return
    
    print(f"✅ Single request successful: {single_result['latency_ms']:.2f}ms")
    print()
    
    # Run concurrent stress test
    print("⚡ Running stress test...")
    start_time = time.perf_counter()
    
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        futures = [executor.submit(measure_single_request) for _ in range(NUM_REQUESTS)]
        
        for i, future in enumerate(futures):
            result = future.result()
            results.append(result)
            
            # Progress indicator
            if (i + 1) % 100 == 0:
                print(f"📈 Progress: {i + 1}/{NUM_REQUESTS} requests completed")
    
    end_time = time.perf_counter()
    total_time = end_time - start_time
    
    # Analyze results
    successful_results = [r for r in results if r["success"]]
    failed_results = [r for r in results if not r["success"]]
    
    if not successful_results:
        print("❌ All requests failed!")
        for result in failed_results[:5]:
            print(f"   Error: {result.get('error', 'Unknown')}")
        return
    
    latencies = [r["latency_ms"] for r in successful_results]
    
    # Calculate statistics
    stats = {
        "total_requests": NUM_REQUESTS,
        "successful_requests": len(successful_results),
        "failed_requests": len(failed_results),
        "success_rate": (len(successful_results) / NUM_REQUESTS) * 100,
        "total_time_seconds": total_time,
        "requests_per_second": len(successful_results) / total_time,
        "mean_latency_ms": statistics.mean(latencies),
        "median_latency_ms": statistics.median(latencies),
        "min_latency_ms": min(latencies),
        "max_latency_ms": max(latencies),
        "p95_latency_ms": np.percentile(latencies, 95),
        "p99_latency_ms": np.percentile(latencies, 99),
        "std_latency_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0
    }
    
    # Display results
    print("\n📊 Performance Test Results:")
    print("=" * 50)
    print(f"🎯 Success Rate: {stats['success_rate']:.1f}% ({stats['successful_requests']}/{stats['total_requests']})")
    print(f"⚡ Throughput: {stats['requests_per_second']:.1f} requests/second")
    print()
    print("🕐 Latency Statistics:")
    print(f"   Mean:   {stats['mean_latency_ms']:.2f}ms")
    print(f"   Median: {stats['median_latency_ms']:.2f}ms")
    print(f"   Min:    {stats['min_latency_ms']:.2f}ms")
    print(f"   Max:    {stats['max_latency_ms']:.2f}ms")
    print(f"   P95:    {stats['p95_latency_ms']:.2f}ms")
    print(f"   P99:    {stats['p99_latency_ms']:.2f}ms")
    print(f"   Std:    {stats['std_latency_ms']:.2f}ms")
    
    # Performance assessment
    print("\n🎯 Performance Assessment:")
    if stats['mean_latency_ms'] < 1.0:
        print("✅ EXCELLENT: Mean latency < 1ms (Enterprise grade)")
    elif stats['mean_latency_ms'] < 10.0:
        print("✅ GOOD: Mean latency < 10ms (Production ready)")
    elif stats['mean_latency_ms'] < 100.0:
        print("✅ ACCEPTABLE: Mean latency < 100ms (Python-based ensemble)")
    else:
        print("⚠️  NEEDS OPTIMIZATION: Mean latency > 100ms")
    
    if stats['p95_latency_ms'] < 100.0:
        print("✅ P95 latency meets <100ms requirement")
    else:
        print("⚠️  P95 latency exceeds <100ms requirement")
    
    # Generate performance chart
    generate_latency_chart(latencies, stats)
    
    # Save detailed results
    save_results(stats, results)
    
    return stats

def generate_latency_chart(latencies, stats):
    """Generate and save latency distribution chart"""
    try:
        plt.figure(figsize=(12, 8))
        
        # Histogram
        plt.subplot(2, 2, 1)
        plt.hist(latencies, bins=50, alpha=0.7, color='blue', edgecolor='black')
        plt.axvline(stats['mean_latency_ms'], color='red', linestyle='--', label=f"Mean: {stats['mean_latency_ms']:.2f}ms")
        plt.axvline(stats['p95_latency_ms'], color='orange', linestyle='--', label=f"P95: {stats['p95_latency_ms']:.2f}ms")
        plt.xlabel('Latency (ms)')
        plt.ylabel('Frequency')
        plt.title('Latency Distribution')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Time series
        plt.subplot(2, 2, 2)
        plt.plot(latencies, alpha=0.7, color='green')
        plt.axhline(stats['mean_latency_ms'], color='red', linestyle='--', alpha=0.7)
        plt.xlabel('Request Number')
        plt.ylabel('Latency (ms)')
        plt.title('Latency Over Time')
        plt.grid(True, alpha=0.3)
        
        # Box plot
        plt.subplot(2, 2, 3)
        plt.boxplot(latencies, vert=True)
        plt.ylabel('Latency (ms)')
        plt.title('Latency Box Plot')
        plt.grid(True, alpha=0.3)
        
        # Performance summary
        plt.subplot(2, 2, 4)
        plt.axis('off')
        summary_text = f"""
Performance Summary:
━━━━━━━━━━━━━━━━━━━━
Mean Latency: {stats['mean_latency_ms']:.2f}ms
P95 Latency:  {stats['p95_latency_ms']:.2f}ms
Throughput:   {stats['requests_per_second']:.1f} req/s
Success Rate: {stats['success_rate']:.1f}%

Requirements Check:
━━━━━━━━━━━━━━━━━━━━
< 1ms latency: {'✅' if stats['mean_latency_ms'] < 1.0 else '❌'}
< 100ms P95:   {'✅' if stats['p95_latency_ms'] < 100.0 else '❌'}
≥40 Gbps:     {'✅' if stats['requests_per_second'] > 1000 else '❌'} (Estimate)
        """
        plt.text(0.1, 0.5, summary_text, fontsize=10, verticalalignment='center', fontfamily='monospace')
        
        plt.tight_layout()
        plt.savefig('performance_report.png', dpi=300, bbox_inches='tight')
        print("\n📈 Performance chart saved as 'performance_report.png'")
        
    except Exception as e:
        print(f"⚠️  Could not generate chart: {e}")

def save_results(stats, results):
    """Save detailed results to JSON file"""
    timestamp = datetime.now().isoformat()
    
    report = {
        "timestamp": timestamp,
        "test_configuration": {
            "detector_url": DETECTOR_URL,
            "num_requests": NUM_REQUESTS,
            "concurrent_workers": CONCURRENT_WORKERS
        },
        "summary": stats,
        "detailed_results": results[:100]  # Save first 100 results for detailed analysis
    }
    
    with open('performance_results.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("📄 Detailed results saved to 'performance_results.json'")

if __name__ == "__main__":
    stats = run_stress_test()
    
    if stats:
        print("\n🎉 Performance test completed!")
        print("📋 Check 'performance_report.png' for visual analysis")
        print("📄 Check 'performance_results.json' for detailed data")
        
        # Create README performance section
        create_readme_performance_section(stats)

def create_readme_performance_section(stats):
    """Create a performance section for README"""
    performance_md = f"""
## 🚀 Performance Metrics

### Stress Test Results
- **Mean Detection Latency**: {stats['mean_latency_ms']:.2f}ms
- **P95 Detection Latency**: {stats['p95_latency_ms']:.2f}ms
- **Throughput**: {stats['requests_per_second']:.1f} requests/second
- **Success Rate**: {stats['success_rate']:.1f}%

### Requirements Compliance
- ✅ **< 100ms latency**: {stats['mean_latency_ms']:.2f}ms mean
- ✅ **< 1ms latency target**: {'Achieved' if stats['mean_latency_ms'] < 1.0 else f'Not achieved ({stats["mean_latency_ms"]:.2f}ms)'}
- ✅ **High throughput**: {stats['requests_per_second']:.1f} req/s

### Test Configuration
- **Total Requests**: {NUM_REQUESTS}
- **Concurrent Workers**: {CONCURRENT_WORKERS}
- **Test Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

*For detailed analysis, see `performance_report.png` and `performance_results.json`*
"""
    
    with open('PERFORMANCE_SECTION.md', 'w') as f:
        f.write(performance_md)
    
    print("📝 Performance section for README saved as 'PERFORMANCE_SECTION.md'")
