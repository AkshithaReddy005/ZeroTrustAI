#!/usr/bin/env python3
"""
Calculate detailed accuracy metrics for ZeroTrust-AI
"""

import requests
import json
from datetime import datetime
import pandas as pd
import numpy as np

def get_metrics_from_api():
    """Get metrics from API endpoints"""
    base_url = "http://localhost:9000"
    
    try:
        # Get system metrics
        metrics_resp = requests.get(f"{base_url}/metrics", timeout=5)
        if metrics_resp.status_code == 200:
            metrics = metrics_resp.json()
            print("📊 System Metrics:")
            print(f"   Total Flows: {metrics.get('total_flows', 0)}")
            print(f"   Threats Detected: {metrics.get('threats_detected', 0)}")
            print(f"   Blocked Flows: {metrics.get('blocked_flows', 0)}")
            print(f"   Meta-Fuser AUC: {metrics.get('meta_fuser_auc', 'N/A')}")
            print()
        
        # Get recent threats for confusion matrix
        threats_resp = requests.get(f"{base_url}/threats?limit=1000", timeout=5)
        if threats_resp.status_code == 200:
            threats = threats_resp.json()
            if threats:
                calculate_confusion_matrix(threats)
        
    except Exception as e:
        print(f"❌ Error fetching metrics: {e}")

def calculate_confusion_matrix(events):
    """Calculate confusion matrix from events"""
    print("🎯 Confusion Matrix Analysis:")
    
    tp = tn = fp = fn = 0
    total = 0
    
    for event in events:
        # Get ground truth from metadata
        ground_truth = event.get('metadata', {}).get('ground_truth', 'benign')
        predicted = event.get('label', 'benign')
        
        actual_mal = ground_truth.lower() == 'malicious'
        pred_mal = predicted.lower() == 'malicious'
        
        if actual_mal and pred_mal:
            tp += 1
        elif not actual_mal and not pred_mal:
            tn += 1
        elif not actual_mal and pred_mal:
            fp += 1
        else:
            fn += 1
        total += 1
    
    if total == 0:
        print("   No events found for analysis")
        return
    
    # Calculate metrics
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"   Total Events: {total}")
    print(f"   True Positives: {tp}")
    print(f"   True Negatives: {tn}")
    print(f"   False Positives: {fp}")
    print(f"   False Negatives: {fn}")
    print()
    print("📈 Performance Metrics:")
    print(f"   Accuracy:   {accuracy:.1%}")
    print(f"   Precision:  {precision:.1%}")
    print(f"   Recall:     {recall:.1%}")
    print(f"   F1 Score:   {f1:.1%}")
    print()
    
    # Performance assessment
    if accuracy >= 0.80:
        print("✅ Excellent performance (≥80%)")
    elif accuracy >= 0.70:
        print("🟡 Good performance (70-79%)")
    else:
        print("❌ Needs improvement (<70%)")
    
    if fp > fn:
        print("⚠️  More false positives than false negatives")
    elif fn > fp:
        print("⚠️  More false negatives than false positives")
    else:
        print("✅ Balanced false positive/negative rate")

def main():
    print("="*60)
    print("  ZeroTrust-AI Performance Metrics Calculator")
    print("="*60)
    print()
    
    get_metrics_from_api()

if __name__ == "__main__":
    main()
