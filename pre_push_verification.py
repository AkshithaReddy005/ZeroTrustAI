#!/usr/bin/env python3
"""
Pre-Push Verification Script
Tests all final checklist functionality without committing to git
"""

import sys
import os
import importlib.util

def test_file_exists(filepath, description):
    """Test if a file exists"""
    if os.path.exists(filepath):
        print(f"✅ {description}: {filepath}")
        return True
    else:
        print(f"❌ {description}: {filepath} NOT FOUND")
        return False

def test_module_import(module_path, module_name, description):
    """Test if a Python module can be imported"""
    try:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, os.path.dirname(module_path))
        spec.loader.exec_module(module)
        print(f"✅ {description}: {module_name}")
        return True
    except Exception as e:
        print(f"❌ {description}: {module_name} - ERROR: {e}")
        return False

def test_mitre_mapping():
    """Test MITRE ATT&CK mapping functionality"""
    print("\n🎯 Testing MITRE ATT&CK Mapping")
    print("-" * 40)
    
    try:
        # Add detector app path
        sys.path.insert(0, 'services/detector/app')
        
        # Import required modules
        from main import map_to_mitre_ttp
        from shared.schemas import FlowFeatures
        
        # Create test flow
        flow = FlowFeatures(
            flow_id='test', src_ip='192.168.1.100', dst_ip='10.0.0.1',
            src_port=45678, dst_port=443, protocol='TCP',
            total_packets=100, total_bytes=1000, avg_packet_size=10,
            std_packet_size=2, duration=1.0, pps=100, avg_entropy=6.0,
            syn_count=1, fin_count=0
        )
        
        # Test mappings
        test_cases = [
            (['tcn_malicious'], 'botnet', 'T1071'),
            (['ae_anomalous'], 'anomalous_behavior', 'T1027'),
            (['port_scan'], 'reconnaissance', 'T1046'),
        ]
        
        all_passed = True
        for reasons, expected_attack, expected_technique in test_cases:
            attack_type, tactic, technique = map_to_mitre_ttp(reasons, flow)
            if attack_type == expected_attack and technique == expected_technique:
                print(f"✅ {reasons[0]} → {attack_type} ({technique})")
            else:
                print(f"❌ {reasons[0]} → Expected {expected_attack} ({expected_technique}), got {attack_type} ({technique})")
                all_passed = False
        
        return all_passed
        
    except Exception as e:
        print(f"❌ MITRE mapping test failed: {e}")
        return False

def test_soar_module():
    """Test SOAR module functionality"""
    print("\n🔧 Testing SOAR Module")
    print("-" * 40)
    
    try:
        sys.path.insert(0, 'services/detector/app')
        from soar import get_blocked_ip_key, get_risk_key
        
        # Test key generation
        test_ip = '192.168.1.100'
        blocked_key = get_blocked_ip_key(test_ip)
        risk_key = get_risk_key(test_ip)
        
        expected_blocked = f"blocked:{test_ip}"
        expected_risk = f"risk:{test_ip}"
        
        if blocked_key == expected_blocked and risk_key == expected_risk:
            print(f"✅ Key generation working: {test_ip}")
            print(f"   Blocked key: {blocked_key}")
            print(f"   Risk key: {risk_key}")
            return True
        else:
            print(f"❌ Key generation failed")
            print(f"   Expected blocked: {expected_blocked}, got: {blocked_key}")
            print(f"   Expected risk: {expected_risk}, got: {risk_key}")
            return False
            
    except Exception as e:
        print(f"❌ SOAR module test failed: {e}")
        return False

def test_performance_module():
    """Test performance test module"""
    print("\n⚡ Testing Performance Module")
    print("-" * 40)
    
    try:
        # Test imports
        import matplotlib.pyplot as plt
        import requests
        import numpy as np
        
        # Test performance module import
        spec = importlib.util.spec_from_file_location("performance_test", "performance_test.py")
        perf_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(perf_module)
        
        print("✅ All dependencies available")
        print("✅ Performance test module imports successfully")
        
        # Test configuration
        if hasattr(perf_module, 'DETECTOR_URL') and hasattr(perf_module, 'NUM_REQUESTS'):
            print(f"✅ Configuration: {perf_module.NUM_REQUESTS} requests to {perf_module.DETECTOR_URL}")
            return True
        else:
            print("❌ Performance module configuration missing")
            return False
            
    except Exception as e:
        print(f"❌ Performance module test failed: {e}")
        return False

def main():
    """Run complete pre-push verification"""
    print("🚀 ZeroTrust-AI Pre-Push Verification")
    print("🎯 Final Checklist - Week 4 Completion")
    print("=" * 60)
    
    # Test file existence
    print("\n📁 Checking Files Exist")
    print("-" * 40)
    
    required_files = [
        ("services/detector/app/soar.py", "SOAR Module"),
        ("performance_test.py", "Performance Test"),
        ("demo_soar.py", "SOAR Demo"),
        ("final_checklist.py", "Final Checklist"),
        ("VERIFICATION_SUMMARY.md", "Verification Summary"),
        ("services/detector/app/main.py", "Main Detector"),
    ]
    
    files_ok = True
    for filepath, description in required_files:
        if not test_file_exists(filepath, description):
            files_ok = False
    
    # Test module imports
    print("\n🔍 Testing Module Imports")
    print("-" * 40)
    
    modules_ok = True
    modules_to_test = [
        ("services/detector/app/soar.py", "soar", "SOAR Module"),
        ("performance_test.py", "performance_test", "Performance Test"),
        ("demo_soar.py", "demo_soar", "SOAR Demo"),
        ("final_checklist.py", "final_checklist", "Final Checklist"),
    ]
    
    for module_path, module_name, description in modules_to_test:
        if not test_module_import(module_path, module_name, description):
            modules_ok = False
    
    # Test functionality
    mitre_ok = test_mitre_mapping()
    soar_ok = test_soar_module()
    perf_ok = test_performance_module()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 VERIFICATION SUMMARY")
    print("=" * 60)
    
    all_checks = [
        ("Files Exist", files_ok),
        ("Module Imports", modules_ok),
        ("MITRE Mapping", mitre_ok),
        ("SOAR Module", soar_ok),
        ("Performance Module", perf_ok),
    ]
    
    all_passed = True
    for check_name, status in all_checks:
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {check_name}: {'PASS' if status else 'FAIL'}")
        if not status:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 ALL VERIFICATIONS PASSED!")
        print("✅ Ready to commit and push to git")
        print("🚀 ZeroTrust-AI Final Checklist Complete")
        print("\n📋 Next Steps:")
        print("   1. git add .")
        print("   2. git commit -m 'feat: Complete final checklist - MITRE, Performance, SOAR'")
        print("   3. git push origin main")
        print("   4. git push new-origin main")
    else:
        print("⚠️  SOME VERIFICATIONS FAILED!")
        print("❌ Please fix issues before pushing")
        print("🔧 Review failed checks above")
    
    print("=" * 60)
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
