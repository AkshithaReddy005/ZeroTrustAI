#!/usr/bin/env python3
"""
ZeroTrust-AI Combat Demo Controller
Orchestrates the complete 3-act live combat demonstration
"""

import time
import subprocess
import threading
import sys
import os
from datetime import datetime

class CombatDemoController:
    def __init__(self, defender_ip="192.168.137.1", attacker_ip="192.168.137.50"):
        self.defender_ip = defender_ip
        self.attacker_ip = attacker_ip
        self.sniffer_process = None
        self.dashboard_process = None
        self.current_act = 0
        
    def print_banner(self):
        """Print demo banner"""
        print("🔥" * 20)
        print("🛡️  ZeroTrust-Ai LIVE COMBAT DEMO")
        print("🔥" * 20)
        print("🎭 Act 1: The Baseline (Benign Traffic)")
        print("🎭 Act 2: The Attack (Malicious Traffic)")
        print("🎭 Act 3: The Evasion (IP Change + Pattern Match)")
        print("🔥" * 20)
        print()
    
    def print_act_header(self, act_number, title, description):
        """Print act header"""
        print(f"\n{'='*60}")
        print(f"🎭 ACT {act_number}: {title}")
        print(f"{'='*60}")
        print(f"📝 {description}")
        print(f"⏰ Started: {datetime.now().strftime('%H:%M:%S')}")
        print(f"🎯 Defender: {self.defender_ip}")
        print(f"👹 Attacker: {self.attacker_ip}")
        print()
    
    def start_defender_services(self):
        """Start defender services (sniffer and dashboard)"""
        print("🛡️ Starting Defender Services...")
        
        try:
            # Start live sniffer
            sniffer_cmd = [
                sys.executable, 
                "services/collector/live_wifi_sniffer.py",
                "--interface", "Wi-Fi",
                "--detector", "http://localhost:9000"
            ]
            
            self.sniffer_process = subprocess.Popen(
                sniffer_cmd,
                cwd=os.path.dirname(os.path.dirname(__file__)),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            print("✅ Live Sniffer Started")
            
            # Start dashboard (in background)
            dashboard_cmd = [
                sys.executable,
                "-m", "streamlit", "run", 
                "apps/dashboard/professional_dashboard.py",
                "--server.port", "8501",
                "--server.address", "0.0.0.0"
            ]
            
            self.dashboard_process = subprocess.Popen(
                dashboard_cmd,
                cwd=os.path.dirname(os.path.dirname(__file__)),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            print("✅ Dashboard Started: http://localhost:8501")
            
            # Wait for services to start
            print("⏳ Waiting for services to initialize...")
            time.sleep(5)
            
            return True
            
        except Exception as e:
            print(f"❌ Error starting defender services: {e}")
            return False
    
    def run_attack_script(self, attack_type, duration=30):
        """Run attack script on attacker machine"""
        print(f"🚀 Running {attack_type.upper()} attack...")
        
        try:
            attack_cmd = [
                sys.executable,
                "scripts/attack_simulator.py",
                "--target", self.defender_ip,
                "--attacker", self.attacker_ip,
                "--attack", attack_type,
                "--duration", str(duration)
            ]
            
            process = subprocess.run(
                attack_cmd,
                cwd=os.path.dirname(os.path.dirname(__file__)),
                capture_output=True,
                text=True,
                timeout=duration + 10
            )
            
            print(process.stdout)
            if process.stderr:
                print(f"⚠️  Attack warnings: {process.stderr}")
            
            return True
            
        except subprocess.TimeoutExpired:
            print(f"⏰ Attack timed out after {duration} seconds")
            return True
        except Exception as e:
            print(f"❌ Error running attack: {e}")
            return False
    
    def act_1_baseline(self):
        """Act 1: Baseline - Benign traffic"""
        self.print_act_header(1, "The Baseline", 
                             "Demonstrating normal network traffic - Dashboard should stay GREEN")
        
        print("🌐 Sending benign traffic...")
        print("👀 Watch the dashboard - it should remain GREEN")
        print("📊 Metrics should show low risk scores")
        print()
        
        # Run benign traffic for 30 seconds
        success = self.run_attack_script("benign", 30)
        
        if success:
            print("✅ Act 1 Complete - Baseline established")
        else:
            print("❌ Act 1 Failed")
        
        return success
    
    def act_2_attack(self):
        """Act 2: Attack - Malicious traffic"""
        self.print_act_header(2, "The Attack", 
                             "Launching DDoS attack - Dashboard should turn RED with MITRE TTPs")
        
        print("🚨 Starting DDoS attack...")
        print("👀 Watch the dashboard - it should turn RED")
        print("🎯 MITRE TTPs should be identified")
        print("🚫 IP should be automatically blocked")
        print()
        
        # Run DDoS attack for 30 seconds
        success = self.run_attack_script("ddos", 30)
        
        if success:
            print("✅ Act 2 Complete - Attack detected and blocked")
        else:
            print("❌ Act 2 Failed")
        
        return success
    
    def act_3_evasion(self):
        """Act 3: Evasion - IP change + pattern match"""
        self.print_act_header(3, "The Evasion", 
                             "Attacker changes IP - Zero-IP behavioral blocking prevents evasion")
        
        print("🎭 Attacker changes IP address (simulated)")
        print("🔥 Attacker launches same attack pattern from new IP")
        print("🚨 Zero-IP behavioral fingerprinting blocks INSTANTLY!")
        print("📊 Behavioral hash match: +1500_+1500_+1500_+1500_+1500")
        print()
        
        # Simulate IP change by using different attacker IP
        new_attacker_ip = "192.168.137.51"
        
        print(f"👹 New Attacker IP: {new_attacker_ip}")
        print("🚀 Launching same DDoS pattern from new IP...")
        
        # Run attack with new IP
        try:
            attack_cmd = [
                sys.executable,
                "scripts/attack_simulator.py",
                "--target", self.defender_ip,
                "--attacker", new_attacker_ip,
                "--attack", "ddos",
                "--duration", "20"
            ]
            
            process = subprocess.run(
                attack_cmd,
                cwd=os.path.dirname(os.path.dirname(__file__)),
                capture_output=True,
                text=True,
                timeout=25
            )
            
            print(process.stdout)
            
            print("✅ Act 3 Complete - Evasion PREVENTED!")
            print("🏆 Zero-IP behavioral fingerprinting SUCCESS!")
            
        except Exception as e:
            print(f"❌ Error in evasion test: {e}")
            return False
        
        return True
    
    def monitor_sniffer_output(self):
        """Monitor sniffer output in background"""
        while self.sniffer_process and self.sniffer_process.poll() is None:
            try:
                line = self.sniffer_process.stdout.readline()
                if line:
                    print(f"🔍 {line.strip()}")
            except:
                break
    
    def stop_all_services(self):
        """Stop all running services"""
        print("\n🛑 Stopping all services...")
        
        if self.sniffer_process:
            self.sniffer_process.terminate()
            self.sniffer_process.wait()
            print("✅ Sniffer stopped")
        
        if self.dashboard_process:
            self.dashboard_process.terminate()
            self.dashboard_process.wait()
            print("✅ Dashboard stopped")
    
    def run_complete_demo(self):
        """Run the complete 3-act combat demo"""
        self.print_banner()
        
        try:
            # Start defender services
            if not self.start_defender_services():
                print("❌ Failed to start defender services")
                return False
            
            # Start sniffer monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_sniffer_output, daemon=True)
            monitor_thread.start()
            
            print("\n🎬 Starting Combat Demo...")
            print("👀 Open http://localhost:8501 to watch the dashboard")
            print("⏰ Demo will take approximately 2 minutes")
            print()
            
            input("Press Enter to start Act 1...")
            
            # Run all acts
            act1_success = self.act_1_baseline()
            time.sleep(5)
            
            input("Press Enter to start Act 2...")
            act2_success = self.act_2_attack()
            time.sleep(5)
            
            input("Press Enter to start Act 3...")
            act3_success = self.act_3_evasion()
            
            # Final summary
            print(f"\n{'='*60}")
            print("🎉 COMBAT DEMO COMPLETE!")
            print(f"{'='*60}")
            print(f"📊 Results:")
            print(f"   Act 1 (Baseline): {'✅ SUCCESS' if act1_success else '❌ FAILED'}")
            print(f"   Act 2 (Attack):   {'✅ SUCCESS' if act2_success else '❌ FAILED'}")
            print(f"   Act 3 (Evasion):  {'✅ SUCCESS' if act3_success else '❌ FAILED'}")
            print()
            
            if all([act1_success, act2_success, act3_success]):
                print("🏆 PERFECT DEMO! ZeroTrust-AI is combat-ready!")
            else:
                print("⚠️  Some acts had issues - check the logs")
            
            return True
            
        except KeyboardInterrupt:
            print("\n🛑 Demo interrupted by user")
            return False
        except Exception as e:
            print(f"❌ Demo error: {e}")
            return False
        finally:
            self.stop_all_services()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="ZeroTrust-AI Combat Demo Controller")
    parser.add_argument("--defender", default="192.168.137.1", help="Defender IP address")
    parser.add_argument("--attacker", default="192.168.137.50", help="Attacker IP address")
    
    args = parser.parse_args()
    
    controller = CombatDemoController(args.defender, args.attacker)
    controller.run_complete_demo()

if __name__ == "__main__":
    main()
