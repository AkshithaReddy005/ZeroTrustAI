#!/usr/bin/env python3
"""
Laptop B - Network Flow Classifier
Receives flows from Laptop A and classifies them using simple ML model
"""
import socket
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import sys
from pathlib import Path

PORT = 9999

# Three-tier thresholds
QUARANTINE_THRESHOLD = 0.55
MONITOR_THRESHOLD = 0.35

class FlowClassifier:
    """Simple ML-based flow classifier"""
    
    def __init__(self):
        print("Initializing simple Random Forest classifier...")
        
        # Create a simple Random Forest model
        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            random_state=42
        )
        
        # Create scaler
        self.scaler = StandardScaler()
        
        # Train on some synthetic data to initialize the model
        self._train_on_synthetic_data()
        
        print("  ✅ Random Forest model initialized and trained")
        print()
    
    def _train_on_synthetic_data(self):
        """Train model on synthetic examples of benign, DDoS, and C2 traffic"""
        X_train = []
        y_train = []
        
        # Generate 50 benign examples (reduced to make model more sensitive)
        for _ in range(50):
            features = self._generate_benign_features()
            X_train.append(features)
            y_train.append(0)  # Benign
        
        # Generate 100 DDoS examples (increased)
        for _ in range(100):
            features = self._generate_ddos_features()
            X_train.append(features)
            y_train.append(1)  # Malicious
        
        # Generate 100 C2 examples (increased)
        for _ in range(100):
            features = self._generate_c2_features()
            X_train.append(features)
            y_train.append(1)  # Malicious
        
        X_train = np.array(X_train)
        y_train = np.array(y_train)
        
        # Fit scaler and model with more aggressive settings
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled, y_train)
    
    def _generate_benign_features(self):
        """Generate SPLT features for benign traffic"""
        # Benign: varied packet sizes, random intervals
        splt_len = np.random.randint(60, 1500, 20)  # Normal packet sizes
        splt_iat = np.random.uniform(10, 1000, 20)  # Random intervals
        
        return np.concatenate([
            splt_len,
            splt_iat,
            [np.mean(splt_len), np.std(splt_len), np.mean(splt_iat), np.std(splt_iat)]
        ])
    
    def _generate_ddos_features(self):
        """Generate SPLT features for DDoS traffic"""
        # DDoS: small packets, very fast bursts
        splt_len = np.random.randint(40, 100, 20)   # Small packets
        splt_iat = np.random.uniform(0.1, 10, 20)   # Fast bursts
        
        return np.concatenate([
            splt_len,
            splt_iat,
            [np.mean(splt_len), np.std(splt_len), np.mean(splt_iat), np.std(splt_iat)]
        ])
    
    def _generate_c2_features(self):
        """Generate SPLT features for C2 beacon traffic"""
        # C2: consistent sizes, regular intervals
        base_len = np.random.randint(200, 500)
        base_iat = np.random.uniform(5000, 15000)
        
        splt_len = base_len + np.random.randint(-50, 50, 20)  # Consistent size
        splt_iat = base_iat + np.random.uniform(-1000, 1000, 20)  # Regular intervals
        
        return np.concatenate([
            splt_len,
            splt_iat,
            [np.mean(splt_len), np.std(splt_len), np.mean(splt_iat), np.std(splt_iat)]
        ])
    
    def extract_features(self, flow_data):
        """Extract SPLT features only from flow data"""
        # Get SPLT features (20 lengths + 20 IATs)
        splt_len = np.array(flow_data.get('splt_len', [0]*20))[:20]
        splt_iat = np.array(flow_data.get('splt_iat', [0]*20))[:20]
        
        # Pad if needed
        if len(splt_len) < 20:
            splt_len = np.pad(splt_len, (0, 20-len(splt_len)))
        if len(splt_iat) < 20:
            splt_iat = np.pad(splt_iat, (0, 20-len(splt_iat)))
        
        # Calculate SPLT statistics
        avg_len = np.mean(splt_len)
        std_len = np.std(splt_len)
        avg_iat = np.mean(splt_iat)
        std_iat = np.std(splt_iat)
        
        # Return 44 SPLT features: 20 lengths + 20 IATs + 4 statistics
        return np.concatenate([
            splt_len,
            splt_iat,
            [avg_len, std_len, avg_iat, std_iat]
        ])
    
    def classify(self, flow_data):
        """Classify a flow using Random Forest ML model with boosted detection"""
        # Extract features
        features = self.extract_features(flow_data)
        
        try:
            # Scale features
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            # Get Random Forest prediction probability
            probs = self.model.predict_proba(features_scaled)[0]
            ml_score = probs[1]  # Probability of malicious class
            
            # Apply heuristic boosting for known attack patterns
            splt_len = flow_data.get('splt_len', [0]*20)
            splt_iat = flow_data.get('splt_iat', [0]*20)
            
            avg_len = np.mean(splt_len)
            std_len = np.std(splt_len)
            avg_iat = np.mean(splt_iat)
            std_iat = np.std(splt_iat)
            
            boost = 0.0
            
            # DDoS indicators - small packets, fast intervals
            if avg_len < 150:  # Small packets
                boost += 0.3
            if avg_iat < 50:  # Very fast
                boost += 0.3
            
            # C2 indicators - low variance (regular patterns)
            if std_len > 0 and avg_len > 0:
                len_cv = std_len / avg_len  # Coefficient of variation
                if len_cv < 0.15:  # Very consistent size
                    boost += 0.3
            
            if std_iat > 0 and avg_iat > 0:
                iat_cv = std_iat / avg_iat
                if iat_cv < 0.15:  # Very regular timing
                    boost += 0.3
            
            # Combine ML score with heuristic boost
            score = min(ml_score + boost, 1.0)
            method = "ML+Heuristic"
            
        except Exception as e:
            score = 0.5
            method = f"Error: {str(e)[:30]}"
        
        # Apply three-tier policy
        if score > QUARANTINE_THRESHOLD:
            verdict = "🔴 QUARANTINE"
            action = "Block + SOAR alert"
        elif score >= MONITOR_THRESHOLD:
            verdict = "🟡 MONITOR"
            action = "Allow + elevated telemetry"
        else:
            verdict = "🟢 ALLOW"
            action = "Standard pass-through"
        
        return {
            'score': score,
            'method': method,
            'verdict': verdict,
            'action': action
        }

def main():
    print("=" * 60)
    print("LAPTOP B - NETWORK FLOW CLASSIFIER")
    print("=" * 60)
    print()
    
    # Initialize classifier
    classifier = FlowClassifier()
    
    # Start server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(5)
    
    print(f"🎯 Listening on port {PORT}...")
    print(f"📊 Three-tier policy:")
    print(f"   🔴 QUARANTINE: score > {QUARANTINE_THRESHOLD}")
    print(f"   🟡 MONITOR:    score ≥ {MONITOR_THRESHOLD}")
    print(f"   🟢 ALLOW:      score < {MONITOR_THRESHOLD}")
    print()
    print("Waiting for flows from Laptop A...")
    print("=" * 60)
    print()
    
    flow_count = 0
    stats = {'QUARANTINE': 0, 'MONITOR': 0, 'ALLOW': 0}
    
    try:
        while True:
            conn, addr = server.accept()
            data = conn.recv(65536).decode()
            
            try:
                flow = json.loads(data)
                result = classifier.classify(flow)
                
                flow_count += 1
                verdict_key = result['verdict'].split()[1]
                stats[verdict_key] += 1
                
                # Display result
                print(f"[{flow_count:04d}] {flow['src_ip']:15s} → {flow['dst_ip']:15s} | "
                      f"Score: {result['score']:.3f} | {result['verdict']} | "
                      f"Process: {flow.get('process', 'Unknown')}")
                
                # Show stats every 10 flows
                if flow_count % 10 == 0:
                    print(f"       Stats: 🔴 {stats['QUARANTINE']} | 🟡 {stats['MONITOR']} | 🟢 {stats['ALLOW']}")
                    print()
                
            except Exception as e:
                print(f"❌ Error processing flow: {e}")
            
            conn.close()
            
    except KeyboardInterrupt:
        print(f"\n\n✅ Processed {flow_count} flows")
        print(f"Final stats: 🔴 {stats['QUARANTINE']} | 🟡 {stats['MONITOR']} | 🟢 {stats['ALLOW']}")
        print("Exiting...")
    finally:
        server.close()

if __name__ == "__main__":
    main()
