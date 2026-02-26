"""
Byzantine Client Detection Module
Implements cosine similarity and contribution tracking to explicitly detect malicious clients
"""

import torch
import numpy as np
from typing import Dict, List, Tuple
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


class ByzantineDetector:
    """Detects malicious clients using multiple detection methods"""
    
    def __init__(self, similarity_threshold=-0.5, deviation_threshold=2.0):
        """
        Args:
            similarity_threshold: Cosine similarity below this flags client as suspicious
            deviation_threshold: Standard deviations from median to flag as suspicious
        """
        self.similarity_threshold = similarity_threshold
        self.deviation_threshold = deviation_threshold
        self.client_history = defaultdict(list)  # Track deviation history per client
        self.trust_scores = {}  # Trust score per client (0-1, lower = more suspicious)

    @staticmethod
    def _is_float_tensor(t: torch.Tensor) -> bool:
        return t.is_floating_point() or t.is_complex()

    def _float_param_keys(self, weights: Dict[str, torch.Tensor]) -> List[str]:
        """Return only parameter keys safe for vector distance/similarity math."""
        return [k for k, v in weights.items() if self._is_float_tensor(v)]
        
    def cosine_similarity(self, weights_a: Dict[str, torch.Tensor], 
                         weights_b: Dict[str, torch.Tensor]) -> float:
        """
        Calculate cosine similarity between two weight dictionaries
        
        Returns:
            float: Similarity score (-1 to 1)
                   1 = same direction (honest)
                   0 = orthogonal
                  -1 = opposite direction (malicious)
        """
        # Flatten only floating-point weights into single vectors
        common_keys = sorted(set(self._float_param_keys(weights_a)) & set(self._float_param_keys(weights_b)))
        if not common_keys:
            return 0.0

        vec_a = torch.cat([weights_a[key].to(torch.float32).flatten() for key in common_keys])
        vec_b = torch.cat([weights_b[key].to(torch.float32).flatten() for key in common_keys])
        
        # Compute cosine similarity
        dot_product = torch.dot(vec_a, vec_b)
        norm_a = torch.norm(vec_a)
        norm_b = torch.norm(vec_b)
        
        if norm_a == 0 or norm_b == 0:
            return 0.0
        
        similarity = (dot_product / (norm_a * norm_b)).item()
        return similarity
    
    def calculate_weight_deviation(self, client_weights: Dict[str, torch.Tensor],
                                   median_weights: Dict[str, torch.Tensor]) -> float:
        """
        Calculate how much client weights deviate from median weights
        
        Returns:
            float: L2 norm of difference (higher = more deviation)
        """
        total_deviation = 0.0

        common_keys = sorted(set(self._float_param_keys(client_weights)) & set(self._float_param_keys(median_weights)))
        for key in common_keys:
            diff = client_weights[key].to(torch.float32) - median_weights[key].to(torch.float32)
            deviation = torch.norm(diff).item()
            total_deviation += deviation
        
        return total_deviation
    
    def detect_malicious_clients(self, 
                                 client_weights: Dict[str, Dict[str, torch.Tensor]],
                                 global_weights: Dict[str, torch.Tensor],
                                 round_num: int,
                                 client_performance: Dict[str, Dict] = None) -> Dict[str, Dict]:
        """
        Detect malicious clients using multiple methods
        
        Args:
            client_weights: Dict mapping client_id -> weight dict
            global_weights: Aggregated global weights
            round_num: Current training round
            
        Returns:
            Dict mapping client_id -> detection results
        """
        results = {}
        
        # Calculate median weights for deviation tracking
        median_weights = self._calculate_median_weights(client_weights)
        
        # Analyze each client
        for client_id, weights in client_weights.items():
            
            # Method 1: Cosine Similarity Check
            similarity = self.cosine_similarity(weights, global_weights)
            
            # Method 2: Deviation from Median
            deviation = self.calculate_weight_deviation(weights, median_weights)
            
            # Track deviation history
            self.client_history[client_id].append(deviation)
            
            # Method 3: Persistent Deviation Check
            avg_deviation = np.mean(self.client_history[client_id])
            std_deviation = np.std(list(self.client_history[client_id]) + 
                                  [d for history in self.client_history.values() 
                                   for d in history])
            
            # Calculate z-score (how many std devs from mean)
            if std_deviation > 0:
                z_score = (deviation - avg_deviation) / std_deviation
            else:
                z_score = 0.0
            
            # Multi-signal detection
            suspicion_signals = []
            
            # Signal 1: Cosine Similarity
            if similarity < self.similarity_threshold:
                suspicion_signals.append("Low similarity")
            
            # Signal 2: Weight Deviation
            if abs(z_score) > self.deviation_threshold or deviation > 100.0:
                suspicion_signals.append("High deviation")
            
            # Signal 3: Performance-based detection (F1 and Accuracy)
            if client_performance and client_id in client_performance:
                perf = client_performance[client_id]
                accuracy = perf.get('accuracy', 1.0)
                f1 = perf.get('f1', 1.0)
                
                # Near-random accuracy (0.5 ± 0.03) = inverted labels (stricter)
                if abs(accuracy - 0.5) < 0.03:
                    suspicion_signals.append("Random accuracy")
                
                # Near-zero F1 after round 3 = not learning (more rounds needed)
                if round_num > 3 and f1 < 0.02:
                    suspicion_signals.append("Near-zero F1")
            
            # Determine malicious status based on suspicion count
            suspicion_count = len(suspicion_signals)
            
            if suspicion_count >= 2:
                is_malicious = True
                status_label = "🚨 MALICIOUS"
            elif suspicion_count == 1:
                is_malicious = True
                status_label = "⚠️ SUSPICIOUS"
            else:
                is_malicious = False
                status_label = "✅ HONEST"
            
            # Update trust score (exponential moving average)
            if client_id not in self.trust_scores:
                self.trust_scores[client_id] = 1.0  # Start with full trust
            
            # Decay trust based on suspicion level
            if suspicion_count >= 2:
                self.trust_scores[client_id] *= 0.5  # Severe trust reduction
            elif suspicion_count == 1:
                self.trust_scores[client_id] *= 0.8  # Moderate trust reduction
            else:
                self.trust_scores[client_id] = min(1.0, self.trust_scores[client_id] + 0.05)
            
            # Store results
            results[client_id] = {
                'cosine_similarity': similarity,
                'deviation': deviation,
                'z_score': z_score,
                'avg_deviation': avg_deviation,
                'trust_score': self.trust_scores[client_id],
                'is_malicious': is_malicious,
                'status_label': status_label,
                'suspicion_count': suspicion_count,
                'suspicion_signals': suspicion_signals,
                'reason': "; ".join(suspicion_signals) if suspicion_signals else "Normal behavior"
            }
        
        return results
    
    def _calculate_median_weights(self, client_weights: Dict[str, Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
        """Calculate component-wise median of all client weights"""
        median_weights = {}
        
        first_client = list(client_weights.values())[0]
        for key in first_client.keys():
            sample = first_client[key]
            if not self._is_float_tensor(sample):
                continue
            stacked = torch.stack([weights[key].to(torch.float32) for weights in client_weights.values()])
            median_weights[key] = torch.median(stacked, dim=0)[0]
        
        return median_weights
    
    def _get_detection_reason(self, similarity: float, z_score: float) -> str:
        """Get human-readable reason for detection"""
        reasons = []
        
        if similarity < self.similarity_threshold:
            reasons.append(f"Opposite direction (similarity={similarity:.3f})")
        
        if abs(z_score) > self.deviation_threshold:
            reasons.append(f"Extreme deviation (z-score={z_score:.2f})")
        
        return "; ".join(reasons) if reasons else "Normal behavior"
    
    def print_detection_report(self, detection_results: Dict[str, Dict], round_num: int):
        """Print formatted detection report"""
        print("\n" + "="*100)
        print(f"🔍 BYZANTINE DETECTION REPORT - Round {round_num}")
        print("="*100)
        
        print(f"\n{'Client':<15} {'Similarity':<12} {'Deviation':<12} {'Z-Score':<10} {'Trust':<8} {'Status':<15} {'Reason':<40}")
        print("-"*100)
        
        for client_id, result in detection_results.items():
            status = result.get('status_label', "🚨 MALICIOUS" if result['is_malicious'] else "✅ HONEST")
            similarity = result['cosine_similarity']
            deviation = result['deviation']
            z_score = result['z_score']
            trust = result['trust_score']
            reason = result['reason'][:40]  # Truncate for display
            
            print(f"{client_id:<15} {similarity:<12.4f} {deviation:<12.4f} {z_score:<10.2f} {trust:<8.3f} {status:<15} {reason:<40}")
        
        print("-"*100)
        
        # Summary
        malicious_clients = [cid for cid, r in detection_results.items() if r['is_malicious']]
        if malicious_clients:
            print(f"\n⚠️  Detected {len(malicious_clients)} malicious client(s): {', '.join(malicious_clients)}")
            for cid in malicious_clients:
                signals = detection_results[cid].get('suspicion_signals', [])
                print(f"   • {cid}: {', '.join(signals)}")
        else:
            print(f"\n✅ All clients appear honest")
        
        print("="*100)
    
    def get_trusted_clients(self, min_trust: float = 0.5) -> List[str]:
        """Get list of clients with trust score above threshold"""
        return [client_id for client_id, trust in self.trust_scores.items() 
                if trust >= min_trust]
    
    def should_exclude_client(self, client_id: str, min_trust: float = 0.3) -> bool:
        """Determine if client should be excluded from aggregation"""
        return self.trust_scores.get(client_id, 1.0) < min_trust


def demo_byzantine_detection():
    """Demo of Byzantine detection"""
    print("\n" + "🔍"*50)
    print("BYZANTINE CLIENT DETECTION DEMO")
    print("🔍"*50)
    
    # Create detector
    detector = ByzantineDetector(similarity_threshold=-0.5, deviation_threshold=2.0)
    
    # Simulate client weights (simplified example)
    print("\n📊 Simulating 4 clients with different behaviors...")
    
    # Honest clients have similar weights
    honest_weights = {
        'layer1.weight': torch.randn(10, 10) * 0.1,
        'layer1.bias': torch.randn(10) * 0.1
    }
    
    # Malicious client has inverted weights
    malicious_weights = {
        'layer1.weight': -torch.randn(10, 10) * 5.0,  # Opposite direction, larger magnitude
        'layer1.bias': -torch.randn(10) * 5.0
    }
    
    client_weights = {
        'bank': {k: v + torch.randn_like(v) * 0.01 for k, v in honest_weights.items()},
        'hospital': {k: v + torch.randn_like(v) * 0.01 for k, v in honest_weights.items()},
        'tech': {k: v + torch.randn_like(v) * 0.01 for k, v in honest_weights.items()},
        'malicious': malicious_weights
    }
    
    # Calculate global weights (average)
    global_weights = {}
    for key in honest_weights.keys():
        global_weights[key] = torch.mean(
            torch.stack([w[key] for w in client_weights.values()]), 
            dim=0
        )
    
    # Run detection
    for round_num in range(1, 4):
        print(f"\n{'='*100}")
        print(f"Round {round_num}")
        print(f"{'='*100}")
        
        results = detector.detect_malicious_clients(client_weights, global_weights, round_num)
        detector.print_detection_report(results, round_num)
        
        # Show trust evolution
        print(f"\n📊 Trust Score Evolution:")
        for client_id, trust in detector.trust_scores.items():
            bar = "█" * int(trust * 20)
            print(f"  {client_id:<15} {bar:<20} {trust:.3f}")


if __name__ == "__main__":
    demo_byzantine_detection()
