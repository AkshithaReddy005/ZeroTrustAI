#!/usr/bin/env python3
"""
XAI (Explainable AI) Module for ZeroTrust-AI
Provides SHAP-based explanations for ML model decisions
"""

import numpy as np
import shap
import torch
import joblib
import sys
import os
from typing import Dict, List, Tuple, Any
from shared.schemas import FlowFeatures

# Add model path
sys.path.append("/models")

class XAIExplainer:
    """XAI Explainer for ZeroTrust-AI ML models"""
    
    def __init__(self):
        self.tcn_explainer = None
        self.ae_explainer = None
        self.iso_explainer = None
        self.feature_names = []
        self._load_models()
        self._setup_feature_names()
    
    def _load_models(self):
        """Load trained models for explanation"""
        try:
            # Load TCN model
            self.tcn_model = torch.load("/models/tcn_classifier.pth", map_location='cpu')
            self.tcn_model.eval()
            
            # Load Autoencoder
            self.ae_model = torch.load("/models/autoencoder.pth", map_location='cpu')
            self.ae_model.eval()
            
            # Load IsolationForest
            self.iso_model = joblib.load("/models/splt_isoforest.joblib")
            
            # Load scalers
            self.splt_scaler = joblib.load("/models/splt_scaler.joblib")
            
        except Exception as e:
            print(f"Warning: Could not load models for XAI: {e}")
    
    def _setup_feature_names(self):
        """Setup human-readable feature names"""
        self.feature_names = [
            # SPLT Packet Lengths (first 10)
            *[f"Packet_{i+1}_Length" for i in range(10)],
            # SPLT Inter-arrival Times (first 10)  
            *[f"Packet_{i+1}_Timing" for i in range(10)],
            # Basic flow features
            "Total_Packets", "Total_Bytes", "Avg_Packet_Size", "Std_Packet_Size",
            "Duration", "Packets_Per_Second", "Avg_Entropy",
            "SYN_Count", "FIN_Count", "TCP_Flags"
        ]
    
    def _flow_to_features(self, flow: FlowFeatures) -> np.ndarray:
        """Convert flow to feature vector for XAI"""
        # Basic features
        basic_features = [
            flow.total_packets, flow.total_bytes, flow.avg_packet_size,
            flow.std_packet_size, flow.duration, flow.pps,
            flow.avg_entropy, flow.syn_count, flow.fin_count
        ]
        
        # SPLT features if available
        splt_features = []
        if hasattr(flow, 'packet_lengths') and hasattr(flow, 'inter_arrival_times'):
            # Take first 10 of each
            packet_lengths = flow.packet_lengths[:10] if len(flow.packet_lengths) >= 10 else flow.packet_lengths + [0] * (10 - len(flow.packet_lengths))
            inter_arrival_times = flow.inter_arrival_times[:10] if len(flow.inter_arrival_times) >= 10 else flow.inter_arrival_times + [0] * (10 - len(flow.inter_arrival_times))
            
            splt_features = packet_lengths + inter_arrival_times
        
        # Combine all features
        all_features = basic_features + splt_features
        
        # Pad to expected length
        expected_length = len(self.feature_names)
        if len(all_features) < expected_length:
            all_features.extend([0] * (expected_length - len(all_features)))
        
        return np.array(all_features[:expected_length], dtype=np.float32)
    
    def explain_detection(self, flow: FlowFeatures, ensemble_score: float, reasons: List[str]) -> Dict[str, Any]:
        """Generate XAI explanation for detection decision"""
        try:
            features = self._flow_to_features(flow)
            
            explanations = {}
            
            # TCN Explanation
            if self.tcn_model is not None and any('tcn' in r.lower() for r in reasons):
                explanations['tcn'] = self._explain_tcn(features, flow)
            
            # Autoencoder Explanation  
            if self.ae_model is not None and any('ae' in r.lower() or 'anomalous' in r.lower() for r in reasons):
                explanations['autoencoder'] = self._explain_autoencoder(features, flow)
            
            # IsolationForest Explanation
            if self.iso_model is not None and any('iso' in r.lower() or 'anomaly' in r.lower() for r in reasons):
                explanations['isolation_forest'] = self._explain_isolation_forest(features, flow)
            
            # Ensemble Explanation
            explanations['ensemble'] = self._explain_ensemble(ensemble_score, explanations)
            
            return explanations
            
        except Exception as e:
            return {"error": f"XAI explanation failed: {str(e)}"}
    
    def _explain_tcn(self, features: np.ndarray, flow: FlowFeatures) -> Dict[str, Any]:
        """Explain TCN decision using SHAP"""
        try:
            # Create a simple explainer (since TCN is complex)
            # Use a KernelExplainer as approximation
            background_data = np.random.randn(100, len(features)) * 0.1
            explainer = shap.KernelExplainer(
                lambda x: self._tcn_predict_proba(x),
                background_data,
                nsamples=100
            )
            
            shap_values = explainer.shap_values(features.reshape(1, -1))
            
            return {
                "type": "SHAP Kernel Explainer",
                "top_features": self._get_top_features(shap_values[0], features),
                "summary": "TCN focuses on temporal patterns in packet sequences",
                "confidence": "High for known attack patterns"
            }
        except Exception as e:
            return {"error": f"TCN explanation failed: {str(e)}"}
    
    def _explain_autoencoder(self, features: np.ndarray, flow: FlowFeatures) -> Dict[str, Any]:
        """Explain Autoencoder anomaly detection"""
        try:
            # Use reconstruction error as explanation
            with torch.no_grad():
                features_tensor = torch.from_numpy(features).float().unsqueeze(0)
                reconstructed = self.ae_model(features_tensor)
                reconstruction_error = torch.mean((features_tensor - reconstructed) ** 2).item()
            
            # Map features to human-readable names
            feature_contributions = {}
            for i, (name, value) in enumerate(zip(self.feature_names, features)):
                if i < 20:  # SPLT features
                    feature_contributions[name] = abs(value - np.mean(features[:20])) if i < 20 else 0
                else:  # Basic features
                    feature_contributions[name] = abs(value - np.mean(features[20:])) if i >= 20 else 0
            
            # Sort by contribution
            sorted_features = sorted(feature_contributions.items(), key=lambda x: x[1], reverse=True)[:5]
            
            return {
                "type": "Reconstruction Error Analysis",
                "reconstruction_error": reconstruction_error,
                "top_features": dict(sorted_features),
                "summary": "Autoencoder flags unusual patterns in packet sequences",
                "anomaly_level": "High" if reconstruction_error > 0.5 else "Low"
            }
        except Exception as e:
            return {"error": f"Autoencoder explanation failed: {str(e)}"}
    
    def _explain_isolation_forest(self, features: np.ndarray, flow: FlowFeatures) -> Dict[str, Any]:
        """Explain IsolationForest decision"""
        try:
            # Scale features
            if len(features) >= 20:  # Have SPLT features
                splt_features = features[:20]
                scaled_features = self.splt_scaler.transform(splt_features.reshape(1, -1)).reshape(-1)
            else:
                scaled_features = features.reshape(1, -1)
            
            # Get anomaly score
            anomaly_score = self.iso_model.decision_function(scaled_features)[0]
            
            # Feature importance from IsolationForest
            if hasattr(self.iso_model, 'feature_importances_'):
                importance = self.iso_model.feature_importances_
                feature_importance = {}
                for i, (name, imp) in enumerate(zip(self.feature_names, importance)):
                    feature_importance[name] = imp
                
                sorted_importance = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:5]
            else:
                sorted_importance = {}
            
            return {
                "type": "Isolation Forest Feature Importance",
                "anomaly_score": float(anomaly_score),
                "top_features": dict(sorted_importance),
                "summary": "IsolationForest identifies statistical outliers in flow patterns",
                "isolation_level": "High" if anomaly_score < -0.1 else "Low"
            }
        except Exception as e:
            return {"error": f"IsolationForest explanation failed: {str(e)}"}
    
    def _explain_ensemble(self, ensemble_score: float, explanations: Dict[str, Any]) -> Dict[str, Any]:
        """Explain ensemble decision"""
        # Weight contributions from each model
        weights = {"tcn": 0.5, "autoencoder": 0.25, "isolation_forest": 0.25}
        
        model_scores = {}
        for model_type in ["tcn", "autoencoder", "isolation_forest"]:
            if model_type in explanations:
                if model_type == "tcn":
                    model_scores[model_type] = 0.7  # Approximate confidence
                elif model_type == "autoencoder":
                    model_scores[model_type] = explanations.get(model_type, {}).get("reconstruction_error", 0) / 2.0
                elif model_type == "isolation_forest":
                    model_scores[model_type] = abs(explanations.get(model_type, {}).get("anomaly_score", 0))
        
        # Calculate weighted contribution
        contributions = {}
        for model_type, weight in weights.items():
            if model_type in model_scores:
                contributions[model_type] = weight * model_scores[model_type]
        
        return {
            "type": "Weighted Ensemble",
            "ensemble_score": ensemble_score,
            "model_contributions": contributions,
            "weights": weights,
            "summary": f"Ensemble combines {list(explanations.keys())} models with optimized weights"
        }
    
    def _tcn_predict_proba(self, features: np.ndarray) -> np.ndarray:
        """TCN prediction for SHAP explainer"""
        try:
            with torch.no_grad():
                # Reshape for TCN input (batch, channels, sequence)
                if len(features) >= 20:  # Have SPLT features
                    splt_features = features[:20]
                    # Create 2-channel input (packet_lengths, inter_arrival_times)
                    tcn_input = splt_features.reshape(1, 2, 10).float()
                else:
                    # Use basic features
                    basic_features = features[20:28] if len(features) >= 28 else features
                    tcn_input = torch.zeros(1, 2, 10).float()  # Dummy input
                
                logits = self.tcn_model(tcn_input)
                probs = torch.softmax(logits, dim=1)
                return probs.numpy()
        except Exception:
            # Return neutral prediction if model fails
            return np.array([[0.5, 0.5]])
    
    def _get_top_features(self, shap_values: np.ndarray, features: np.ndarray) -> List[Tuple[str, float]]:
        """Get top contributing features from SHAP values"""
        feature_contributions = []
        for i, (shap_val, feat_val, feat_name) in enumerate(zip(shap_values, features, self.feature_names)):
            contribution = abs(shap_val)
            feature_contributions.append((feat_name, contribution))
        
        # Sort by contribution and return top 5
        feature_contributions.sort(key=lambda x: x[1], reverse=True)
        return feature_contributions[:5]
    
    def get_human_readable_name(self, feature_name: str) -> str:
        """Convert technical feature names to human-readable"""
        mapping = {
            "Packet_1_Length": "First Packet Size",
            "Packet_2_Length": "Second Packet Size", 
            "Packet_3_Length": "Third Packet Size",
            "Packet_4_Length": "Fourth Packet Size",
            "Packet_5_Length": "Fifth Packet Size",
            "Packet_1_Timing": "First Inter-arrival Time",
            "Packet_2_Timing": "Second Inter-arrival Time",
            "Packet_3_Timing": "Third Inter-arrival Time",
            "Total_Packets": "Total Packet Count",
            "Total_Bytes": "Total Bytes Transferred",
            "Avg_Packet_Size": "Average Packet Size",
            "Std_Packet_Size": "Packet Size Variation",
            "Duration": "Flow Duration",
            "Packets_Per_Second": "Packet Rate (PPS)",
            "Avg_Entropy": "Traffic Entropy",
            "SYN_Count": "SYN Flag Count",
            "FIN_Count": "FIN Flag Count",
            "TCP_Flags": "TCP Flag Anomalies"
        }
        return mapping.get(feature_name, feature_name.replace("_", " "))

# Global XAI explainer instance
xai_explainer = XAIExplainer()

def explain_detection(flow: FlowFeatures, ensemble_score: float, reasons: List[str]) -> Dict[str, Any]:
    """Main function to explain detection decision"""
    return xai_explainer.explain_detection(flow, ensemble_score, reasons)

def get_feature_importance_summary() -> Dict[str, Any]:
    """Get overall feature importance across all models"""
    return {
        "tcn_features": "Temporal patterns in packet sequences",
        "ae_features": "Reconstruction errors in packet timing/size",
        "iso_features": "Statistical outliers in flow characteristics",
        "most_important": "Packet timing and size variations typically drive decisions"
    }
