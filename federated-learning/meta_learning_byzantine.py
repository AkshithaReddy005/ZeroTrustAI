#!/usr/bin/env python3
"""
Meta-Learning for Adaptive Byzantine Detection
Replaces fixed weights with MAML-based meta-learner
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import Dict, List, Tuple, Optional
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

class MetaLearningByzantineDetector:
    """
    Meta-learning based Byzantine detector using MAML
    Learns optimal trust scoring weights automatically
    """
    
    def __init__(self, input_dim=4, meta_lr=0.01, inner_lr=0.1):
        """
        Initialize meta-learning detector
        
        Args:
            input_dim: Number of input features (acc, f1, similarity, round)
            meta_lr: Meta-learning rate
            inner_lr: Inner adaptation learning rate
        """
        self.input_dim = input_dim
        self.meta_lr = meta_lr
        self.inner_lr = inner_lr
        
        # Meta-learner network
        self.meta_learner = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 1),
            nn.Sigmoid()  # Output trust weight [0, 2]
        )
        
        self.meta_optimizer = optim.Adam(self.meta_learner.parameters(), lr=meta_lr)
        
        # Experience buffer for meta-learning
        self.experience_buffer = []
        self.max_buffer_size = 1000
        
        # Performance tracking
        self.meta_history = []
        self.adaptation_history = defaultdict(list)
        
    def extract_features(self, metrics: Dict, round_num: int) -> torch.Tensor:
        """
        Extract features for meta-learner
        
        Args:
            metrics: Client performance metrics
            round_num: Current federated round
            
        Returns:
            Feature tensor
        """
        features = torch.tensor([
            metrics.get('acc', 0.5),
            metrics.get('f1', 0.0),
            metrics.get('similarity', 0.9),
            round_num / 10.0  # Normalize round number
        ], dtype=torch.float32)
        
        return features
    
    def compute_trust_weight(self, metrics: Dict, round_num: int) -> float:
        """
        Compute adaptive trust weight using meta-learner
        
        Args:
            metrics: Client performance metrics
            round_num: Current federated round
            
        Returns:
            Adaptive trust weight
        """
        features = self.extract_features(metrics, round_num)
        
        with torch.no_grad():
            trust_weight = self.meta_learner(features)
            # Scale to [0.1, 2.0] range
            trust_weight = 0.1 + trust_weight.item() * 1.9
            
        return trust_weight
    
    def adapt_to_client(self, client_id: str, metrics_history: List[Dict], 
                       adaptation_steps: int = 5) -> Dict:
        """
        Adapt meta-learner to specific client behavior
        
        Args:
            client_id: Client identifier
            metrics_history: Historical performance metrics
            adaptation_steps: Number of adaptation steps
            
        Returns:
            Adapted model state
        """
        if len(metrics_history) < 2:
            return {}
        
        # Store original parameters
        original_params = {name: param.clone() 
                          for name, param in self.meta_learner.named_parameters()}
        
        # Create adaptation optimizer
        adapted_optimizer = optim.SGD(self.meta_learner.parameters(), lr=self.inner_lr)
        
        # Adapt to client-specific patterns
        for step in range(adaptation_steps):
            # Sample from client history
            if len(metrics_history) >= 2:
                sample_idx = np.random.randint(0, len(metrics_history) - 1)
                current_metrics = metrics_history[sample_idx]
                next_metrics = metrics_history[sample_idx + 1]
                
                # Predict trust weight
                features = self.extract_features(current_metrics, sample_idx)
                predicted_weight = self.meta_learner(features)
                
                # Compute adaptation loss based on actual improvement
                actual_improvement = (next_metrics.get('f1', 0) - current_metrics.get('f1', 0))
                target_weight = 1.0 + actual_improvement  # Higher weight for improvement
                
                loss = nn.MSELoss()(predicted_weight, torch.tensor([target_weight]))
                
                # Adaptation step
                adapted_optimizer.zero_grad()
                loss.backward()
                adapted_optimizer.step()
        
        # Store adapted parameters
        adapted_params = {name: param.clone() 
                        for name, param in self.meta_learner.named_parameters()}
        
        # Restore original parameters
        for name, param in self.meta_learner.named_parameters():
            param.data.copy_(original_params[name])
        
        self.adaptation_history[client_id].append(adapted_params)
        
        return adapted_params
    
    def meta_update(self, client_experiences: List[Tuple]):
        """
        Update meta-learner using MAML
        
        Args:
            client_experiences: List of (features, target_weight) tuples
        """
        if len(client_experiences) < 5:
            return
        
        # Sample batch of experiences
        batch_size = min(32, len(client_experiences))
        batch_indices = np.random.choice(len(client_experiences), batch_size, replace=False)
        
        meta_loss = 0.0
        
        for idx in batch_indices:
            features, target_weight = client_experiences[idx]
            
            # Forward pass
            predicted_weight = self.meta_learner(features)
            
            # Compute loss
            loss = nn.MSELoss()(predicted_weight, target_weight)
            meta_loss += loss
        
        # Meta-update
        self.meta_optimizer.zero_grad()
        meta_loss = meta_loss / batch_size
        meta_loss.backward()
        self.meta_optimizer.step()
        
        # Track meta-learning progress
        self.meta_history.append(meta_loss.item())
        
        if len(self.meta_history) % 10 == 0:
            logger.info(f"Meta-learning loss: {meta_loss.item():.4f}")
    
    def add_experience(self, metrics: Dict, round_num: int, actual_performance: float):
        """
        Add experience to buffer for meta-learning
        
        Args:
            metrics: Client performance metrics
            round_num: Current federated round
            actual_performance: Actual performance improvement
        """
        features = self.extract_features(metrics, round_num)
        target_weight = torch.tensor([1.0 + actual_performance])
        
        experience = (features, target_weight)
        self.experience_buffer.append(experience)
        
        # Limit buffer size
        if len(self.experience_buffer) > self.max_buffer_size:
            self.experience_buffer.pop(0)
    
    def get_adaptive_status(self, trust_weight: float) -> str:
        """
        Get adaptive status based on trust weight
        
        Args:
            trust_weight: Computed trust weight
            
        Returns:
            Status string
        """
        if trust_weight < 0.3:
            return "QUARANTINED (Meta-Learning)"
        elif trust_weight < 0.7:
            return "OBSERVATION (Meta-Learning)"
        elif trust_weight > 1.2:
            return "TRUSTED EXPERT (Meta-Learning)"
        else:
            return "VERIFIED (Meta-Learning)"
    
    def save_meta_model(self, path: str):
        """Save meta-learner state"""
        torch.save({
            'meta_learner': self.meta_learner.state_dict(),
            'meta_optimizer': self.meta_optimizer.state_dict(),
            'meta_history': self.meta_history,
            'experience_buffer': self.experience_buffer
        }, path)
        logger.info(f"Meta-learner saved to {path}")
    
    def load_meta_model(self, path: str):
        """Load meta-learner state"""
        checkpoint = torch.load(path)
        self.meta_learner.load_state_dict(checkpoint['meta_learner'])
        self.meta_optimizer.load_state_dict(checkpoint['meta_optimizer'])
        self.meta_history = checkpoint.get('meta_history', [])
        self.experience_buffer = checkpoint.get('experience_buffer', [])
        logger.info(f"Meta-learner loaded from {path}")
