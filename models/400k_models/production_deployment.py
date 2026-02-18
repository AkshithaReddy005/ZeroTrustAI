
# PRODUCTION DEPLOYMENT CODE
def detect_attack(flow_features):
    """
    Production-ready attack detection function
    """
    # Load models (in production, load once at startup)
    tcn_model = load_tcn_model()
    ae_model = load_ae_model()
    scaler_tcn = load_tcn_scaler()
    scaler_ae = load_ae_scaler()
    
    # Preprocess features
    X_tcn = scaler_tcn.transform(flow_features)
    X_ae = scaler_ae.transform(flow_features)
    
    # Get predictions
    with torch.no_grad():
        tcn_prob = tcn_model(torch.FloatTensor(X_tcn)).item()
        
        reconstructed = ae_model(torch.FloatTensor(X_ae))
        reconstruction_error = torch.mean((X_ae - reconstructed) ** 2).item()
    
    # Normalize reconstruction error
    # (In production, precompute min/max from training)
    ae_error_normalized = (reconstruction_error - AE_MIN) / (AE_MAX - AE_MIN)
    
    # FINAL PRODUCTION LOGIC
    TCN_THRESHOLD = 0.4
    AE_THRESHOLD = 0.95
    
    tcn_prediction = tcn_prob >= TCN_THRESHOLD
    ae_prediction = ae_error_normalized >= AE_THRESHOLD
    
    # Ensemble decision
    is_attack = tcn_prediction or ae_prediction
    
    return {
        'is_attack': is_attack,
        'tcn_confidence': tcn_prob,
        'ae_anomaly_score': ae_error_normalized,
        'final_decision': is_attack
    }

# Usage:
# result = detect_attack(flow_features)
# if result['is_attack']:
#     block_traffic()
# else:
#     allow_traffic()
