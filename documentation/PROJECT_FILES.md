# ZeroTrust-AI Project Files Overview

## Core Application Files

### Services (Main Application)
- **`services/detector/app/main.py`** - Main detection service with ML models
- **`services/api-gateway/app/main.py`** - External API gateway  
- **`services/pcap-replay/app.py`** - PCAP replay for testing
- **`services/collector/app.py`** - Metrics collection service

### Configuration
- **`infra/docker-compose.yml`** - All services orchestration
- **`shared/schemas.py`** - Pydantic data models
- **`.gitignore`** - Git ignore rules
- **`.gitattributes`** - Git LFS configuration

## Data & Models

### Datasets
- **`data/raw/`** - Original PCAP files
  - `Benign-Monday-no-metadata.parquet`
  - `DoS-Wednesday-no-metadata.parquet`
  - `capture20110810.binetflow`
- **`data/processed/splt_features.csv`** - Extracted SPLT features
- **`data/processed/splt_features_labeled.csv`** - Labeled dataset

### Trained Models
- **`models/tcn_classifier.pth`** - TCN model (98.58% accuracy)
- **`models/autoencoder.pth`** - Autoencoder model
- **`models/ae_threshold.txt`** - AE anomaly threshold
- **`models/splt_isoforest.joblib`** - Isolation Forest model
- **`models/splt_scaler.joblib`** - Feature scaler

## Scripts (Training & Processing)

### Model Training
- **`scripts/train_tcn.py`** - Train TCN classifier
- **`scripts/train_autoencoder.py`** - Train Autoencoder
- **`scripts/train_isoforest_splt.py`** - Train Isolation Forest
- **`scripts/evaluate_models.py`** - Model evaluation with metrics

### Data Processing
- **`scripts/extract_splt_nfstream.py`** - Extract SPLT from PCAP
- **`scripts/extract_splt_lite.py`** - Lightweight SPLT extraction
- **`scripts/build_labeled_splt_ctu.py`** - Create labeled dataset

### Utilities
- **`scripts/demo_minimal.py`** - Minimal demo
- **`scripts/test_malicious.py`** - Test with malicious data
- **`scripts/download_cicids2018.py`** - Download dataset

## Documentation

- **`docs/TECHNICAL_DOCUMENTATION.md`** - Complete technical reference
- **`docs/TECHNICAL_OVERVIEW.md`** - High-level overview
- **`docs/WORKFLOW.md`** - End-to-end workflow

### Planning
- **`PLAN.md`** - Project plan and status
- **`EXPERIMENT_LOG.md`** - Experiment tracking (git-ignored)
- **`README.md`** - Project description

## Most Important Files (Priority Order)

### 1. Core Detection
- **`services/detector/app/main.py`** - Main detection logic
- **`models/tcn_classifier.pth`** - Best performing model

### 2. Training Pipeline
- **`scripts/train_tcn.py`** - Train the main classifier
- **`scripts/evaluate_models.py`** - Test model performance

### 3. Data Processing
- **`scripts/extract_splt_nfstream.py`** - Feature extraction
- **`data/processed/splt_features_labeled.csv`** - Training data

### 4. Deployment
- **`infra/docker-compose.yml`** - Run the entire system
- **`services/api-gateway/app/main.py`** - External API

### 5. Documentation
- **`docs/WORKFLOW.md`** - How the system works
- **`docs/TECHNICAL_DOCUMENTATION.md`** - Technical details

## File Dependencies

```
PCAP files → extract_splt_nfstream.py → splt_features.csv
                                                    ↓
                                            train_tcn.py → tcn_classifier.pth
                                                    ↓
                                        detector/app/main.py → API
```

## Directory Structure Summary

- **`services/`** - Running applications (microservices)
- **`scripts/`** - One-time execution (training, processing)
- **`data/`** - Static data files
- **`models/`** - Trained ML models
- **`docs/`** - Documentation
- **`infra/`** - Infrastructure configuration

## Key Points

- The **detector service** is the heart of the system - it loads all models and makes real-time threat decisions
- **TCN model** achieves 98.58% accuracy and is the primary classifier
- **SPLT features** enable detection without decrypting traffic
- **Docker Compose** orchestrates the entire microservices stack
- **Documentation** provides comprehensive technical and workflow details
