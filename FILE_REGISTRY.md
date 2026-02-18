# ZeroTrust-AI File Registry

## 📁 File Creation Log

### **🗓️ February 18, 2026**

#### **Registry & Documentation**
| File | Purpose | Created By | Status |
|------|---------|------------|--------|
| `ARCHITECTURE_DIAGRAMS.md` | Complete architecture with mixed content | Cascade | ✅ Created |
| `ARCHITECTURE_MERMAID_ONLY.md` | Pure Mermaid diagrams only | Cascade | ✅ Created |
| `FILE_REGISTRY.md` | Master file creation registry | Cascade | ✅ Created |

#### **C2-DDoS Project Files**
- `c2_ddos/main.py` - Core detection pipeline with SPLT feature extraction
- `c2_ddos/README.md` - Project documentation and overview
- `c2_ddos/scripts/train_model.py` - TCN model training pipeline
- `c2_ddos/scripts/analyze_data.py` - Data analysis and visualization utilities
- `c2_ddos/scripts/feature_engineering.py` - RobustScaler + tail-padding + volumetric feature derivation
- `c2_ddos/scripts/snorkel_labeling.py` - Phase 1: 5 Snorkel LFs + label matrix + soft label generation
- `c2_ddos/scripts/redis_feature_store.py` - Phase 1: Redis bulk writes, PEP quarantine, TTL, InfluxDB queue
- `c2_ddos/scripts/train_autoencoder.py` - Phase 2: AE on 80K benign only + KneeLocator threshold
- `c2_ddos/scripts/train_isolation_forest.py` - Phase 2: IF on 13 volumetric features + contamination sweep
- `c2_ddos/scripts/train_tcn.py` - Phase 2: TCN with Snorkel soft labels + Redis SPLT reading
- `c2_ddos/scripts/ensemble_fusion.py` - Phase 3: GridSearchCV weight calibration + 3-tier ZT policy
- `c2_ddos/PROJECT_PLAN.md` - Concise project introduction and phased plan

#### **Data Processing & Analysis**
| File | Purpose | Created By | Status |
|------|---------|------------|--------|
| `unified_feature_extraction.py` | dpkt-based unified extraction from PCAPs | Cascade | ✅ Created |
| `create_final_balanced.py` | Create 238K balanced dataset (C2+DDoS+Normal) | Cascade | ✅ Created |
| `feature_analysis.py` | Analyze features in training dataset | Cascade | ✅ Created |
| `check_dataset_composition.py` | Verify dataset composition | Cascade | ✅ Created |
| `check_training_features.py` | Analyze training features | Cascade | ✅ Created |
| `analyze_feature_contributions.py` | Feature importance analysis | Cascade | ✅ Created |

#### **Validation & Debugging**
| File | Purpose | Created By | Status |
|------|---------|------------|--------|
| `validate_unified_data.py` | Validate unified extracted dataset | Cascade | ✅ Created |
| `debug_pcap.py` | Debug PCAP packet structure | Cascade | ✅ Created |

#### **Dataset Files Generated**
| File | Purpose | Size | Samples | Status |
|------|---------|------|---------|--------|
| `data/processed/master_unified_data.csv` | Unified C2+Normal extraction | ~50MB | 78,342 | ✅ Created |
| `data/processed/final_balanced_240k.csv` | Final training dataset | ~150MB | 238,014 | ✅ Created |
| `data/processed/final_balanced_240k.json` | Dataset summary metadata | ~5KB | N/A | ✅ Created |
| `data/processed/final_balanced_240k_blueprint.csv` | Blueprint-ready dataset: SPLT padded to 40 + derived volumetric + pseudo-directionality | ~162MB | 238,014 | ✅ Created |
| `data/processed/final_balanced_240k_blueprint.json` | Blueprint-ready dataset summary metadata | ~1KB | N/A | ✅ Created |

---

## 📋 File Registry Template

**For future file creation, use this format:**

```markdown
#### **[Category]**
| File | Purpose | Created By | Status |
|------|---------|------------|--------|
| `filename.ext` | Brief description | Your Name | ✅ Created |
```

---

## 🔍 File Locations

### **C2-DDoS Project Directory**
```
c2_ddos/
├── main.py                           # Main detection pipeline
├── README.md                         # Project documentation
├── PROJECT_PLAN.md                   # Complete project roadmap
├── data/
│   ├── raw/                         # Raw PCAP files
│   └── processed/                   # Processed datasets
├── models/                          # Trained models
├── notebooks/                       # Analysis notebooks
└── scripts/
    ├── train_model.py               # Model training script
    └── analyze_data.py              # Data analysis utilities
```
```

### **Scripts Directory (Root)**
```
scripts/
├── unified_feature_extraction.py
├── create_final_balanced.py
├── feature_analysis.py
├── check_dataset_composition.py
├── check_training_features.py
├── analyze_feature_contributions.py
├── validate_unified_data.py
└── debug_pcap.py
```

### **Data Directory**
```
data/processed/
├── master_unified_data.csv
├── final_balanced_240k.csv
└── final_balanced_240k.json
```

### **Documentation Directory**
```
/
├── ARCHITECTURE_DIAGRAMS.md
├── ARCHITECTURE_MERMAID_ONLY.md
└── FILE_REGISTRY.md
```

---

## 📝 Registry Rules

1. **All new files must be registered** immediately after creation
2. **Include purpose, creator, and status**
3. **Use the template format** for consistency
4. **Update locations** when files are moved
5. **Mark status** as ✅ Created, 🔄 Modified, or ❌ Deleted

---

## 🎯 Last Updated
**Date**: February 18, 2026  
**Total Registered Files: 19**  
**Registry Maintained By**: Cascade

---

## 📋 Future File Creation Protocol

**When creating any new file:**

1. **Create the file** using appropriate tool
2. **Immediately update** this registry
3. **Use the template format**:
   ```markdown
   | File | Purpose | Created By | Status |
   |------|---------|------------|--------|
   | `filename.ext` | Brief description | Your Name | ✅ Created |
   ```
4. **Update file locations** if needed
5. **Save the registry** immediately

**No exceptions - every file must be registered!**
