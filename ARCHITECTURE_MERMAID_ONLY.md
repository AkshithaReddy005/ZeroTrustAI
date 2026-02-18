# ZeroTrust-AI Architecture Mermaid Diagrams

## 1. Complete System Architecture

```mermaid
graph TB
    %% Define subgraphs for major components
    subgraph "🌐 Docker Network: ztai_net"
        %% PRO CALLOUT BOXES
        subgraph "🧠 AI BRAIN"
            direction LR
            CALLOUT1[**🧠 AI BRAIN**<br/>Multi-Model Threat Detection]
        end
        
        subgraph "🚪 GATEWAY LOCK"
            direction LR
            CALLOUT2[**🚪 GATEWAY LOCK**<br/>Real-time Enforcement]
        end
        
        subgraph "🔐 PRIVACY SYNC"
            direction LR
            CALLOUT3[**🔐 PRIVACY SYNC**<br/>Federated Intelligence]
        end
        
        subgraph "📊 Data Ingestion Layer"
            PCAP[📁 PCAP Files<br/>C2, DDoS, Normal]
            PARQUET[📊 Parquet Datasets<br/>DDoS-Friday]
            FEDERATED[🔄 Federated Client Data<br/>Enterprise/University/Datacenter]
        end
        
        subgraph "🔧 Data Processing Layer"
            UNIFIED[⚙️ Unified Feature Extraction<br/>dpkt-based]
            SPLT[📈 SPLT Features<br/>20-packet sequences]
            FLOW[🌊 Flow Statistics<br/>Duration, Protocol, Packets]
            BALANCED[📋 Balanced Dataset<br/>238K samples]
        end
        
        subgraph "🧠 Multi-Model Ensemble Layer"
            TCN[🧠 TCN Model<br/>Temporal Convolutional Network]
            AE[🤖 Autoencoder<br/>Unsupervised Anomaly Detection]
            IF[🌲 Isolation Forest<br/>Statistical Outlier Detection]
            ENSEMBLE[🔗 Ensemble Logic<br/>OR-combination]
        end
        
        subgraph "🛡️ Detection & Response Layer"
            DETECTOR[🔍 DETECTOR SERVICE<br/>Port 9000<br/>Multi-Model Inference]
            API[🌐 API GATEWAY<br/>Port 8000<br/>REST API Endpoints]
            REDIS[🗄️ REDIS<br/>Port 6379<br/>SOAR Actions & Cache<br/>💾 AOF/RDB Persistence]
            INFLUX[📊 INFLUXDB<br/>Port 8086<br/>Time-Series Metrics<br/>📅 7-day Retention Policy]
            PDP[🧠 POLICY DECISION POINT<br/>NIST SP 800-207<br/>Risk Assessment]
            PEP[🛡️ POLICY ENFORCEMENT POINT<br/>Micro-segmentation<br/>Lateral Movement Prevention]
            SOAR[🛡️ SOAR ENGINE<br/>IP Blocking & Rate Limiting]
        end
        
        subgraph "📊 Visualization & Monitoring"
            STREAMLIT[📱 STREAMLIT DASHBOARD<br/>Port 8501<br/>Real-time UI]
            REACT[🌐 REACT SOC DASHBOARD<br/>Web Interface]
            WEBSOCKET[📡 WEBSOCKET SERVER<br/>Port 9002<br/>Real-time Updates]
            COLLECTOR[🔄 DATA COLLECTOR<br/>Flow Aggregation]
        end
        
        subgraph "🔄 Federated Learning"
            ENTERPRISE[🏢 Enterprise Client<br/>Business Traffic]
            UNIVERSITY[🎓 University Client<br/>Academic Traffic]
            DATACENTER[🖥️ Datacenter Client<br/>Cloud Infrastructure]
            FED_SERVER[🌐 Federated Server<br/>🛡️ Robust Aggregation<br/>Krum/Median Filtering]
            HONEYPOT[🍯 HONEY-TOKEN SERVER<br/>Attacker Intelligence<br/>Fake C2 Infrastructure]
        end
        
        subgraph "📁 PCAP Processing"
            PCAP_REPLAY[📁 PCAP REPLAY SERVICE<br/>File Processing & Replay]
        end
    end
    
    %% Data Flow Connections - Organized by layers
    %% Data Processing Flow
    PCAP --> UNIFIED
    PARQUET --> UNIFIED
    FEDERATED --> UNIFIED
    
    UNIFIED --> SPLT
    UNIFIED --> FLOW
    SPLT --> BALANCED
    FLOW --> BALANCED
    
    %% Model Training Flow
    BALANCED --> TCN
    BALANCED --> AE
    BALANCED --> IF
    
    TCN --> ENSEMBLE
    AE --> ENSEMBLE
    IF --> ENSEMBLE
    
    %% Detection Pipeline Flow - FIXED: Direct Ensemble to SOAR
    ENSEMBLE --> DETECTOR
    DETECTOR --> API
    ENSEMBLE -.-> SOAR
    
    %% Storage & SOAR Flow - FIXED: Redis vs InfluxDB Roles
    API --> REDIS
    API --> INFLUX
    REDIS --> PDP
    PDP --> PEP
    PEP --> SOAR
    SOAR --> REDIS
    
    %% Dashboard & Monitoring Flow
    API -.-> STREAMLIT
    API -.-> REACT
    STREAMLIT -.-> REDIS
    STREAMLIT -.-> INFLUX
    REACT -.-> REDIS
    REACT -.-> INFLUX
    WEBSOCKET -.-> STREAMLIT
    COLLECTOR -.-> INFLUX
    
    %% Federated Learning Flow - FIXED: Model Weights to Control Plane
    ENTERPRISE --> FED_SERVER
    UNIVERSITY --> FED_SERVER
    DATACENTER --> FED_SERVER
    FED_SERVER --> TCN
    FED_SERVER --> AE
    HONEYPOT --> FED_SERVER
    
    %% PCAP Processing Flow
    PCAP_REPLAY --> API
    
    %% Styling
    classDef dataLayer fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef processingLayer fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef modelLayer fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef detectionLayer fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef vizLayer fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    classDef federatedLayer fill:#f1f8e9,stroke:#33691e,stroke-width:2px
    classDef pcapLayer fill:#e0f2f1,stroke:#004d40,stroke-width:2px
    
    class PCAP,PARQUET,FEDERATED dataLayer
    class UNIFIED,SPLT,FLOW,BALANCED processingLayer
    class TCN,AE,IF,ENSEMBLE modelLayer
    class DETECTOR,API,REDIS,INFLUX,PDP,PEP,SOAR detectionLayer
    class STREAMLIT,REACT,WEBSOCKET,COLLECTOR vizLayer
    class ENTERPRISE,UNIVERSITY,DATACENTER,FED_SERVER,HONEYPOT federatedLayer
    class PCAP_REPLAY pcapLayer
```

## 2. Real-time Data Flow Architecture

```mermaid
sequenceDiagram
    participant NT as Network Traffic
    participant API as API Gateway
    participant DET as Detector Service
    participant TCN as TCN Model
    participant AE as Autoencoder
    participant IF as Isolation Forest
    participant REDIS as Redis
    participant SOAR as SOAR Engine
    participant DASH as Dashboard
    
    NT->>API: Flow Features (JSON)
    API->>DET: Detection Request
    DET->>TCN: Temporal Analysis
    DET->>AE: Anomaly Detection
    DET->>IF: Statistical Analysis
    
    TCN-->>DET: TCN Prediction
    AE-->>DET: Anomaly Score
    IF-->>DET: Outlier Score
    
    DET->>DET: Ensemble Logic (OR)
    DET->>API: Threat Event
    
    API->>REDIS: Store Threat Data
    API->>SOAR: Trigger SOAR if High Risk
    
    SOAR->>REDIS: Store Block Action
    SOAR-->>API: Response Action
    
    API->>DASH: Real-time Update
    REDIS->>DASH: SOAR Actions
```

## 3. SOAR Decision Flow

```mermaid
flowchart TD
    TE[Threat Event] --> RS{Risk Score}
    RS -->|< 0.70| MONITOR[👁️ Monitor Only<br/>Show in feed]
    RS -->|0.70-0.85| MEDIUM{Volumetric?}
    RS -->|≥ 0.85| HIGH{Confidence ≥ 0.90?}
    
    MEDIUM -->|Yes| RATE[⚠️ Rate Limit<br/>Medium-risk containment]
    MEDIUM -->|No| MONITOR
    
    HIGH -->|Yes| BLOCK[🚫 Block IP<br/>High-risk prevention]
    HIGH -->|No| MONITOR
    
    RATE --> REDIS_STORE[💾 Store in Redis<br/>TTL: 24 hours]
    BLOCK --> REDIS_STORE
    MONITOR --> FEED[📊 Add to Threat Feed]
    
    REDIS_STORE --> INFLUX_METRICS[📊 Store Metrics in InfluxDB<br/>Detection Latency, Response Time]
    FEED --> INFLUX_METRICS
    REDIS_STORE --> DASH_UPDATE[📱 Update Dashboard<br/>SOAR Panel]
    INFLUX_METRICS --> DASH_UPDATE
```

## 4. Service Dependencies (Docker Compose)

```mermaid
graph LR
    subgraph "Service Dependencies"
        API[API Gateway] --> REDIS[Redis]
        API --> DETECTOR[Detector]
        DASH[Dashboard] --> API
        DASH --> REDIS
        DASH --> INFLUX[InfluxDB]
        COLLECTOR[Collector] --> API
        PCAP_REPLAY[PCAP Replay] --> API
        WEBSOCKET[WebSocket] --> DETECTOR
    end
    
    subgraph "Port Mappings"
        API --> P8000[Port 8000]
        DETECTOR --> P9000[Port 9000]
        DASH --> P8501[Port 8501]
        WEBSOCKET --> P9002[Port 9002]
        REDIS --> P6379[Port 6379]
        INFLUX --> P8086[Port 8086]
    end
    
    classDef service fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef storage fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef port fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    
    class API,DETECTOR,DASH,COLLECTOR,PCAP_REPLAY,WEBSOCKET service
    class REDIS,INFLUX storage
    class P8000,P9000,P8501,P9002,P6379,P8086 port
```

## 5. Federated Learning Architecture

```mermaid
graph TB
    subgraph "Federated Learning Infrastructure"
        subgraph "Client Sites"
            ENTERPRISE[🏢 Enterprise A<br/>Business Traffic]
            UNIVERSITY[🎓 University B<br/>Academic Traffic]
            DATACENTER[🖥️ Datacenter C<br/>Cloud Infrastructure]
        end
        
        subgraph "Federated Server"
            FED_SERVER[🌐 Federated Server<br/>Model Aggregation]
            GLOBAL_MODEL[📊 Global Model<br/>Distributed Updates]
        end
        
        subgraph "Training Process"
            LOCAL_TRAIN[🔧 Local Training<br/>Privacy-Preserving]
            MODEL_UPDATES[📦 Model Updates<br/>Gradients/Weights]
            AGGREGATION[🔄 Federated Aggregation<br/>FedAvg/FedProx]
        end
    end
    
    ENTERPRISE --> LOCAL_TRAIN
    UNIVERSITY --> LOCAL_TRAIN
    DATACENTER --> LOCAL_TRAIN
    
    LOCAL_TRAIN --> MODEL_UPDATES
    MODEL_UPDATES --> FED_SERVER
    
    FED_SERVER --> AGGREGATION
    AGGREGATION --> GLOBAL_MODEL
    
    GLOBAL_MODEL --> ENTERPRISE
    GLOBAL_MODEL --> UNIVERSITY
    GLOBAL_MODEL --> DATACENTER
    
    classDef client fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef server fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef process fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    
    class ENTERPRISE,UNIVERSITY,DATACENTER client
    class FED_SERVER,GLOBAL_MODEL server
    class LOCAL_TRAIN,MODEL_UPDATES,AGGREGATION process
```

## 6. Trust Score Decay Visualization

```mermaid
graph LR
    A[Initial Trust: 100%] --> B[C2 Beacon Detected: 85%]
    B --> C[Beaconing Continues: 60%] 
    C --> D[Anomalous Patterns: 30%]
    D --> E[Block Threshold: <10%]
    
    style A fill:#4caf50
    style B fill:#ff9800  
    style C fill:#ff5722
    style D fill:#f44336
    style E fill:#d32f2f
```

## 7. Zero Trust Micro-segmentation

```mermaid
graph TB
    subgraph "Network Segments"
        CORPORATE[🏢 Corporate Zone<br/>High Trust]
        UNIVERSITY[🎓 University Zone<br/>Medium Trust]  
        DMZ[🖥️ DMZ Zone<br/>Low Trust]
        HONEYPOT[🍯 Honeypot Zone<br/>Decoy]
    end
    
    subgraph "Policy Enforcement Points"
        GATEWAY[🛡️ Gateway PEP<br/>Network ingress/egress]
        SEGMENT[🔒 Segment PEP<br/>Inter-zone communication]
        ENDPOINT[💻 Endpoint PEP<br/>Host-level enforcement]
        HONEYPOT_PEP[🍯 Honeypot PEP<br/>Attacker containment]
    end
    
    CORPORATE --> SEGMENT
    UNIVERSITY --> SEGMENT
    DMZ --> GATEWAY
    HONEYPOT --> HONEYPOT_PEP
    
    GATEWAY --> CORPORATE
    SEGMENT --> UNIVERSITY
    ENDPOINT --> DMZ
    HONEYPOT_PEP --> GATEWAY
    
    classDef zone fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef pep fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    
    class CORPORATE,UNIVERSITY,DMZ,HONEYPOT zone
    class GATEWAY,SEGMENT,ENDPOINT,HONEYPOT_PEP pep
```

## 8. PDP vs PEP Architecture

```mermaid
graph TB
    subgraph "Policy Decision Point (PDP)"
        RISK[🧠 Risk Assessment Engine]
        TRUST[📊 Trust Score Calculation]  
        POLICY[🎯 Policy Rule Engine]
        AUDIT[📋 Compliance Audit Log]
    end
    
    subgraph "Policy Enforcement Point (PEP)"
        ENFORCE[🛡️ Traffic Enforcement]
        ACCESS[🔒 Access Control]
        RATE[⚠️ Rate Limiting]
        BLOCK[🚫 IP Blocking]
    end
    
    RISK --> TRUST
    TRUST --> POLICY
    POLICY --> AUDIT
    
    POLICY --> ENFORCE
    ENFORCE --> ACCESS
    ACCESS --> RATE
    RATE --> BLOCK
    
    classDef pdp fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef pep fill:#fff3e0,stroke:#e65100,stroke-width:2px
    
    class RISK,TRUST,POLICY,AUDIT pdp
    class ENFORCE,ACCESS,RATE,BLOCK pep
```
