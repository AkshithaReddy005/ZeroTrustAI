#!/usr/bin/env python3
"""
Phase 1: Redis Feature Store Integration
Handles bulk writes of SPLT sequences and flow features to Redis.
AOF persistence enabled. Pipeline bulk writes for performance.
"""

import redis
import json
import numpy as np
import pandas as pd
import logging
import joblib
from pathlib import Path
from sklearn.preprocessing import RobustScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Redis config
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
FLOW_TTL_SECONDS = 3600       # 1-hour TTL on flow records
QUARANTINE_TTL_SECONDS = 1800  # 30-min TTL on quarantine entries
BATCH_SIZE = 500               # Flows per pipeline.execute() call

# 13 volumetric features for Isolation Forest
VOLUMETRIC_FEATURES = [
    'pps', 'bps', 'duration', 'total_packets', 'total_bytes',
    'mean_packet_size', 'std_packet_size', 'mean_iat', 'std_iat',
    'upload_bytes', 'download_bytes', 'protocol', 'upload_ratio'
]

# 40 SPLT features for TCN
SPLT_FEATURES = (
    [f'splt_len_{i}' for i in range(1, 21)] +
    [f'splt_iat_{i}' for i in range(1, 21)]
)


class RedisFeatureStore:
    """
    Redis-backed feature store for ZTAI platform.
    Roles:
      1. Feature Store  — write SPLT sequences during extraction
      2. PEP Lookup     — sub-ms quarantine IP check on hot path
      3. TTL Quarantine — auto-expiring blocked IP list
    """

    def __init__(self, host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB):
        self.client = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self._check_connection()

    def _check_connection(self):
        try:
            self.client.ping()
            logger.info(f"✅ Redis connected at {REDIS_HOST}:{REDIS_PORT}")
        except redis.ConnectionError:
            logger.warning("⚠️  Redis not reachable — running in offline mode")
            self.client = None

    def is_available(self) -> bool:
        return self.client is not None

    # ─────────────────────────────────────────────
    # FEATURE STORE — BULK WRITE
    # ─────────────────────────────────────────────

    def write_flows_bulk(self, df: pd.DataFrame):
        """
        Write all flows to Redis using pipeline bulk writes.
        Single round-trip per BATCH_SIZE flows — never write one at a time.
        """
        if not self.is_available():
            logger.warning("Redis unavailable — skipping feature store write")
            return

        total = len(df)
        written = 0
        pipe = self.client.pipeline()

        for idx, row in df.iterrows():
            flow_id = str(row.get('flow_id', idx))
            key = f"flow:{flow_id}"

            # Build feature mapping (Redis Hash)
            mapping = {}
            for col in SPLT_FEATURES:
                if col in row.index:
                    mapping[col] = str(float(row[col]))
            for col in VOLUMETRIC_FEATURES:
                if col in row.index:
                    mapping[col] = str(float(row[col]))
            mapping['attack_type'] = str(row.get('attack_type', 'Unknown'))
            mapping['snorkel_prob'] = str(float(row.get('snorkel_prob', 0.5)))
            mapping['label'] = str(int(row.get('label', 0)))

            pipe.hset(key, mapping=mapping)
            pipe.expire(key, FLOW_TTL_SECONDS)
            written += 1

            # Execute batch
            if written % BATCH_SIZE == 0:
                pipe.execute()
                pipe = self.client.pipeline()
                logger.info(f"  Written {written:,}/{total:,} flows to Redis...")

        # Flush remaining
        pipe.execute()
        logger.info(f"✅ Bulk write complete: {written:,} flows → Redis")

    # ─────────────────────────────────────────────
    # FEATURE STORE — READ (TCN Training)
    # ─────────────────────────────────────────────

    def read_splt_batch(self, flow_ids: list) -> np.ndarray:
        """
        Read SPLT sequences from Redis for TCN training.
        Returns array of shape (N, 40).
        """
        if not self.is_available():
            return None

        pipe = self.client.pipeline()
        for flow_id in flow_ids:
            pipe.hgetall(f"flow:{flow_id}")
        results = pipe.execute()

        sequences = []
        for r in results:
            if r:
                seq = [float(r.get(f, 0.0)) for f in SPLT_FEATURES]
                sequences.append(seq)
            else:
                sequences.append([0.0] * 40)

        return np.array(sequences, dtype=np.float32)

    def read_volumetric_batch(self, flow_ids: list) -> np.ndarray:
        """
        Read volumetric features from Redis for IF training.
        Returns array of shape (N, 13).
        """
        if not self.is_available():
            return None

        pipe = self.client.pipeline()
        for flow_id in flow_ids:
            pipe.hgetall(f"flow:{flow_id}")
        results = pipe.execute()

        vectors = []
        for r in results:
            if r:
                vec = [float(r.get(f, 0.0)) for f in VOLUMETRIC_FEATURES]
                vectors.append(vec)
            else:
                vectors.append([0.0] * 13)

        return np.array(vectors, dtype=np.float32)

    # ─────────────────────────────────────────────
    # PEP — QUARANTINE (HOT PATH)
    # ─────────────────────────────────────────────

    def check_quarantine(self, ip: str) -> bool:
        """
        Sub-ms quarantine lookup on hot path.
        Returns True if IP is currently blocked.
        """
        if not self.is_available():
            return False
        return self.client.exists(f"quarantine:{ip}") == 1

    def quarantine_ip(self, ip: str, risk_score: float, reason: str, ttl: int = QUARANTINE_TTL_SECONDS):
        """
        Write blocked IP to Redis with TTL.
        Blocks auto-expire — prevents false positives from permanently locking users.
        """
        if not self.is_available():
            return
        key = f"quarantine:{ip}"
        self.client.hset(key, mapping={
            'ip': ip,
            'risk_score': str(risk_score),
            'reason': reason
        })
        self.client.expire(key, ttl)
        logger.info(f"🚫 QUARANTINE: {ip} blocked (risk={risk_score:.3f}, TTL={ttl}s)")

    def release_quarantine(self, ip: str):
        """Manually release a quarantined IP."""
        if not self.is_available():
            return
        self.client.delete(f"quarantine:{ip}")
        logger.info(f"✅ RELEASED: {ip} removed from quarantine")

    def get_quarantine_list(self) -> list:
        """Return all currently quarantined IPs."""
        if not self.is_available():
            return []
        keys = self.client.keys("quarantine:*")
        return [k.replace("quarantine:", "") for k in keys]

    # ─────────────────────────────────────────────
    # MONITOR QUEUE
    # ─────────────────────────────────────────────

    def queue_monitor_event(self, flow_id: str, risk_score: float, reason: str):
        """Push elevated-risk flow to monitor queue for Streamlit dashboard."""
        if not self.is_available():
            return
        event = json.dumps({'flow_id': flow_id, 'risk_score': risk_score, 'reason': reason})
        self.client.lpush("monitor_queue", event)
        self.client.ltrim("monitor_queue", 0, 999)  # Keep last 1000 events

    def queue_influx_write(self, record: dict):
        """Push record to async InfluxDB write-behind queue."""
        if not self.is_available():
            return
        self.client.lpush("influx_queue", json.dumps(record))


# ─────────────────────────────────────────────
# ROBUST SCALER — FIT & SAVE
# ─────────────────────────────────────────────

def fit_robust_scaler(df: pd.DataFrame, output_dir: str = "models") -> RobustScaler:
    """
    Fit RobustScaler on 13 volumetric features from training data.
    Uses median/IQR — not distorted by extreme byte-count outliers.
    Saves scaler to disk — MUST apply same transform at inference time.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    available = [f for f in VOLUMETRIC_FEATURES if f in df.columns]
    missing = [f for f in VOLUMETRIC_FEATURES if f not in df.columns]
    if missing:
        logger.warning(f"Missing volumetric features (will be 0): {missing}")

    X = df[available].fillna(0).values
    scaler = RobustScaler()
    scaler.fit(X)

    scaler_path = Path(output_dir) / "robust_scaler.pkl"
    joblib.dump(scaler, scaler_path)
    logger.info(f"✅ RobustScaler fitted on {len(available)} features → saved to {scaler_path}")
    return scaler


def load_robust_scaler(model_dir: str = "models") -> RobustScaler:
    """Load saved RobustScaler for inference."""
    path = Path(model_dir) / "robust_scaler.pkl"
    if not path.exists():
        raise FileNotFoundError(f"RobustScaler not found at {path}. Run fit_robust_scaler() first.")
    return joblib.load(path)


# ─────────────────────────────────────────────
# POST-ZERO-PADDING (TAIL PADDING)
# ─────────────────────────────────────────────

def pad_splt_sequences(df: pd.DataFrame, target_len: int = 40) -> pd.DataFrame:
    """
    Post-zero-padding for SPLT sequences shorter than target_len packets.
    Pads at the TAIL — TCN reads left-to-right, leading zeros corrupt temporal pattern.
    """
    len_cols = [f'splt_len_{i}' for i in range(1, target_len + 1)]
    iat_cols = [f'splt_iat_{i}' for i in range(1, target_len + 1)]

    for col in len_cols + iat_cols:
        if col not in df.columns:
            df[col] = 0.0

    logger.info(f"✅ Post-zero-padding applied: SPLT sequences padded to {target_len} packets")
    return df


# ─────────────────────────────────────────────
# DERIVE VOLUMETRIC FEATURES
# ─────────────────────────────────────────────

def derive_volumetric_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derive the 13 volumetric features from base flow features.
    Must be called before fit_robust_scaler() and IF training.
    """
    df = df.copy()

    duration = df.get('duration', pd.Series(np.zeros(len(df)))).fillna(0)
    total_packets = df.get('total_packets', pd.Series(np.ones(len(df)))).fillna(1)
    total_bytes = df.get('total_bytes', pd.Series(np.zeros(len(df)))).fillna(0)

    df['pps'] = total_packets / (duration + 1e-6)
    df['bps'] = total_bytes / (duration + 1e-6)
    df['mean_packet_size'] = total_bytes / (total_packets + 1e-6)

    iat_cols = [c for c in df.columns if c.startswith('splt_iat_')]
    if iat_cols:
        df['mean_iat'] = df[iat_cols].mean(axis=1)
        df['std_iat'] = df[iat_cols].std(axis=1).fillna(0)
    else:
        df['mean_iat'] = duration / (total_packets + 1e-6)
        df['std_iat'] = 0.0

    len_cols = [c for c in df.columns if c.startswith('splt_len_')]
    if len_cols:
        df['std_packet_size'] = df[len_cols].std(axis=1).fillna(0)
    else:
        df['std_packet_size'] = 0.0

    # Directionality (pseudo-exfil heuristic)
    if 'upload_bytes' not in df.columns and len_cols:
        upload_cols = [c for i, c in enumerate(len_cols) if i % 2 == 0]
        download_cols = [c for i, c in enumerate(len_cols) if i % 2 != 0]
        df['upload_bytes'] = df[upload_cols].sum(axis=1)
        df['download_bytes'] = df[download_cols].sum(axis=1)

    df['upload_ratio'] = df['upload_bytes'] / (df['total_bytes'] + 1e-6)

    logger.info(f"✅ Derived 13 volumetric features for {len(df):,} samples")
    return df


# ─────────────────────────────────────────────
# FULL PHASE 1 RUNNER
# ─────────────────────────────────────────────

def run_phase1(data_path: str, model_dir: str = "models"):
    """
    Complete Phase 1 pipeline:
    1. Load Snorkel-labeled dataset
    2. Derive volumetric features
    3. Apply post-zero-padding
    4. Fit RobustScaler
    5. Write to Redis Feature Store
    """
    logger.info("=" * 60)
    logger.info("PHASE 1: Redis Feature Store + Preprocessing")
    logger.info("=" * 60)

    # Load Snorkel-labeled data
    snorkel_path = str(Path(data_path).parent / "snorkel_labeled.csv")
    if Path(snorkel_path).exists():
        df = pd.read_csv(snorkel_path)
        logger.info(f"Loaded Snorkel-labeled data: {len(df):,} samples")
    else:
        df = pd.read_csv(data_path)
        logger.warning(f"Snorkel labels not found — using raw dataset. Run snorkel_labeling.py first.")

    # Step 1: Derive volumetric features
    df = derive_volumetric_features(df)

    # Step 2: Post-zero-padding (tail padding)
    df = pad_splt_sequences(df, target_len=40)

    # Step 3: Fit RobustScaler on volumetric features
    scaler = fit_robust_scaler(df, output_dir=model_dir)

    # Step 4: Write to Redis Feature Store
    store = RedisFeatureStore()
    if store.is_available():
        store.write_flows_bulk(df)
    else:
        logger.warning("Redis not running — skipping Feature Store write.")
        logger.info("To start Redis: docker run -d -p 6379:6379 redis:7-alpine --appendonly yes")

    # Save processed dataset
    processed_path = str(Path(data_path).parent / "phase1_processed.csv")
    df.to_csv(processed_path, index=False)
    logger.info(f"✅ Phase 1 processed dataset saved → {processed_path}")

    return df, store, scaler


if __name__ == "__main__":
    DATA_PATH = "../../data/processed/final_balanced_240k.csv"
    run_phase1(DATA_PATH)
