"""
SENTINEL Configuration Module

Core parameters for the behavioral DDoS detection framework.
All parameters are hardcoded as specified in the paper.

Reference: Table 2 in "SENTINEL: A Behavioral DDoS Detection Framework
Using Adaptive Baseline Profiling and Multi-Dimensional Temporal Correlation"
"""

from dataclasses import dataclass
from typing import Dict

# EWMA smoothing parameter (controls baseline adaptation rate)
ALPHA = 0.3

# Leaky accumulator decay factor (controls persistence decay rate)
LAMBDA = 0.8

# Z-score anomaly threshold (triggers accumulator increment)
TAU_Z = 3.0

# Accumulator confirmation threshold (triggers anomaly confirmation)
THETA_A = 5.0

# Correlation sliding window duration in seconds
WINDOW_SIZE = 60

# Observation interval in seconds
OBSERVATION_INTERVAL = 5

# Detection trigger threshold (correlation score threshold)
DELTA_THRESH = 0.70

# Sequential template boost for matching attack progression patterns
DELTA_SEQ = 0.2

# Division guard to prevent division by zero
EPSILON = 1e-9

# Flow table inactivity timeout in seconds
FLOW_TIMEOUT = 60

# Learning phase duration in hours
LEARNING_PHASE_HOURS = 24

# IQR outlier exclusion multiplier
IQR_MULTIPLIER = 1.5

# Feature extraction intervals
FEATURE_INTERVAL = OBSERVATION_INTERVAL

# Anomaly type weights for correlation scoring
ANOMALY_WEIGHTS: Dict[str, float] = {
    "distributed_connection_burst": 0.50,
    "synchronized_request_timing": 0.40,
    "incomplete_handshake_spike": 0.35,
    "geographic_entropy_reduction": 0.30,
    "session_duration_anomaly": 0.25,
    "per_source_request_spike": 0.20,
    "protocol_compliance_violation": 0.15,
    "user_agent_homogeneity": 0.10,
}

# Mitigation tier thresholds
MITIGATION_TIER_1 = 0.70
MITIGATION_TIER_2 = 0.85
MITIGATION_TIER_3 = 0.90
MITIGATION_ALERT = 0.50
MITIGATION_LOG_ONLY = 0.50

# De-escalation thresholds
DEESCALATION_TIER3_THRESH = 0.60
DEESCALATION_TIER3_DURATION = 120
DEESCALATION_ALL_DURATION = 300

# Rate limiting multiplier
RATE_LIMIT_MULTIPLIER = 2.0

# Mitigation action timeouts
DROP_RULE_TIMEOUT = 300

# Simulation parameters
SIMULATION_WALL_CLOCK_RATIO = 10.0
RANDOM_SEED = 42

# Heuristic thresholds
CONNECTION_EXHAUSTION_THRESHOLD = 100
INCOMPLETE_HANDSHAKE_THRESHOLD = 500
SLOWLORIS_CONCURRENT_THRESHOLD = 20
SLOWLORIS_BYTES_THRESHOLD = 1024
SLOWLORIS_GAP_THRESHOLD = 5
HTTP_FLOOD_MULTIPLIER = 10
HTTP_FLOOD_SUSTAINED_SECONDS = 60
UA_DIVERSITY_THRESHOLD = 0.1
UA_MIN_REQUESTS = 100
DISTRIBUTED_SOURCE_THRESHOLD = 50
DISTRIBUTED_WINDOW = 5
CROSS_CORRELATION_THRESHOLD = 0.7
CROSS_CORRELATION_MIN_SOURCES = 100


@dataclass
class Config:
    """Complete configuration container for SENTINEL."""
    alpha: float = ALPHA
    lambda_decay: float = LAMBDA
    tau_z: float = TAU_Z
    theta_a: float = THETA_A
    window_size: int = WINDOW_SIZE
    observation_interval: int = OBSERVATION_INTERVAL
    delta_thresh: float = DELTA_THRESH
    delta_seq: float = DELTA_SEQ
    epsilon: float = EPSILON
    flow_timeout: int = FLOW_TIMEOUT
    learning_phase_hours: int = LEARNING_PHASE_HOURS
    mitigation_tier_1: float = MITIGATION_TIER_1
    mitigation_tier_2: float = MITIGATION_TIER_2
    mitigation_tier_3: float = MITIGATION_TIER_3
    mitigation_alert: float = MITIGATION_ALERT
    
    def to_dict(self) -> Dict:
        return {
            'alpha': self.alpha,
            'lambda_decay': self.lambda_decay,
            'tau_z': self.tau_z,
            'theta_a': self.theta_a,
            'window_size': self.window_size,
            'observation_interval': self.observation_interval,
            'delta_thresh': self.delta_thresh,
            'delta_seq': self.delta_seq,
            'epsilon': self.epsilon,
            'flow_timeout': self.flow_timeout,
            'learning_phase_hours': self.learning_phase_hours,
            'mitigation_tier_1': self.mitigation_tier_1,
            'mitigation_tier_2': self.mitigation_tier_2,
            'mitigation_tier_3': self.mitigation_tier_3,
            'mitigation_alert': self.mitigation_alert,
        }


DEFAULT_CONFIG = Config()
