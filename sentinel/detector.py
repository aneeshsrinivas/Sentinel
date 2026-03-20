"""
SENTINEL Detector - Main detection loop (Algorithm 1).
Wires feature extractor, baseline, accumulator, correlation, heuristics, mitigation, telemetry.
"""
import time
import math
import numpy as np
from typing import List, Dict, Optional, Any
from collections import defaultdict

from .config import (
    DEFAULT_CONFIG, ALPHA, LAMBDA, TAU_Z, THETA_A,
    OBSERVATION_INTERVAL, WINDOW_SIZE, DELTA_THRESH, DELTA_SEQ,
    ANOMALY_WEIGHTS,
)
from .feature_extractor import FeatureExtractor
from .baseline import BaselineStore
from .anomaly.accumulator import LeakyAccumulator
from .correlation.scorer import CorrelationEngine
from .heuristics import HeuristicEngine, AnomalyEvent as HeuristicAnomaly
from .mitigation import MitigationController
from .telemetry import TelemetryStore


FEATURE_NAMES = [
    "new_connection_rate", "concurrent_connection_count", "mean_connection_duration",
    "variance_connection_duration", "handshake_completion_ratio", "request_rate",
    "inter_request_timing_variance", "protocol_compliance_score", "total_request_rate",
    "unique_source_count", "geographic_entropy", "backend_error_rate",
    "response_latency_mean", "source_diversity_per_minute", "geo_distribution_shift_rate",
    "cross_source_timing_correlation", "protocol_frequency_ratio", "payload_entropy_proxy",
]


def _flow_to_dict(flow) -> Dict[str, Any]:
    """Convert a TrafficFlow dataclass or dict to the expected 16-key dict."""
    if isinstance(flow, dict):
        return flow
    return {
        'src_ip': flow.src_ip,
        'dst_ip': flow.dst_ip,
        'sport': flow.src_port,
        'dport': flow.dst_port,
        'proto': flow.proto,
        'start_time': flow.timestamp,
        'last_time': flow.timestamp,
        'bytes_sent': flow.bytes_sent,
        'bytes_recv': flow.bytes_recv,
        'packets': 1,
        'handshake_complete': flow.handshake_completed,
        'request_count': 1 if flow.http_request else 0,
        'protocol_violation': flow.protocol_violation,
        'user_agent': flow.user_agent or '',
        'country_code': flow.country_code or 'US',
        'response_status': 200,
    }


class SentinelDetector:
    """Main SENTINEL detector implementing Algorithm 1."""

    def __init__(self, simulation_mode: bool = True, db_path: str = ":memory:"):
        self.simulation_mode = simulation_mode
        self.feature_extractor = FeatureExtractor()
        self.baseline = BaselineStore(alpha=ALPHA, skip_learning=True)
        self.accumulators = {}
        self.correlation = CorrelationEngine(
            window_size=WINDOW_SIZE,
            delta_seq=DELTA_SEQ,
            weights=ANOMALY_WEIGHTS.copy(),
        )
        self.heuristics = HeuristicEngine()
        self.mitigation = MitigationController()
        self.telemetry = TelemetryStore(db_path)

        for fname in FEATURE_NAMES:
            self.accumulators[fname] = LeakyAccumulator(
                decay_rate=LAMBDA,
                z_threshold=TAU_Z,
                alert_threshold=THETA_A,
            )

        self._step_count = 0
        self._last_top_anomaly = None

    def seed_baseline(self, n_intervals: int = 100):
        """
        Seed baselines with realistic traffic variance.
        
        Critical: variance must be high enough that normal fluctuations
        don't trigger anomalies, but attack signals still exceed tau_z=3.0.
        """
        from simulation.traffic_generator import TrafficGenerator

        gen = TrafficGenerator(seed=42)
        rng = np.random.default_rng(42)

        feature_values = {fname: [] for fname in FEATURE_NAMES}

        for i in range(n_intervals):
            sim_time = float(i * OBSERVATION_INTERVAL)
            n_flows = max(10, int(rng.normal(50, 10)))
            flows = gen.generate_legitimate(n_flows=n_flows, sim_time=sim_time)
            features = self.feature_extractor.extract(flows)
            for fname in FEATURE_NAMES:
                feature_values[fname].append(features.get(fname, 0.0))

        from sentinel.baseline import BaselineStats
        for fname in FEATURE_NAMES:
            vals = feature_values[fname]
            if vals:
                mean = float(np.mean(vals))
                std = float(np.std(vals))
            else:
                mean, std = 0.0, 1.0

            # Ensure minimum variance so z-scores aren't astronomically large
            variance = max(std * std, mean * 0.05 + 0.01, 0.1)

            bl = self.baseline.get_baseline(fname)
            if bl.is_learning():
                bl.finalize_learning(use_synthetic=False, synthetic_data={})

            bl._global = BaselineStats(mean=mean, variance=variance, sample_count=n_intervals)
            bl._contexts[(12, 0)] = BaselineStats(mean=mean, variance=variance, sample_count=n_intervals)

            self.telemetry.log_baseline_snapshot(fname, mean, variance)

    def step(self, flows: List, sim_time: float = None) -> dict:
        """
        Run one delta_t=5s detection cycle (Algorithm 1).
        Accepts list of TrafficFlow objects or flow dicts.
        """
        if sim_time is None:
            sim_time = time.time()

        flow_dicts = [_flow_to_dict(f) for f in flows]
        features = self.feature_extractor.extract(flow_dicts)

        anomaly_events = []
        top_feature = None
        top_accumulator = 0.0

        hour, dow = 12, 0

        for fname in FEATURE_NAMES:
            fval = features.get(fname, 0.0)
            mean, variance = self.baseline.get(fname, hour=hour, day_of_week=dow)
            std = max(math.sqrt(max(variance, 0)), 1e-9)
            z = (fval - mean) / std
            self.baseline.update(fname, fval, hour=hour, day_of_week=dow)
            acc_val, is_anomalous = self.accumulators[fname].process_zscore(fname, z)

            if is_anomalous:
                confidence = min(abs(z) / 5.0, 1.0)
                anomaly_events.append({
                    'feature_id': fname,
                    'z_score': z,
                    'confidence': confidence,
                    'accumulator': acc_val,
                })
                # Use sim_time for consistent window expiry
                self.correlation.enqueue(fname, confidence, timestamp=sim_time)
                self.telemetry.log_anomaly_event(HeuristicAnomaly(fname, confidence, sim_time))

            if acc_val > top_accumulator:
                top_accumulator = acc_val
                top_feature = fname

        heuristic_events = self.heuristics.evaluate(flow_dicts)
        contributing_sources = list(set(f['src_ip'] for f in flow_dicts))
        for he in heuristic_events:
            # Use sim_time, NOT he.timestamp (which is time.time())
            self.correlation.enqueue(he.feature_id, he.confidence, timestamp=sim_time)
            self.telemetry.log_anomaly_event(he)

        # Pass sim_time so the sliding window expires events correctly
        score = self.correlation.score(current_time=sim_time)
        action = self.mitigation.apply(score, contributing_sources)
        self.telemetry.log_correlation_score(score, sim_time)
        self.telemetry.log_mitigation_action(action)

        self._step_count += 1
        tier = action.tier

        top_anomaly = top_feature
        if heuristic_events:
            top_anomaly = heuristic_events[0].feature_id
        if top_anomaly:
            self._last_top_anomaly = top_anomaly

        return {
            'score': round(score, 6),
            'tier': tier,
            'anomalies': anomaly_events,
            'heuristics': [he.to_dict() for he in heuristic_events],
            'top_anomaly': top_anomaly,
            'action_description': action.action_description,
            'features': features,
            'step': self._step_count,
            'sim_time': sim_time,
        }
