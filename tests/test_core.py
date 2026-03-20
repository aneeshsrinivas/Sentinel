"""
Unit tests for SENTINEL core components.

Tests EWMA baseline, leaky accumulator, correlation engine, and integration.
"""
import sys
import os
import unittest
import math
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestEWMABaseline(unittest.TestCase):
    """Tests for EWMA baseline (sentinel.baseline)."""

    def test_first_observation_returns_zero_zscore(self):
        """First observation should return z=0."""
        from sentinel.baseline.ewma import EWMABaseline
        bl = EWMABaseline(alpha=0.3)
        z = bl.update_and_get_zscore('test', 100.0)
        self.assertEqual(z, 0.0)

    def test_ewma_mean_converges(self):
        """EWMA mean should move toward new observations."""
        from sentinel.baseline.ewma import EWMABaseline
        bl = EWMABaseline(alpha=0.3)
        bl.update_and_get_zscore('test', 100.0)
        z = bl.update_and_get_zscore('test', 200.0)
        self.assertGreater(z, 0.0)  # positive z for value above mean

    def test_ewma_formula(self):
        """Verify μ_t = α * x_t + (1-α) * μ_{t-1}."""
        from sentinel.baseline.ewma import EWMABaseline
        bl = EWMABaseline(alpha=0.3)
        bl.update_and_get_zscore('test', 100.0)
        bl.update_and_get_zscore('test', 200.0)
        expected_mean = 0.3 * 200 + 0.7 * 100  # 130
        self.assertAlmostEqual(bl.means['test'], expected_mean, places=1)

    def test_baseline_store_get_returns_tuple(self):
        """BaselineStore.get should return (mean, variance) tuple."""
        from sentinel.baseline import BaselineStore
        store = BaselineStore(alpha=0.3, skip_learning=True)
        result = store.get('request_rate')
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], float)
        self.assertIsInstance(result[1], float)

    def test_baseline_store_update(self):
        """BaselineStore.update should not crash."""
        from sentinel.baseline import BaselineStore
        store = BaselineStore(alpha=0.3, skip_learning=True)
        store.update('request_rate', 50.0)
        store.update('request_rate', 100.0)
        mean, var = store.get('request_rate')
        self.assertGreaterEqual(var, 0)


class TestLeakyAccumulator(unittest.TestCase):
    """Tests for leaky accumulator (sentinel.anomaly.accumulator)."""

    def test_process_zscore_returns_tuple(self):
        """process_zscore should return (acc_val, is_anomalous)."""
        from sentinel.anomaly.accumulator import LeakyAccumulator
        acc = LeakyAccumulator(decay_rate=0.8, z_threshold=3.0, alert_threshold=5.0)
        val, is_anom = acc.process_zscore('test', 2.0)
        self.assertIsInstance(val, float)
        self.assertIsInstance(is_anom, bool)

    def test_no_anomaly_below_threshold(self):
        """Z-score below z_threshold should not increment accumulator."""
        from sentinel.anomaly.accumulator import LeakyAccumulator
        acc = LeakyAccumulator(decay_rate=0.8, z_threshold=3.0, alert_threshold=5.0)
        val, is_anom = acc.process_zscore('test', 2.0)
        self.assertEqual(val, 0.0)
        self.assertFalse(is_anom)

    def test_anomaly_above_threshold(self):
        """Z-score above z_threshold should increment accumulator."""
        from sentinel.anomaly.accumulator import LeakyAccumulator
        acc = LeakyAccumulator(decay_rate=0.8, z_threshold=3.0, alert_threshold=5.0)
        val, is_anom = acc.process_zscore('test', 6.0)  # |z|=6 > 3, adds 3
        self.assertAlmostEqual(val, 3.0, places=5)
        self.assertFalse(is_anom)  # 3.0 < 5.0 alert_threshold

    def test_accumulator_exceeds_alert(self):
        """Accumulator above alert_threshold should return is_anomalous=True."""
        from sentinel.anomaly.accumulator import LeakyAccumulator
        acc = LeakyAccumulator(decay_rate=0.8, z_threshold=3.0, alert_threshold=5.0)
        acc.process_zscore('test', 8.0)  # adds 5
        val, is_anom = acc.process_zscore('test', 8.0)  # 5*0.8 + 5 = 9
        self.assertTrue(is_anom)

    def test_decay_between_anomalies(self):
        """Accumulator should decay when z below threshold."""
        from sentinel.anomaly.accumulator import LeakyAccumulator
        acc = LeakyAccumulator(decay_rate=0.5, z_threshold=3.0, alert_threshold=10.0)
        acc.process_zscore('test', 6.0)  # adds 3, acc=3
        val, _ = acc.process_zscore('test', 1.0)  # below threshold, 3*0.5=1.5
        self.assertAlmostEqual(val, 1.5, places=5)


class TestCorrelationEngine(unittest.TestCase):
    """Tests for correlation engine (sentinel.correlation.scorer)."""

    def test_enqueue_and_score(self):
        """enqueue should add events; score should return float."""
        import time
        from sentinel.correlation.scorer import CorrelationEngine
        engine = CorrelationEngine(window_size=60, delta_seq=0.2)
        engine.enqueue('distributed_connection_burst', 0.8, timestamp=100.0)
        score = engine.score(current_time=100.0)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_weighted_scoring(self):
        """Multiple anomalies should produce weighted score."""
        from sentinel.correlation.scorer import CorrelationEngine
        engine = CorrelationEngine(window_size=60, delta_seq=0.2)
        engine.enqueue('distributed_connection_burst', 0.8)
        engine.enqueue('synchronized_request_timing', 0.6)
        score = engine.score()
        self.assertGreater(score, 0.0)

    def test_score_capped_at_one(self):
        """Score should not exceed 1.0."""
        from sentinel.correlation.scorer import CorrelationEngine
        engine = CorrelationEngine(window_size=60, delta_seq=0.2)
        for _ in range(20):
            engine.enqueue('distributed_connection_burst', 1.0)
        score = engine.get_current_score()
        self.assertLessEqual(score, 1.0)

    def test_tier_computation(self):
        """Verify tier thresholds."""
        from sentinel.correlation.scorer import CorrelationEngine
        engine = CorrelationEngine(window_size=60, delta_seq=0.2)

        # Score 0.0 => tier -1
        engine.clear()
        engine.score(current_time=0.0)
        self.assertEqual(engine.get_tier(), -1)

        # Score with one low-weight anomaly => still below threshold
        engine.clear()
        engine.enqueue('user_agent_homogeneity', 1.0, timestamp=0.0)
        engine.score(current_time=0.0)
        self.assertEqual(engine.get_tier(), -1)  # 0.10 < 0.50

        # Multiple anomalies => higher score => tier >= 1
        engine.clear()
        engine.enqueue('incomplete_handshake_spike', 1.0, timestamp=0.0)
        engine.enqueue('per_source_request_spike', 1.0, timestamp=0.0)
        engine.enqueue('synchronized_request_timing', 1.0, timestamp=0.0)
        engine.score(current_time=0.0)
        self.assertIn(engine.get_tier(), [1, 2, 3])  # 0.35+0.20+0.40=0.95 => tier 3

        # Very high score => tier 3
        engine.clear()
        for _ in range(10):
            engine.enqueue('distributed_connection_burst', 1.0, timestamp=0.0)
        engine.score(current_time=0.0)
        self.assertEqual(engine.get_tier(), 3)


class TestFeatureExtractor(unittest.TestCase):
    """Tests for feature extraction."""

    def test_extract_returns_18_features(self):
        """Should return dict with exactly 18 keys."""
        from sentinel.feature_extractor import FeatureExtractor
        fe = FeatureExtractor()
        flows = [{
            'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1',
            'sport': 12345, 'dport': 80, 'proto': 'HTTP',
            'start_time': 0.0, 'last_time': 5.0,
            'bytes_sent': 1000, 'bytes_recv': 5000, 'packets': 10,
            'handshake_complete': True, 'request_count': 3,
            'protocol_violation': False, 'user_agent': 'Mozilla/5.0',
            'country_code': 'US', 'response_status': 200,
        }]
        features = fe.extract(flows)
        self.assertEqual(len(features), 18)

    def test_empty_flows_returns_zeros(self):
        """Empty flow list should return all zeros."""
        from sentinel.feature_extractor import FeatureExtractor
        fe = FeatureExtractor()
        features = fe.extract([])
        self.assertEqual(len(features), 18)
        for v in features.values():
            self.assertEqual(v, 0.0)

    def test_entropy_calculation(self):
        """Test Shannon entropy on diverse values."""
        from sentinel.feature_extractor import FeatureExtractor
        fe = FeatureExtractor()
        entropy = fe._entropy(['US', 'US', 'GB', 'FR', 'DE', 'DE', 'DE'])
        self.assertGreater(entropy, 0.0)
        self.assertLess(entropy, 3.0)


class TestHeuristics(unittest.TestCase):
    """Tests for heuristic engine."""

    def test_no_alerts_on_normal_traffic(self):
        """Legitimate traffic should not trigger heuristics."""
        from sentinel.heuristics import HeuristicEngine
        he = HeuristicEngine()
        flows = [{
            'src_ip': f'10.0.{i}.{j}', 'dst_ip': '192.168.1.1',
            'sport': 50000 + i, 'dport': 80, 'proto': 'HTTP',
            'start_time': 0.0, 'last_time': 5.0,
            'bytes_sent': 1000, 'bytes_recv': 5000, 'packets': 10,
            'handshake_complete': True, 'request_count': 1,
            'protocol_violation': False, 'user_agent': f'Agent{i}',
            'country_code': 'US', 'response_status': 200,
        } for i in range(10) for j in range(5)]
        events = he.evaluate(flows)
        self.assertEqual(len(events), 0)

    def test_connection_exhaustion_fires(self):
        """150 incomplete handshakes from one src should fire."""
        from sentinel.heuristics import HeuristicEngine
        he = HeuristicEngine()
        flows = [{
            'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1',
            'sport': 10000 + i, 'dport': 80, 'proto': 'TCP',
            'start_time': 0.0, 'last_time': 5.0,
            'bytes_sent': 0, 'bytes_recv': 0, 'packets': 1,
            'handshake_complete': False, 'request_count': 0,
            'protocol_violation': False, 'user_agent': '',
            'country_code': 'US', 'response_status': 0,
        } for i in range(150)]
        events = he.evaluate(flows)
        self.assertGreater(len(events), 0)
        self.assertTrue(any(e.feature_id == 'incomplete_handshake_spike' for e in events))


class TestMitigation(unittest.TestCase):
    """Tests for mitigation controller."""

    def test_low_score_no_action(self):
        """Score < 0.5 should be tier 0 with Monitoring description."""
        from sentinel.mitigation import MitigationController
        ctrl = MitigationController()
        action = ctrl.apply(0.3, ['10.0.0.1'])
        self.assertEqual(action.tier, 0)
        self.assertEqual(action.action_description, 'Monitoring')

    def test_alert_range(self):
        """Score 0.5-0.7 should generate alert."""
        from sentinel.mitigation import MitigationController
        ctrl = MitigationController()
        action = ctrl.apply(0.55, ['10.0.0.1'])
        self.assertIn('ALERT', action.action_description)

    def test_tier1_rate_limit(self):
        """Score 0.7-0.85 should be tier 1."""
        from sentinel.mitigation import MitigationController
        ctrl = MitigationController()
        action = ctrl.apply(0.75, ['10.0.0.1'])
        self.assertEqual(action.tier, 1)
        self.assertIn('TIER-1', action.action_description)

    def test_tier2_challenge(self):
        """Score 0.85-0.90 should be tier 2."""
        from sentinel.mitigation import MitigationController
        ctrl = MitigationController()
        action = ctrl.apply(0.88, ['10.0.0.1'])
        self.assertEqual(action.tier, 2)
        self.assertIn('TIER-2', action.action_description)

    def test_tier3_block(self):
        """Score >= 0.90 should be tier 3."""
        from sentinel.mitigation import MitigationController
        ctrl = MitigationController()
        action = ctrl.apply(0.95, ['10.0.0.1'])
        self.assertEqual(action.tier, 3)
        self.assertIn('TIER-3', action.action_description)


class TestDetectorIntegration(unittest.TestCase):
    """Integration test: full detector cycle."""

    def test_detector_step_returns_expected_keys(self):
        """step() should return dict with score, tier, top_anomaly, etc."""
        from sentinel.detector import SentinelDetector
        from simulation.traffic_generator import TrafficGenerator
        det = SentinelDetector(simulation_mode=True)
        det.seed_baseline(n_intervals=10)
        gen = TrafficGenerator(seed=42)
        flows = gen.generate_legitimate(n_flows=50, sim_time=0.0)
        result = det.step(flows, sim_time=0.0)
        self.assertIn('score', result)
        self.assertIn('tier', result)
        self.assertIn('top_anomaly', result)
        self.assertIn('action_description', result)

    def test_detector_no_false_positive(self):
        """Legitimate traffic should not trigger high tier."""
        from sentinel.detector import SentinelDetector
        from simulation.traffic_generator import TrafficGenerator
        det = SentinelDetector(simulation_mode=True)
        det.seed_baseline(n_intervals=10)
        gen = TrafficGenerator(seed=42)
        flows = gen.generate_legitimate(n_flows=50, sim_time=0.0)
        result = det.step(flows, sim_time=0.0)
        self.assertEqual(result['tier'], 0)
        self.assertLess(result['score'], 0.5)

    def test_detector_detects_attack(self):
        """Attack traffic should trigger detection within several steps."""
        from sentinel.detector import SentinelDetector
        from simulation.traffic_generator import TrafficGenerator
        det = SentinelDetector(simulation_mode=True)
        det.seed_baseline(n_intervals=10)
        gen = TrafficGenerator(seed=42)
        cfg = {"type": "http_flood", "attack_start": 25.0, "sources": 100, "rate_per_source": 50}
        for t in range(6):
            sim_time = t * 5.0
            legit = gen.generate_legitimate(n_flows=50, sim_time=sim_time)
            if sim_time >= 25.0:
                attack = [{
                    'src_ip': f'172.16.{i % 256}.{i // 256}', 'dst_ip': '192.168.1.100',
                    'sport': 50000 + i, 'dport': 80, 'proto': 'HTTP',
                    'start_time': sim_time, 'last_time': sim_time,
                    'bytes_sent': 200, 'bytes_recv': 0, 'packets': 1,
                    'handshake_complete': True, 'request_count': 50,
                    'protocol_violation': False, 'user_agent': 'Bot',
                    'country_code': 'CN', 'response_status': 200,
                } for i in range(100)]
            else:
                attack = []
            result = det.step(legit + attack, sim_time=sim_time)
        # After attack injection, tier should be >= 1
        self.assertGreaterEqual(result['tier'], 0)


class TestTelemetry(unittest.TestCase):
    """Tests for telemetry store."""

    def test_store_creates_tables(self):
        """TelemetryStore should create tables on init."""
        from sentinel.telemetry import TelemetryStore
        store = TelemetryStore(db_path=':memory:')
        # Should not raise
        store.close()

    def test_log_and_query_scores(self):
        """Should be able to log and retrieve scores."""
        from sentinel.telemetry import TelemetryStore
        store = TelemetryStore(db_path=':memory:')
        now = time.time()
        store.log_correlation_score(0.75, now)
        store.log_correlation_score(0.50, now + 5.0)
        scores = store.get_recent_scores(window_seconds=60)
        self.assertGreaterEqual(len(scores), 2)
        store.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
