"""
SENTINEL Baseline Comparisons Module

Implements three comparison systems:
- Static Threshold
- Snort-sim (signature-based)
- Random Forest (machine learning)

Reference: Section 5.3.3 in "SENTINEL: A Behavioral DDoS Detection Framework"
"""

import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

from .metrics import compute_roc_points, compute_auc


class StaticThresholdDetector:
    """
    Static threshold baseline: alerts when per-source rate >10x baseline
    OR aggregate >2x baseline.
    """
    
    def __init__(self, per_source_threshold: float = 10.0, 
                 aggregate_threshold: float = 2.0):
        self.per_source_threshold = per_source_threshold
        self.aggregate_threshold = aggregate_threshold
    
    def run(self, test_data: List[Dict]) -> List[Dict]:
        """Run static threshold detection on test data."""
        results = []
        
        for test_case in test_data:
            features = test_case.get('features', [])
            is_attack = test_case.get('is_attack', False)
            attack_start = test_case.get('attack_start', 30.0)
            scenario_id = test_case.get('scenario_id', 'unknown')
            
            detection_time = None
            false_positives = 0
            true_positives = 0
            false_negatives = 0
            true_negatives = 0
            peak_score = 0.0
            
            baseline_rate = self._estimate_baseline(features[:20] if len(features) >= 20 else features)
            
            for t, feature_vec in enumerate(features):
                current_time = float(t) * 5.0
                
                per_source = feature_vec.get('request_rate', 0)
                aggregate = feature_vec.get('total_request_rate', 0)
                
                per_source_ratio = per_source / max(baseline_rate, 0.1)
                aggregate_ratio = aggregate / max(baseline_rate * 100, 0.1)
                
                score = max(per_source_ratio / self.per_source_threshold,
                           aggregate_ratio / self.aggregate_threshold)
                score = min(score, 1.0)
                
                peak_score = max(peak_score, score)
                
                is_attack_active = is_attack and current_time >= attack_start
                
                if score >= 0.7:
                    if is_attack_active:
                        true_positives += 1
                        if detection_time is None:
                            detection_time = current_time
                    else:
                        false_positives += 1
                else:
                    if is_attack_active:
                        false_negatives += 1
                    else:
                        true_negatives += 1
            
            latency = None
            detected = False
            if detection_time is not None and is_attack:
                latency = detection_time - attack_start
                detected = True
            
            results.append({
                'scenario_id': scenario_id,
                'detected': detected,
                'latency': latency,
                'peak_score': peak_score,
                'false_positives': false_positives,
                'true_positives': true_positives,
                'false_negatives': false_negatives,
                'true_negatives': true_negatives,
                'is_attack': is_attack,
            })
        
        return results
    
    def _estimate_baseline(self, samples: List[Dict]) -> float:
        """Estimate baseline rate from initial samples."""
        rates = [s.get('request_rate', 0) for s in samples if 'request_rate' in s]
        if not rates:
            return 50.0
        return np.median(rates)


class SnortSimDetector:
    """
    Signature-based detection simulating Snort rules for DDoS patterns:
    - SYN flood pattern
    - Slowloris pattern
    - HTTP flood pattern
    """
    
    SYNFLOOD_RULE = {
        'type': 'syn_flood',
        'threshold_conn_rate': 100,
        'incomplete_ratio': 0.9,
    }
    
    SLOWLORIS_RULE = {
        'type': 'slowloris',
        'low_bytes_threshold': 100,
        'long_duration_threshold': 60,
        'low_request_ratio': 0.1,
    }
    
    HTTPFLOOD_RULE = {
        'type': 'http_flood',
        'request_rate_threshold': 10,
        'uniform_ua_ratio': 0.9,
    }
    
    def __init__(self):
        self.rules = [self.SYNFLOOD_RULE, self.SLOWLORIS_RULE, self.HTTPFLOOD_RULE]
    
    def run(self, test_data: List[Dict]) -> List[Dict]:
        """Run signature-based detection on test data."""
        results = []
        
        for test_case in test_data:
            features = test_case.get('features', [])
            is_attack = test_case.get('is_attack', False)
            attack_start = test_case.get('attack_start', 30.0)
            scenario_id = test_case.get('scenario_id', 'unknown')
            
            detection_time = None
            false_positives = 0
            true_positives = 0
            false_negatives = 0
            true_negatives = 0
            peak_score = 0.0
            rule_matches = defaultdict(int)
            
            for t, feature_vec in enumerate(features):
                current_time = float(t) * 5.0
                
                score = self._match_rules(feature_vec)
                peak_score = max(peak_score, score)
                
                for rule_name, matched in self._get_rule_matches(feature_vec).items():
                    if matched:
                        rule_matches[rule_name] += 1
                
                is_attack_active = is_attack and current_time >= attack_start
                
                if score >= 0.7:
                    if is_attack_active:
                        true_positives += 1
                        if detection_time is None:
                            detection_time = current_time
                    else:
                        false_positives += 1
                else:
                    if is_attack_active:
                        false_negatives += 1
                    else:
                        true_negatives += 1
            
            latency = None
            detected = False
            if detection_time is not None and is_attack:
                latency = detection_time - attack_start
                detected = True
            
            results.append({
                'scenario_id': scenario_id,
                'detected': detected,
                'latency': latency,
                'peak_score': peak_score,
                'false_positives': false_positives,
                'true_positives': true_positives,
                'false_negatives': false_negatives,
                'true_negatives': true_negatives,
                'rule_matches': dict(rule_matches),
                'is_attack': is_attack,
            })
        
        return results
    
    def _match_rules(self, features: Dict) -> float:
        """Match features against rules and return highest score."""
        max_score = 0.0
        
        conn_rate = features.get('new_connection_rate', 0)
        if conn_rate > self.SYNFLOOD_RULE['threshold_conn_rate']:
            max_score = max(max_score, 0.8)
        
        handshake_ratio = features.get('handshake_completion_ratio', 1.0)
        if handshake_ratio < (1 - self.SYNFLOOD_RULE['incomplete_ratio']):
            max_score = max(max_score, 0.9)
        
        duration = features.get('mean_connection_duration', 0)
        if duration > self.SLOWLORIS_RULE['long_duration_threshold']:
            max_score = max(max_score, 0.7)
        
        request_rate = features.get('request_rate', 0)
        if request_rate > self.HTTPFLOOD_RULE['request_rate_threshold'] * 50:
            max_score = max(max_score, 0.85)
        
        return min(max_score, 1.0)
    
    def _get_rule_matches(self, features: Dict) -> Dict[str, bool]:
        """Check which rules match."""
        matches = {}
        
        conn_rate = features.get('new_connection_rate', 0)
        matches['syn_flood'] = conn_rate > self.SYNFLOOD_RULE['threshold_conn_rate']
        
        duration = features.get('mean_connection_duration', 0)
        matches['slowloris'] = duration > self.SLOWLORIS_RULE['long_duration_threshold']
        
        request_rate = features.get('request_rate', 0)
        matches['http_flood'] = request_rate > self.HTTPFLOOD_RULE['request_rate_threshold'] * 50
        
        return matches


class RandomForestDetector:
    """
    Random Forest classifier trained on labeled flow features.
    scikit-learn RandomForestClassifier(n_estimators=100, max_depth=10)
    """
    
    def __init__(self, n_estimators: int = 100, max_depth: int = 10, 
                 n_samples_train: int = 1000):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.n_samples_train = n_samples_train
        self.model = None
        self.feature_names: List[str] = []
        self._trained = False
    
    def train(self, training_data: List[Dict]):
        """Train the Random Forest on labeled data."""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            print("Warning: scikit-learn not available, using fallback")
            self._train_fallback(training_data)
            return
        
        if not training_data:
            return
        
        self.feature_names = self._extract_feature_names(training_data)
        
        X = []
        y = []
        
        for sample in training_data:
            features = sample.get('features', [])
            is_attack = sample.get('is_attack', False)
            
            for fv in features:
                X.append([fv.get(fn, 0) for fn in self.feature_names])
                y.append(1 if is_attack else 0)
        
        if len(X) < 10:
            self._train_fallback(training_data)
            return
        
        X = np.array(X)
        y = np.array(y)
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=42
        )
        self.model.fit(X_scaled, y)
        self._trained = True
    
    def _train_fallback(self, training_data: List[Dict]):
        """Fallback training when sklearn unavailable."""
        self._trained = False
        self.feature_names = ['request_rate', 'new_connection_rate', 
                              'handshake_completion_ratio', 'geographic_entropy']
    
    def _extract_feature_names(self, data: List[Dict]) -> List[str]:
        """Extract all unique feature names from data."""
        feature_names = set()
        for sample in data:
            for fv in sample.get('features', []):
                feature_names.update(fv.keys())
        return sorted(list(feature_names))[:20]
    
    def predict(self, features: List[Dict]) -> List[float]:
        """Predict attack probabilities for feature vectors."""
        if not self._trained or self.model is None:
            return [0.5] * len(features)
        
        try:
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            return [0.5] * len(features)
        
        X = [[fv.get(fn, 0) for fn in self.feature_names] for fv in features]
        X = np.array(X)
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        probs = self.model.predict_proba(X_scaled)
        return probs[:, 1].tolist()
    
    def run(self, test_data: List[Dict]) -> List[Dict]:
        """Run Random Forest detection on test data."""
        all_data = test_data
        split_idx = int(len(all_data) * 0.7)
        
        training_data = all_data[:split_idx]
        test_subset = all_data[split_idx:]
        
        self.train(training_data)
        
        results = []
        
        for test_case in test_subset:
            features = test_case.get('features', [])
            is_attack = test_case.get('is_attack', False)
            attack_start = test_case.get('attack_start', 30.0)
            scenario_id = test_case.get('scenario_id', 'unknown')
            
            if not features:
                results.append({
                    'scenario_id': scenario_id,
                    'detected': False,
                    'latency': None,
                    'peak_score': 0.0,
                    'false_positives': 0,
                    'true_positives': 0,
                    'false_negatives': 0,
                    'true_negatives': 0,
                    'is_attack': is_attack,
                })
                continue
            
            probs = self.predict(features)
            scores = [min(p * 2, 1.0) for p in probs]
            
            detection_time = None
            false_positives = 0
            true_positives = 0
            false_negatives = 0
            true_negatives = 0
            
            for t, score in enumerate(scores):
                current_time = float(t) * 5.0
                
                is_attack_active = is_attack and current_time >= attack_start
                
                if score >= 0.7:
                    if is_attack_active:
                        true_positives += 1
                        if detection_time is None:
                            detection_time = current_time
                    else:
                        false_positives += 1
                else:
                    if is_attack_active:
                        false_negatives += 1
                    else:
                        true_negatives += 1
            
            latency = None
            detected = False
            if detection_time is not None and is_attack:
                latency = detection_time - attack_start
                detected = True
            
            results.append({
                'scenario_id': scenario_id,
                'detected': detected,
                'latency': latency,
                'peak_score': max(scores) if scores else 0.0,
                'false_positives': false_positives,
                'true_positives': true_positives,
                'false_negatives': false_negatives,
                'true_negatives': true_negatives,
                'is_attack': is_attack,
            })
        
        return results


class BaselineComparison:
    """
    Compares SENTINEL against three baseline systems.
    """
    
    def __init__(self):
        self.static_threshold = StaticThresholdDetector()
        self.snort_sim = SnortSimDetector()
        self.random_forest = RandomForestDetector()
    
    def run_all(self, test_data: List[Dict]) -> Dict[str, List[Dict]]:
        """Run all baseline detectors on test data."""
        return {
            'Static_Threshold': self.static_threshold.run(test_data),
            'Snort_sim': self.snort_sim.run(test_data),
            'Random_Forest': self.random_forest.run(test_data),
        }
    
    def compare_roc_curves(
        self,
        sentinel_results: List[Dict],
        baseline_results: Dict[str, List[Dict]]
    ) -> Dict[str, Tuple[List[float], List[float], float]]:
        """Compute ROC curves for all systems."""
        roc_data = {}
        
        sentinel_fprs, sentinel_tprs = compute_roc_points(sentinel_results)
        sentinel_auc = compute_auc(sentinel_fprs, sentinel_tprs)
        roc_data['SENTINEL'] = (sentinel_fprs, sentinel_tprs, sentinel_auc)
        
        for name, results in baseline_results.items():
            fprs, tprs = compute_roc_points(results)
            auc = compute_auc(fprs, tprs)
            roc_data[name] = (fprs, tprs, auc)
        
        return roc_data
    
    def format_comparison_table(
        self,
        sentinel_metrics: Dict,
        baseline_metrics: Dict[str, Dict]
    ) -> str:
        """Format comparison as a table."""
        lines = []
        lines.append("\n" + "=" * 90)
        lines.append("SYSTEM COMPARISON RESULTS")
        lines.append("=" * 90)
        lines.append(f"{'System':<20} {'DR':>8} {'Latency':>10} {'FP/12h':>8} {'F1':>8} {'AUC':>8}")
        lines.append("-" * 90)
        
        systems = [('SENTINEL', sentinel_metrics)] + [
            (name, metrics) for name, metrics in baseline_metrics.items()
        ]
        
        for name, metrics in systems:
            latency = metrics.get('latency', {})
            latency_mean = latency.get('mean', 0) if isinstance(latency, dict) else latency
            
            lines.append(
                f"{name:<20} "
                f"{metrics.get('detection_rate', 0):>8.3f} "
                f"{latency_mean:>10.2f}s "
                f"{metrics.get('false_positives_per_12h', 0):>8.1f} "
                f"{metrics.get('f1', 0):>8.3f} "
                f"{metrics.get('auc', 0):>8.3f}"
            )
        
        lines.append("=" * 90 + "\n")
        
        return "\n".join(lines)
