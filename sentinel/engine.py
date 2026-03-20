import json
import time
import yaml
import os
from datetime import datetime
from sentinel.baseline.ewma import EWMABaseline
from sentinel.anomaly.accumulator import LeakyAccumulator
from sentinel.correlation.scorer import CorrelationEngine

class SentinelEngine:
    def __init__(self, config_dir="configs"):
        # Load configs
        self.config_dir = config_dir
        self.params = self._load_yaml(os.path.join(config_dir, "detection_params.yaml"))
        self.weights = os.path.join(config_dir, "feature_weights.yaml")
        
        # Initialize submodules
        self.baseline = EWMABaseline(alpha=self.params.get("ewma_alpha", 0.3))
        self.accumulator = LeakyAccumulator(
            decay_rate=self.params.get("accumulator_decay", 0.8),
            z_threshold=self.params.get("zscore_threshold", 3.0),
            alert_threshold=self.params.get("accumulator_threshold", 5.0)
        )
        self.correlation = CorrelationEngine(
            weights_file=self.weights,
            window_size=self.params.get("correlation_window", 60)
        )
        self.current_mitigation_tier = 0

    def _load_yaml(self, path):
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        except Exception:
            return {}

    def process_features(self, feature_dict, timestamp=None):
        """
        Process a batch of extracted features from the current temporal window.
        feature_dict format: {"per_source_request_rate_spike": 500, "geographic_entropy_reduction": 0.5, ...}
        """
        if timestamp is None:
            timestamp = time.time()
            
        results = []
        for feature_name, value in feature_dict.items():
            z_score = self.baseline.update_and_get_zscore(feature_name, value)
            acc_val, is_anomalous = self.accumulator.process_zscore(feature_name, z_score)
            
            if is_anomalous:
                # Confidence proportional to z_score, capped at 1.0
                confidence = min(abs(z_score) / 5.0, 1.0)
                self.correlation.add_anomaly(feature_name, confidence, timestamp)
            
            results.append({
                "feature": feature_name,
                "value": value,
                "z_score": z_score,
                "accumulator": acc_val,
                "is_anomalous": is_anomalous
            })
            
        # Calculate global correlation score
        score = self.correlation.get_score(timestamp)
        
        # Update mitigation tier
        self._update_mitigation(score)
        
        # Determine worst feature string for logging
        worst_feature = max(results, key=lambda x: x["accumulator"]) if results else None
        
        # Log event
        log_entry = {
            "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            "feature": worst_feature["feature"] if worst_feature else "none",
            "z_score": round(worst_feature["z_score"], 3) if worst_feature else 0.0,
            "accumulator": round(worst_feature["accumulator"], 3) if worst_feature else 0.0,
            "correlation_score": round(score, 3),
            "mitigation_tier": self.current_mitigation_tier
        }
        return json.dumps(log_entry)

    def _update_mitigation(self, score):
        if score >= self.params.get("mitigation_tier3_threshold", 0.90):
            self.current_mitigation_tier = 3
        elif score >= self.params.get("mitigation_tier2_threshold", 0.85):
            self.current_mitigation_tier = max(self.current_mitigation_tier, 2)
        elif score >= self.params.get("mitigation_tier1_threshold", 0.70):
            self.current_mitigation_tier = max(self.current_mitigation_tier, 1)
        elif score < self.params.get("mitigation_deescalation_score", 0.60):
            self.current_mitigation_tier = 0

if __name__ == "__main__":
    engine = SentinelEngine()
    print(engine.process_features({"per_source_request_rate_spike": 100}))
