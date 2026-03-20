"""
SENTINEL Baseline Module

EWMA-based adaptive baseline profiling with temporal context awareness.
Stores baselines per feature per (hour_of_day, day_of_week) context.

Reference: Section 3.3 in "SENTINEL: A Behavioral DDoS Detection Framework"
"""

import time
import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List, Any
from datetime import datetime
import numpy as np

from ..config import DEFAULT_CONFIG


@dataclass
class BaselineStats:
    """Baseline statistics for a feature in a temporal context."""
    mean: float
    variance: float
    sample_count: int = 0
    observations: List[float] = None
    
    def __post_init__(self):
        if self.observations is None:
            self.observations = []


class TemporalBaseline:
    """
    EWMA baseline with temporal context awareness.
    
    Maintains 24 x 7 = 168 temporal context slots per feature,
    plus one global fallback.
    """
    
    def __init__(self, feature_id: str, alpha: float = None, epsilon: float = None):
        self.feature_id = feature_id
        self.alpha = alpha or DEFAULT_CONFIG.alpha
        self.epsilon = epsilon or DEFAULT_CONFIG.epsilon
        
        self._contexts: Dict[Tuple[int, int], BaselineStats] = {}
        self._global: Optional[BaselineStats] = None
        
        self._learning_phase = True
        self._learning_observations: Dict[Tuple[int, int], List[float]] = defaultdict(list)
        self._learning_start_time: Optional[float] = None
        self._learning_duration_hours: int = DEFAULT_CONFIG.learning_phase_hours
    
    def _get_context(self, hour: int, day_of_week: int) -> Tuple[int, int]:
        """Normalize temporal context indices."""
        hour = max(0, min(23, int(hour) % 24))
        day_of_week = max(0, min(6, int(day_of_week) % 7))
        return (hour, day_of_week)
    
    def _get_or_create_stats(self, hour: int, day_of_week: int) -> BaselineStats:
        """Get or create baseline stats for a temporal context."""
        ctx = self._get_context(hour, day_of_week)
        
        if ctx not in self._contexts:
            self._contexts[ctx] = BaselineStats(mean=0.0, variance=0.0)
        
        return self._contexts[ctx]
    
    def get(self, hour: Optional[int] = None, 
            day_of_week: Optional[int] = None) -> Tuple[float, float]:
        """
        Get baseline (mean, variance) for current or specified temporal context.
        
        Returns:
            Tuple of (mean, variance)
        """
        if hour is None or day_of_week is None:
            now = datetime.now()
            hour = now.hour
            day_of_week = now.weekday()
        
        stats = self._get_or_create_stats(hour, day_of_week)
        
        if stats.sample_count == 0:
            if self._global and self._global.sample_count > 0:
                return (self._global.mean, self._global.variance)
            return (0.0, 1.0)
        
        return (stats.mean, stats.variance)
    
    def update(self, value: float, hour: Optional[int] = None,
               day_of_week: Optional[int] = None):
        """
        Update baseline with new observation using EWMA rule.
        
        μ_t = α * x_t + (1-α) * μ_{t-1}
        σ²_t = α * (x_t - μ_t)² + (1-α) * σ²_{t-1}
        
        Reference: Equation (2) in the paper.
        """
        if self._learning_phase:
            self._add_learning_observation(value, hour, day_of_week)
            return
        
        if hour is None or day_of_week is None:
            now = datetime.now()
            hour = now.hour
            day_of_week = now.weekday()
        
        stats = self._get_or_create_stats(hour, day_of_week)
        
        if stats.sample_count == 0:
            stats.mean = value
            stats.variance = 0.0
        else:
            old_mean = stats.mean
            
            stats.mean = self.alpha * value + (1 - self.alpha) * stats.mean
            
            diff = value - stats.mean
            stats.variance = (self.alpha * diff * diff + 
                            (1 - self.alpha) * stats.variance)
        
        stats.sample_count += 1
        
        if self._global is None:
            self._global = BaselineStats(mean=stats.mean, variance=stats.variance)
        else:
            self._global.mean = (self.alpha * stats.mean + 
                               (1 - self.alpha) * self._global.mean)
            self._global.variance = (self.alpha * stats.variance + 
                                    (1 - self.alpha) * self._global.variance)
            self._global.sample_count += 1
    
    def _add_learning_observation(self, value: float, hour: Optional[int],
                                  day_of_week: Optional[int]):
        """Collect observations during learning phase."""
        if hour is None or day_of_week is None:
            now = datetime.now()
            hour = now.hour
            day_of_week = now.weekday()
        
        ctx = self._get_context(hour, day_of_week)
        self._learning_observations[ctx].append(value)
        
        if self._learning_start_time is None:
            self._learning_start_time = time.time()
    
    def compute_z_score(self, value: float, hour: Optional[int] = None,
                        day_of_week: Optional[int] = None) -> float:
        """
        Compute z-score for a value against the baseline.
        
        z = (x - μ) / max(√σ², ε)
        
        Reference: Equation (1) in the paper.
        """
        mean, variance = self.get(hour, day_of_week)
        
        std = max(math.sqrt(variance), self.epsilon)
        return (value - mean) / std
    
    def is_learning(self) -> bool:
        """Check if still in learning phase."""
        return self._learning_phase
    
    def finalize_learning(self, use_synthetic: bool = False,
                          synthetic_data: Optional[Dict] = None):
        """
        Finalize learning phase and compute baselines from collected observations.
        
        Applies IQR outlier exclusion before computing final baselines.
        
        Args:
            use_synthetic: If True, seed baselines from synthetic data
            synthetic_data: Pre-computed synthetic baseline values
        """
        if use_synthetic and synthetic_data:
            for (hour, dow), stats in self._contexts.items():
                if (hour, dow) in synthetic_data:
                    synthetic = synthetic_data[(hour, dow)]
                    self._contexts[(hour, dow)] = BaselineStats(
                        mean=synthetic.get('mean', 0.0),
                        variance=synthetic.get('variance', 1.0),
                        sample_count=synthetic.get('count', 100)
                    )
            self._learning_phase = False
            return
        
        for ctx, observations in self._learning_observations.items():
            if len(observations) < 10:
                continue
            
            clean_obs = self._apply_iqr_filter(observations)
            
            if clean_obs:
                mean = np.mean(clean_obs)
                variance = np.var(clean_obs)
                self._contexts[ctx] = BaselineStats(
                    mean=mean,
                    variance=variance,
                    sample_count=len(clean_obs),
                    observations=clean_obs
                )
        
        if self._contexts:
            means = [s.mean for s in self._contexts.values()]
            variances = [s.variance for s in self._contexts.values()]
            self._global = BaselineStats(
                mean=np.mean(means) if means else 0.0,
                variance=np.mean(variances) if variances else 1.0,
                sample_count=sum(s.sample_count for s in self._contexts.values())
            )
        
        self._learning_phase = False
        self._learning_observations.clear()
    
    def _apply_iqr_filter(self, observations: List[float]) -> List[float]:
        """
        Apply IQR outlier exclusion.
        
        Removes observations beyond 1.5 × IQR from median.
        
        Reference: Section 3.4 in the paper.
        """
        if len(observations) < 4:
            return observations
        
        sorted_obs = sorted(observations)
        q1_idx = len(sorted_obs) // 4
        q3_idx = 3 * len(sorted_obs) // 4
        
        q1 = sorted_obs[q1_idx]
        q3 = sorted_obs[q3_idx]
        iqr = q3 - q1
        
        median = sorted_obs[len(sorted_obs) // 2]
        
        lower_bound = median - 1.5 * iqr
        upper_bound = median + 1.5 * iqr
        
        return [x for x in observations if lower_bound <= x <= upper_bound]
    
    def get_all_contexts(self) -> Dict[Tuple[int, int], BaselineStats]:
        """Get all temporal context baselines."""
        return self._contexts.copy()
    
    def get_global(self) -> Optional[BaselineStats]:
        """Get global fallback baseline."""
        return self._global
    
    def reset(self):
        """Reset baseline to initial state."""
        self._contexts.clear()
        self._global = None
        self._learning_observations.clear()
        self._learning_phase = True
        self._learning_start_time = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize baseline to dictionary."""
        contexts = {}
        for (h, d), stats in self._contexts.items():
            contexts[f"{h}_{d}"] = {
                'mean': stats.mean,
                'variance': stats.variance,
                'sample_count': stats.sample_count,
            }
        
        return {
            'feature_id': self.feature_id,
            'alpha': self.alpha,
            'contexts': contexts,
            'global': {
                'mean': self._global.mean if self._global else 0.0,
                'variance': self._global.variance if self._global else 1.0,
            } if self._global else None,
            'learning_phase': self._learning_phase,
        }


class BaselineStore:
    """
    Manages EWMA baselines for all features.
    
    Provides centralized access to per-feature temporal baselines.
    """
    
    def __init__(self, alpha: float = None, epsilon: float = None,
                 skip_learning: bool = False):
        self.alpha = alpha or DEFAULT_CONFIG.alpha
        self.epsilon = epsilon or DEFAULT_CONFIG.epsilon
        self.skip_learning = skip_learning
        
        self._baselines: Dict[str, TemporalBaseline] = {}
        
        self._synthetic_baseline_data: Optional[Dict] = None
    
    def get_baseline(self, feature_id: str) -> TemporalBaseline:
        """Get or create baseline for a feature."""
        if feature_id not in self._baselines:
            self._baselines[feature_id] = TemporalBaseline(
                feature_id=feature_id,
                alpha=self.alpha,
                epsilon=self.epsilon
            )
            
            if self.skip_learning:
                self._initialize_synthetic_baseline(feature_id)
        
        return self._baselines[feature_id]
    
    def _initialize_synthetic_baseline(self, feature_id: str):
        """Initialize baseline with synthetic normal traffic parameters."""
        synthetic_params = {
            'new_connection_rate': {'mean': 5.0, 'variance': 4.0},
            'concurrent_connection_count': {'mean': 20.0, 'variance': 100.0},
            'mean_connection_duration': {'mean': 2.0, 'variance': 2.25},
            'variance_connection_duration': {'mean': 1.0, 'variance': 1.0},
            'handshake_completion_ratio': {'mean': 0.95, 'variance': 0.0025},
            'request_rate': {'mean': 50.0, 'variance': 400.0},
            'inter_request_timing_variance': {'mean': 0.5, 'variance': 0.25},
            'protocol_compliance_score': {'mean': 0.98, 'variance': 0.0004},
            'total_request_rate': {'mean': 500.0, 'variance': 10000.0},
            'unique_source_count': {'mean': 100.0, 'variance': 500.0},
            'geographic_entropy': {'mean': 3.5, 'variance': 0.25},
            'backend_error_rate': {'mean': 0.02, 'variance': 0.0004},
            'response_latency_mean': {'mean': 0.1, 'variance': 0.01},
            'source_diversity_per_minute': {'mean': 50.0, 'variance': 100.0},
            'geo_distribution_shift_rate': {'mean': 0.01, 'variance': 0.0001},
            'cross_source_timing_correlation': {'mean': 0.1, 'variance': 0.01},
            'protocol_frequency_ratio': {'mean': 0.8, 'variance': 0.04},
            'payload_entropy_proxy': {'mean': 0.5, 'variance': 0.0625},
        }
        
        baseline = self._baselines[feature_id]
        params = synthetic_params.get(feature_id, {'mean': 1.0, 'variance': 1.0})
        
        synthetic_data = {}
        for hour in range(24):
            for dow in range(7):
                synthetic_data[(hour, dow)] = params
        
        baseline.finalize_learning(use_synthetic=True, synthetic_data=synthetic_data)
    
    def get(self, feature_id: str, hour: Optional[int] = None,
            day_of_week: Optional[int] = None) -> Tuple[float, float]:
        """Get baseline statistics for a feature."""
        return self.get_baseline(feature_id).get(hour, day_of_week)
    
    def update(self, feature_id: str, value: float,
               hour: Optional[int] = None, day_of_week: Optional[int] = None):
        """Update baseline with new observation."""
        self.get_baseline(feature_id).update(value, hour, day_of_week)
    
    def compute_z_score(self, feature_id: str, value: float,
                       hour: Optional[int] = None,
                       day_of_week: Optional[int] = None) -> float:
        """Compute z-score for a feature value."""
        return self.get_baseline(feature_id).compute_z_score(value, hour, day_of_week)
    
    def finalize_all_learning(self, synthetic_data: Optional[Dict] = None):
        """Finalize learning for all baselines."""
        for baseline in self._baselines.values():
            if baseline.is_learning():
                baseline.finalize_learning(
                    use_synthetic=self.skip_learning,
                    synthetic_data=synthetic_data
                )
    
    def is_any_learning(self) -> bool:
        """Check if any baseline is still in learning phase."""
        return any(b.is_learning() for b in self._baselines.values())
    
    def get_feature_ids(self) -> List[str]:
        """Get list of all registered feature IDs."""
        return list(self._baselines.keys())
    
    def reset(self):
        """Reset all baselines."""
        for baseline in self._baselines.values():
            baseline.reset()
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize baseline store to dictionary."""
        return {
            'baselines': {fid: b.to_dict() for fid, b in self._baselines.items()},
            'alpha': self.alpha,
            'skip_learning': self.skip_learning,
        }
