"""
SENTINEL - Behavioral DDoS Detection Framework
"""

__version__ = '1.0.0'

from .config import (
    ALPHA, LAMBDA, TAU_Z, THETA_A, WINDOW_SIZE,
    OBSERVATION_INTERVAL, DELTA_THRESH, DELTA_SEQ, EPSILON,
    DEFAULT_CONFIG, Config, ANOMALY_WEIGHTS,
)

from .baseline.ewma import EWMABaseline
from .baseline import BaselineStore, TemporalBaseline
from .anomaly.accumulator import LeakyAccumulator
from .correlation.scorer import CorrelationEngine, CorrelationEngineFactory

__all__ = [
    'ALPHA', 'LAMBDA', 'TAU_Z', 'THETA_A', 'WINDOW_SIZE',
    'OBSERVATION_INTERVAL', 'DELTA_THRESH', 'DELTA_SEQ', 'EPSILON',
    'DEFAULT_CONFIG', 'Config', 'ANOMALY_WEIGHTS',
    'EWMABaseline', 'BaselineStore', 'TemporalBaseline',
    'LeakyAccumulator', 'CorrelationEngine', 'CorrelationEngineFactory',
]
