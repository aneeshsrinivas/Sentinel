"""
Correlation engine — weighted sliding window scorer.
Implements Equation (4) from the paper:
  S_t = Σ w_i * c_i  for all events i in window W ending at t
Plus sequential template boost Δseq = 0.2 if attack progression matched.
"""
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional, Dict

from ..config import (
    WINDOW_SIZE as CORRELATION_WINDOW,
    DELTA_THRESH as DETECTION_THRESHOLD,
    DELTA_SEQ as TEMPLATE_BOOST,
)

ANOMALY_WEIGHTS = {
    "distributed_connection_burst":  0.50,
    "synchronized_request_timing":   0.40,
    "incomplete_handshake_spike":    0.35,
    "geographic_entropy_reduction":  0.30,
    "session_duration_anomaly":      0.25,
    "per_source_request_spike":      0.20,
    "protocol_compliance_violation": 0.15,
    "user_agent_homogeneity":        0.10,
}

# Attack progression template: these anomaly types in this order = boost
ATTACK_TEMPLATE = [
    "distributed_connection_burst",
    "per_source_request_spike",
    "incomplete_handshake_spike",
    "geographic_entropy_reduction",
]


@dataclass
class AnomalyEvent:
    feature_id: str
    confidence: float
    timestamp: float

    def to_dict(self):
        return {
            "feature_id": self.feature_id,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


class CorrelationEngine:
    """
    Maintains a sliding window of W=60s over confirmed anomaly events.
    Computes weighted correlation score each cycle.
    Expires events older than W seconds every call to score().
    """

    def __init__(self, window_size: int = None, delta_seq: float = None,
                 weights: Dict[str, float] = None):
        # deque of AnomalyEvent, ordered by timestamp ascending
        self._window: deque = deque()
        self.weights = dict(weights) if weights else dict(ANOMALY_WEIGHTS)
        self._correlation_window = window_size if window_size is not None else CORRELATION_WINDOW
        self._template_boost = delta_seq if delta_seq is not None else TEMPLATE_BOOST
        self.detection_threshold = DETECTION_THRESHOLD
        self._last_score: float = 0.0

    def enqueue(self, feature_id: str, confidence: float,
                timestamp: Optional[float] = None):
        """Add a confirmed anomaly event to the sliding window."""
        if timestamp is None:
            timestamp = time.time()
        event = AnomalyEvent(
            feature_id=feature_id,
            confidence=float(confidence),
            timestamp=float(timestamp),
        )
        self._window.append(event)

    def score(self, current_time: Optional[float] = None) -> float:
        """
        Expire stale events, then compute weighted sum.
        This MUST remove events older than W=60s on every call —
        that is what prevents the score from locking at 1.0.
        """
        if current_time is None:
            current_time = time.time()

        # --- CRITICAL: expire events outside the sliding window ---
        cutoff = current_time - self._correlation_window
        while self._window and self._window[0].timestamp < cutoff:
            self._window.popleft()
        # ----------------------------------------------------------

        if not self._window:
            self._last_score = 0.0
            return 0.0

        # Weighted sum: S_t = Σ w_i * c_i
        total = 0.0
        for event in self._window:
            w = self.weights.get(event.feature_id, 0.05)
            total += w * event.confidence

        # Cap at 1.0
        total = min(total, 1.0)

        # Sequential template boost
        if self._template_matched():
            total = min(total + self._template_boost, 1.0)

        self._last_score = total
        return total

    def _template_matched(self) -> bool:
        """
        Returns True if the recent events contain the attack progression
        template in temporal order (not necessarily consecutive).
        """
        seen = []
        for event in self._window:
            if event.feature_id in ATTACK_TEMPLATE:
                if event.feature_id not in seen:
                    seen.append(event.feature_id)
        template_idx = 0
        for item in seen:
            if template_idx < len(ATTACK_TEMPLATE) and item == ATTACK_TEMPLATE[template_idx]:
                template_idx += 1
        return template_idx >= 3  # at least 3 of 4 template steps matched in order

    def get_current_score(self) -> float:
        """Return last computed score without re-scoring."""
        return self._last_score

    def get_tier(self) -> int:
        """Compute mitigation tier from current score."""
        s = self._last_score
        if s >= 0.90:
            return 3
        elif s >= 0.85:
            return 2
        elif s >= 0.70:
            return 1
        elif s >= 0.50:
            return 0
        return -1

    def recent_events(self) -> list:
        return list(self._window)

    def clear(self):
        self._window.clear()
        self._last_score = 0.0


def CorrelationEngineFactory(**kwargs):
    return CorrelationEngine(**kwargs)
