"""
SENTINEL Mitigation Controller - 3-tier graduated response system.
"""
import time
from dataclasses import dataclass, field
from typing import List

from .config import (
    MITIGATION_TIER_1, MITIGATION_TIER_2, MITIGATION_TIER_3,
    MITIGATION_ALERT, DEESCALATION_TIER3_THRESH,
    DEESCALATION_TIER3_DURATION, DEESCALATION_ALL_DURATION,
)


@dataclass
class MitigationAction:
    tier: int
    score: float
    affected_sources: List[str] = field(default_factory=list)
    action_description: str = ""
    timestamp: float = 0.0

    def to_dict(self):
        return {
            "tier": self.tier, "score": self.score,
            "affected_sources": self.affected_sources,
            "action_description": self.action_description,
            "timestamp": self.timestamp,
        }


class MitigationController:
    """3-tier graduated mitigation with de-escalation hysteresis."""

    def __init__(self):
        self.current_tier = 0
        self.tier1_start_time = None
        self.tier1_start_score = None
        self.last_mitigation_time = None
        self._below_threshold_start = None
        self._below_50_start = None
        self._action_log: List[MitigationAction] = []

    def apply(self, score: float, contributing_sources: List[str] = None) -> MitigationAction:
        now = time.time()
        sources = contributing_sources or []

        # Auto-escalation: Tier 1 active >60s without score reduction
        if (self.current_tier == 1 and self.tier1_start_time is not None
                and now - self.tier1_start_time > 60):
            self.current_tier = 2

        # De-escalation: Tier 3 -> clear when S < 0.60 for 120 consecutive seconds
        if self.current_tier == 3 and score < DEESCALATION_TIER3_THRESH:
            if self._below_threshold_start is None:
                self._below_threshold_start = now
            elif now - self._below_threshold_start > DEESCALATION_TIER3_DURATION:
                self.current_tier = 0
                self._below_threshold_start = None
        else:
            self._below_threshold_start = None

        # All mitigation off when S < 0.50 for 300s
        if score < MITIGATION_ALERT:
            if self._below_50_start is None:
                self._below_50_start = now
            elif now - self._below_50_start > DEESCALATION_ALL_DURATION:
                self.current_tier = 0
                self.tier1_start_time = None
                self._below_50_start = None
        else:
            self._below_50_start = None

        # Determine action based on score
        if score < MITIGATION_ALERT:
            tier = 0
            desc = "Monitoring"
        elif score < MITIGATION_TIER_1:
            tier = 0
            desc = f"ALERT: Score {score:.3f} - manual review recommended"
        elif score < MITIGATION_TIER_2:
            tier = 1
            if self.tier1_start_time is None:
                self.tier1_start_time = now
                self.tier1_start_score = score
            desc = f"TIER-1: Rate limiting {len(sources)} sources to 2x baseline"
        elif score < MITIGATION_TIER_3:
            tier = 2
            desc = f"TIER-2: Aggressive limiting + challenges for {len(sources)} sources"
        else:
            tier = 3
            desc = f"TIER-3: BLOCKING {len(sources)} top sources (5-min expiry)"

        # Only escalate, don't downgrade within same cycle (hysteresis)
        if tier > self.current_tier:
            self.current_tier = tier
            if tier == 1 and self.tier1_start_time is None:
                self.tier1_start_time = now
                self.tier1_start_score = score
        elif tier < self.current_tier:
            # Keep current tier for hysteresis
            tier = self.current_tier

        action = MitigationAction(
            tier=tier,
            score=score,
            affected_sources=sources[:100],
            action_description=desc,
            timestamp=now,
        )
        self._action_log.append(action)
        self.last_mitigation_time = now
        return action

    def get_action_history(self):
        return list(self._action_log)
