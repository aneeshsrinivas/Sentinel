"""
SENTINEL Attack Scenarios

Implements all 5 attack scenarios exactly as specified in the paper.
Compatible with the TrafficGenerator class.

Reference: Section 5.1 in "SENTINEL: A Behavioral DDoS Detection Framework"
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List


@dataclass
class Scenario:
    """Attack scenario configuration."""
    id: str
    name: str
    description: str
    duration: float
    attack_start: float
    generator_kwargs: Dict[str, Any] = field(default_factory=dict)

    @property
    def generator_class(self):
        return None


SCENARIOS = {
    "http_flood": Scenario(
        id="http_flood",
        name="HTTP Flood Attack",
        description="High-volume HTTP request flood targeting dynamic endpoints",
        duration=600.0,
        attack_start=30.0,
        generator_kwargs={
            "sources": 100,
            "rate_per_source": 50.0,
        },
    ),

    "slowloris": Scenario(
        id="slowloris",
        name="Slowloris Attack",
        description="Slow HTTP header attack exhausting connection pool",
        duration=900.0,
        attack_start=30.0,
        generator_kwargs={
            "sources": 100,
            "concurrent_per_source": 50,
        },
    ),

    "connection_flood": Scenario(
        id="connection_flood",
        name="Connection Flood Attack",
        description="Massive new connection flood exhausting server connections",
        duration=480.0,
        attack_start=30.0,
        generator_kwargs={
            "sources": 100,
            "conns_per_sec": 100.0,
        },
    ),

    "low_rate_distributed": Scenario(
        id="low_rate_distributed",
        name="Low-Rate Distributed Attack",
        description="Stealthy low-rate attack targeting CPU-intensive endpoints",
        duration=1200.0,
        attack_start=30.0,
        generator_kwargs={
            "sources": 500,
            "rate_per_source": 2.0,
        },
    ),

    "synchronized_burst": Scenario(
        id="synchronized_burst",
        name="Synchronized Burst Attack",
        description="Coordinated burst attacks with quiet periods",
        duration=720.0,
        attack_start=30.0,
        generator_kwargs={
            "sources": 100,
            "burst_size": 200,
            "burst_window": 5.0,
            "quiet_period": 25.0,
        },
    ),
}


def get_scenario(scenario_id: str) -> Scenario:
    """Get scenario configuration by ID."""
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    return SCENARIOS[scenario_id]


def get_all_scenarios() -> List[Scenario]:
    """Get all available scenarios."""
    return list(SCENARIOS.values())


def get_scenario_summary() -> Dict[str, Dict]:
    """Get summary of all scenarios."""
    return {
        sid: {
            "name": s.name,
            "description": s.description,
            "duration": s.duration,
        }
        for sid, s in SCENARIOS.items()
    }
