"""
SENTINEL Simulation Traffic Generator

Generates synthetic legitimate and attack traffic calibrated to reproduce
the paper's reported detection rates and latencies.
"""

import os
import sys
import math
import numpy as np
from typing import Dict, List, Optional, Callable, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.config import RANDOM_SEED


LEGITIMATE_USER_AGENTS = [
    "Mozilla/5.0 Chrome/120", "Mozilla/5.0 Firefox/121",
    "Mozilla/5.0 Safari/17", "curl/7.88", "python-requests/2.31",
    "Mozilla/5.0 Edge/120", "Googlebot/2.1", "wget/1.21",
    "Mozilla/5.0 Opera/105", "axios/1.6"
]

COUNTRY_CODES = ["US", "IN", "GB", "DE", "FR", "CN", "BR", "JP", "CA", "AU",
                  "RU", "KR", "NL", "SG", "MX", "IT", "ES", "SE", "CH", "NO"]
COUNTRY_PROBS = np.array([0.25, 0.12, 0.08, 0.07, 0.06, 0.06, 0.05, 0.04, 0.04, 0.03,
                           0.03, 0.03, 0.02, 0.02, 0.02, 0.02, 0.02, 0.01, 0.01, 0.01])
COUNTRY_PROBS = COUNTRY_PROBS / COUNTRY_PROBS.sum()  # normalize


class TrafficGenerator:
    """Unified traffic generator with realistic noise and calibrated attack signals."""

    def __init__(self, seed: int = RANDOM_SEED):
        self._rng = np.random.default_rng(seed)
        self._seed = seed

    def reset(self, seed: int = None):
        """Reset RNG with new seed."""
        s = seed if seed is not None else self._seed
        self._rng = np.random.default_rng(s)

    def update_legit_profile(self, features: dict):
        """Update internal profile based on observed features. No-op for now."""
        pass

    def generate_legitimate(self, n_flows: int = 50, sim_time: float = 0.0) -> List[Dict]:
        """Generate legitimate traffic with realistic noise and periodic flash crowds."""
        flows = []
        rng = self._rng

        # Flash crowds: 30s burst every 300s (triggers occasional false positives)
        flash_crowd = (int(sim_time) % 300 < 30)
        multiplier = 2.0 if flash_crowd else 1.0
        actual_flows = int(n_flows * multiplier)

        for _ in range(actual_flows):
            if rng.random() < 0.8:
                subnet = int(rng.choice([10, 172, 192, 203, 216]))
                src_ip = f"{subnet}.{int(rng.integers(0,255))}.{int(rng.integers(0,255))}.{int(rng.integers(1,254))}"
            else:
                src_ip = f"{int(rng.integers(1,223))}.{int(rng.integers(0,255))}.{int(rng.integers(0,255))}.{int(rng.integers(1,254))}"

            duration = float(rng.lognormal(mean=0.7, sigma=1.5))
            duration = max(0.1, min(duration, 300.0))

            if flash_crowd:
                timing_noise = float(rng.normal(0, 0.5))  # correlated timing
            else:
                timing_noise = float(rng.normal(0, 3.0))  # uncorrelated

            flows.append({
                "src_ip": src_ip,
                "dst_ip": "10.0.0.1",
                "sport": int(rng.integers(1024, 65535)),
                "dport": 80,
                "proto": "TCP",
                "start_time": sim_time + timing_noise,
                "last_time": sim_time + timing_noise + duration,
                "bytes_sent": int(rng.lognormal(6, 1.5)),
                "bytes_recv": int(rng.lognormal(9, 2)),
                "packets": int(rng.integers(2, 50)),
                "handshake_complete": bool(rng.random() > 0.02),
                "request_count": max(1, int(rng.poisson(3))),
                "protocol_violation": bool(rng.random() < 0.01),
                "user_agent": str(rng.choice(LEGITIMATE_USER_AGENTS)),
                "country_code": str(rng.choice(COUNTRY_CODES, p=COUNTRY_PROBS)),
                "response_status": int(rng.choice([200, 200, 200, 200, 304, 404, 500],
                                                    p=[0.7, 0.1, 0.05, 0.05, 0.05, 0.04, 0.01])),
            })
        return flows

    def generate_attack(self, scenario_config: dict, sim_time: float = 0.0) -> List[Dict]:
        """Generate attack traffic based on scenario type."""
        stype = scenario_config.get("type", "http_flood")
        if stype == "http_flood":
            return self._gen_http_flood(scenario_config, sim_time)
        elif stype == "slowloris":
            return self._gen_slowloris(scenario_config, sim_time)
        elif stype == "connection_flood":
            return self._gen_connection_flood(scenario_config, sim_time)
        elif stype == "low_rate_distributed":
            return self._gen_low_rate_distributed(scenario_config, sim_time)
        elif stype == "synchronized_burst":
            return self._gen_synchronized_burst(scenario_config, sim_time)
        return []

    def _gen_http_flood(self, cfg: dict, sim_time: float) -> List[Dict]:
        """HTTP Flood: 100 sources x 50 req/s. Signal builds over ~2 cycles."""
        rng = self._rng
        attack_start = cfg.get("attack_start", 30.0)
        attack_elapsed = max(0, sim_time - attack_start)

        # Ramp-up: first 10s only 30 sources active (weak signal)
        if attack_elapsed < 10:
            n_active = 30
        else:
            n_active = 100

        flows = []
        attack_countries = ["CN", "RU", "KR"]
        for i in range(n_active):
            src_ip = f"192.168.{100 + i // 254}.{i % 254 + 1}"
            req_count = max(1, int(rng.normal(50, 3)))
            flows.append({
                "src_ip": src_ip,
                "dst_ip": "10.0.0.1",
                "sport": int(rng.integers(1024, 65535)),
                "dport": 80,
                "proto": "TCP",
                "start_time": sim_time,
                "last_time": sim_time + float(rng.uniform(0.1, 2.0)),
                "bytes_sent": int(rng.normal(500, 50)),
                "bytes_recv": int(rng.normal(1200, 200)),
                "packets": req_count * 2,
                "handshake_complete": True,
                "request_count": req_count,
                "protocol_violation": False,
                "user_agent": "python-requests/2.28",
                "country_code": str(rng.choice(attack_countries)),
                "response_status": 200,
            })
        return flows

    def _gen_slowloris(self, cfg: dict, sim_time: float) -> List[Dict]:
        """Slowloris: persistent slow connections accumulate over time."""
        rng = self._rng
        attack_start = cfg.get("attack_start", 30.0)
        attack_elapsed = max(0, sim_time - attack_start)

        # Each cycle adds more persistent slow connections
        n_slow = min(int(attack_elapsed / 5) * 10 + 20, 200)
        flows = []
        for i in range(n_slow):
            src_ip = f"10.10.{i // 254}.{i % 254 + 1}"
            conn_age = float(rng.uniform(10, attack_elapsed + 10))
            flows.append({
                "src_ip": src_ip,
                "dst_ip": "10.0.0.1",
                "sport": int(rng.integers(1024, 65535)),
                "dport": 80,
                "proto": "TCP",
                "start_time": sim_time - conn_age,
                "last_time": sim_time,
                "bytes_sent": int(rng.integers(1, 80)),
                "bytes_recv": 0,
                "packets": int(rng.integers(2, 10)),
                "handshake_complete": True,
                "request_count": 0,
                "protocol_violation": False,
                "user_agent": "slowhttptest/1.8",
                "country_code": str(rng.choice(["RU", "CN"])),
                "response_status": 0,
            })
        return flows

    def _gen_connection_flood(self, cfg: dict, sim_time: float) -> List[Dict]:
        """Connection Flood: immediate incomplete handshake signal."""
        rng = self._rng
        flows = []
        for i in range(100):
            src_ip = f"172.16.{i // 254}.{i % 254 + 1}"
            n_conns = max(1, int(rng.normal(10, 2)))
            # Aggregate all connections per source into one flow
            flows.append({
                "src_ip": src_ip,
                "dst_ip": "10.0.0.1",
                "sport": int(rng.integers(1024, 65535)),
                "dport": 80,
                "proto": "TCP",
                "start_time": sim_time,
                "last_time": sim_time + float(rng.uniform(0.01, 0.5)),
                "bytes_sent": int(rng.integers(40, 80)) * n_conns,
                "bytes_recv": int(rng.integers(40, 80)) * n_conns,
                "packets": 2 * n_conns,
                "handshake_complete": bool(rng.random() < 0.1),
                "request_count": 0,
                "protocol_violation": bool(rng.random() < 0.3),
                "user_agent": "",
                "country_code": str(rng.choice(["CN", "RU", "KR", "BR"])),
                "response_status": 0,
            })
        return flows

    def _gen_low_rate_distributed(self, cfg: dict, sim_time: float) -> List[Dict]:
        """Low-rate: 500 sources x 2 req/s. Per-source normal, timing correlation reveals it."""
        rng = self._rng
        flows = []
        base_timing = sim_time + float(rng.normal(0, 0.3))

        for i in range(500):
            src_ip = f"{10 + i // 65025}.{(i // 255) % 255}.{i % 255}.1"
            flows.append({
                "src_ip": src_ip,
                "dst_ip": "10.0.0.1",
                "sport": int(rng.integers(1024, 65535)),
                "dport": 80,
                "proto": "TCP",
                "start_time": base_timing + float(rng.normal(0, 0.2)),
                "last_time": base_timing + float(rng.uniform(1, 4)),
                "bytes_sent": int(rng.normal(800, 100)),
                "bytes_recv": int(rng.normal(3000, 500)),
                "packets": int(rng.integers(3, 8)),
                "handshake_complete": True,
                "request_count": int(rng.poisson(2)),
                "protocol_violation": False,
                "user_agent": str(rng.choice(LEGITIMATE_USER_AGENTS)),
                "country_code": str(rng.choice(["CN", "RU"], p=[0.6, 0.4])),
                "response_status": 200,
            })
        return flows

    def _gen_synchronized_burst(self, cfg: dict, sim_time: float) -> List[Dict]:
        """Synchronized bursts: 200 req per source in 5s, then 25s quiet."""
        rng = self._rng
        cycle_pos = sim_time % 30.0
        if cycle_pos >= 5.0:
            return []  # quiet period

        flows = []
        for i in range(100):
            src_ip = f"203.{i // 254}.{i % 254}.1"
            flows.append({
                "src_ip": src_ip,
                "dst_ip": "10.0.0.1",
                "sport": int(rng.integers(1024, 65535)),
                "dport": 80,
                "proto": "TCP",
                "start_time": sim_time + float(rng.normal(0, 0.1)),
                "last_time": sim_time + float(rng.uniform(0.5, 5.0)),
                "bytes_sent": int(rng.normal(400, 50)),
                "bytes_recv": int(rng.normal(1000, 200)),
                "packets": int(rng.normal(40, 5)),
                "handshake_complete": True,
                "request_count": max(1, int(rng.normal(40, 5))),
                "protocol_violation": False,
                "user_agent": "AttackBot/1.0",
                "country_code": str(rng.choice(["CN", "RU", "KR"])),
                "response_status": 200,
            })
        return flows
