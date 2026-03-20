"""
Ablation study: measures contribution of each SENTINEL component
by running the full experiment suite with one component disabled.
Results are measured, never hardcoded.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from sentinel.detector import SentinelDetector, FEATURE_NAMES
from sentinel.config import OBSERVATION_INTERVAL, DELTA_THRESH, TAU_Z, THETA_A
from simulation.traffic_generator import TrafficGenerator
from simulation.scenarios import SCENARIOS


def make_detector(config_name: str) -> SentinelDetector:
    """Factory — returns a detector variant for each ablation config."""
    detector = SentinelDetector(simulation_mode=True)

    if config_name == "NoEWMA":
        # Baseline barely adapts — use large smoothing factor
        detector._no_ewma = True

    elif config_name == "NoLeaky":
        # Any z > tau_z immediately confirms anomaly
        for acc in detector.accumulators.values():
            acc.alert_threshold = 0.001

    elif config_name == "NoWeight":
        # Uniform weights for correlation engine
        n = len(detector.correlation.weights)
        if n > 0:
            uniform = 1.0 / n
            for k in detector.correlation.weights:
                detector.correlation.weights[k] = uniform

    elif config_name == "Single":
        # Alert on any single confirmed anomaly
        detector._single_mode = True

    return detector


def _do_seed_baseline(detector, gen, n_intervals=120):
    """Seed baseline from legitimate traffic."""
    import numpy as np
    rng = np.random.default_rng(42)
    feature_values = {fname: [] for fname in FEATURE_NAMES}

    for i in range(n_intervals):
        sim_time = float(i * OBSERVATION_INTERVAL)
        n_flows = max(10, int(rng.normal(50, 10)))
        flows = gen.generate_legitimate(n_flows=n_flows, sim_time=sim_time)
        features = detector.feature_extractor.extract(flows)
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
        variance = max(std * std, mean * 0.05 + 0.01, 0.1)
        bl = detector.baseline.get_baseline(fname)
        if bl.is_learning():
            bl.finalize_learning(use_synthetic=False, synthetic_data={})
        bl._global = BaselineStats(mean=mean, variance=variance, sample_count=n_intervals)
        bl._contexts[(12, 0)] = BaselineStats(mean=mean, variance=variance, sample_count=n_intervals)


def run_ablation_experiment(config_name: str, scenario_name: str, rep: int) -> dict:
    seed = 42 + rep * 100
    scenario = SCENARIOS[scenario_name]

    gen = TrafficGenerator(seed=seed)
    detector = make_detector(config_name)

    _do_seed_baseline(detector, gen, n_intervals=120)

    cfg = {
        "type": scenario.id,
        "attack_start": scenario.attack_start,
        **scenario.generator_kwargs,
    }

    detection_time = None
    peak_score = 0.0
    n_steps = int(scenario.duration / OBSERVATION_INTERVAL)

    for step in range(n_steps):
        sim_time = float(step * OBSERVATION_INTERVAL)

        legit = gen.generate_legitimate(n_flows=50, sim_time=sim_time)
        if sim_time >= scenario.attack_start:
            attack = gen.generate_attack(cfg, sim_time=sim_time)
        else:
            attack = []

        result = detector.step(legit + attack, sim_time=sim_time)
        score = result["score"]
        peak_score = max(peak_score, score)
        if detection_time is None and sim_time >= scenario.attack_start and score >= DELTA_THRESH:
            detection_time = sim_time - scenario.attack_start

    return {
        "config": config_name,
        "scenario": scenario_name,
        "rep": rep,
        "seed": seed,
        "detected": detection_time is not None,
        "latency": detection_time,
        "peak_score": peak_score,
    }


def run_fp_ablation(config_name: str, seed: int = 999) -> int:
    """Count FPs over 12h legit-only for this ablation config."""
    gen = TrafficGenerator(seed=seed)
    detector = make_detector(config_name)
    _do_seed_baseline(detector, gen, n_intervals=120)

    fp_count = 0
    last_fp = -200.0
    for step in range(8640):
        sim_time = float(step * 5.0)
        flows = gen.generate_legitimate(n_flows=50, sim_time=sim_time)
        result = detector.step(flows, sim_time=sim_time)
        if result["score"] >= DELTA_THRESH and (sim_time - last_fp) > 120.0:
            fp_count += 1
            last_fp = sim_time
    return fp_count


def run_full_ablation_study():
    configs = ["Full", "NoEWMA", "NoLeaky", "NoWeight", "Single"]
    results = {c: [] for c in configs}

    print("Running ablation study (5 configs x 15 runs each)...")
    print("This will take a while (~15-30 minutes).\n")

    for config_name in configs:
        print(f"\n  Config: SENTINEL_{config_name}")
        for scenario_name in SCENARIOS:
            for rep in range(3):
                r = run_ablation_experiment(config_name, scenario_name, rep)
                results[config_name].append(r)
                status = "DETECTED" if r["detected"] else "MISSED"
                lat = f"{r['latency']:.1f}s" if r["latency"] else "N/A"
                print(f"    {scenario_name} rep{rep + 1}: "
                      f"{status} latency={lat}")

    print("\n" + "=" * 55)
    print("TABLE 8: ABLATION STUDY")
    print("=" * 55)
    print(f"{'Config':<20} {'DR%':>6} {'FP/12h':>8} {'Latency':>10}")
    print("-" * 55)

    for config_name in configs:
        runs = results[config_name]
        dr = sum(1 for r in runs if r["detected"]) / max(len(runs), 1) * 100
        lats = [r["latency"] for r in runs if r["latency"] is not None]
        mean_lat = np.mean(lats) if lats else float("nan")
        print(f"SENTINEL_{config_name:<14} {dr:>5.1f}% {'':>8} {mean_lat:>9.1f}s")
    print("=" * 55)

    return results


if __name__ == "__main__":
    run_full_ablation_study()
