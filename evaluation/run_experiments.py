#!/usr/bin/env python3
"""
SENTINEL Experiments Runner — Runs all 15 test runs (5 scenarios x 3 reps).
Produces Table 4 matching the paper, with 95% bootstrap CIs.
"""
import sys
import os
import json
import time as time_module
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.detector import SentinelDetector, FEATURE_NAMES
from sentinel.config import OBSERVATION_INTERVAL, DELTA_THRESH
from sentinel.baseline import BaselineStats
from simulation.traffic_generator import TrafficGenerator
from simulation.scenarios import SCENARIOS


def _seed_detector_baseline(detector, gen, n_intervals=120):
    """Seed baseline from synthetic legitimate traffic."""
    rng = np.random.default_rng(42)
    feature_values = {fname: [] for fname in FEATURE_NAMES}

    for i in range(n_intervals):
        sim_time = float(i * OBSERVATION_INTERVAL)
        n_flows = max(10, int(rng.normal(50, 10)))
        flows = gen.generate_legitimate(n_flows=n_flows, sim_time=sim_time)
        features = detector.feature_extractor.extract(flows)
        gen.update_legit_profile(features)
        for fname in FEATURE_NAMES:
            feature_values[fname].append(features.get(fname, 0.0))

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


def run_single_scenario(scenario_name: str, rep_idx: int, seed: int) -> dict:
    """Run one scenario and return per-run results."""
    scenario = SCENARIOS[scenario_name]
    duration = scenario.duration
    attack_start_time = scenario.attack_start
    cfg = {
        "type": scenario.id,
        "attack_start": attack_start_time,
        **scenario.generator_kwargs,
    }

    gen = TrafficGenerator(seed=seed + rep_idx * 3)
    detector = SentinelDetector(simulation_mode=True)
    _seed_detector_baseline(detector, gen, n_intervals=120)

    detection_time = None
    peak_score = 0.0
    score_series = []

    n_steps = int(duration / OBSERVATION_INTERVAL)
    for step_idx in range(n_steps):
        sim_time = float(step_idx * OBSERVATION_INTERVAL)

        legit_flows = gen.generate_legitimate(n_flows=50, sim_time=sim_time)

        if sim_time >= attack_start_time:
            attack_flows = gen.generate_attack(cfg, sim_time=sim_time)
        else:
            attack_flows = []

        combined = legit_flows + attack_flows
        result = detector.step(combined, sim_time=sim_time)

        score = result["score"]
        score_series.append({"time": sim_time, "score": score})
        peak_score = max(peak_score, score)

        if detection_time is None and sim_time >= attack_start_time and score >= DELTA_THRESH:
            detection_time = sim_time - attack_start_time

    detected = detection_time is not None

    return {
        "scenario": scenario_name,
        "scenario_id": scenario_name,
        "rep": rep_idx,
        "seed": seed,
        "detected": detected,
        "detection_latency": detection_time,
        "latency": detection_time,
        "peak_score": peak_score,
        "score_series": score_series,
        "is_attack": True,
    }


def run_fp_evaluation(seed: int = 999) -> dict:
    """Run 12-hour legitimate-only window and count false positives."""
    gen = TrafficGenerator(seed=seed)
    detector = SentinelDetector(simulation_mode=True)
    _seed_detector_baseline(detector, gen, n_intervals=120)

    fp_count = 0
    last_fp_time = -200.0

    # 12 hours = 8640 steps x 5s
    for step in range(8640):
        sim_time = float(step * OBSERVATION_INTERVAL)
        flows = gen.generate_legitimate(n_flows=50, sim_time=sim_time)
        result = detector.step(flows, sim_time=sim_time)

        if result["score"] >= DELTA_THRESH and (sim_time - last_fp_time) > 120.0:
            fp_count += 1
            last_fp_time = sim_time

    return {"fp_count": fp_count}


def run_all_experiments(reps: int = 3):
    """Run all 15 attack experiments plus FP evaluation."""
    results = []
    total = len(SCENARIOS) * reps
    count = 0

    scenario_order = [
        "http_flood", "slowloris", "connection_flood",
        "low_rate_distributed", "synchronized_burst",
    ]

    for scenario_name in scenario_order:
        for rep in range(reps):
            count += 1
            seed = 42 + rep * 100
            print(f"  [{count}/{total}] {scenario_name} (rep {rep + 1})...",
                  end=" ", flush=True)
            t0 = time_module.time()
            r = run_single_scenario(scenario_name, rep, seed)
            elapsed = time_module.time() - t0
            status = "DETECTED" if r["detected"] else "MISSED"
            lat = f"{r['detection_latency']:.1f}s" if r['detection_latency'] is not None else "N/A"
            print(f"{status} latency={lat} peak={r['peak_score']:.4f} ({elapsed:.1f}s)")
            results.append(r)

    print("\n  Running 12-hour false positive evaluation...")
    fp_results = run_fp_evaluation(seed=999)
    print(f"  FP in 12h: {fp_results['fp_count']}")

    return results, fp_results


def compute_and_print_table4(results, fp_results=None):
    """Print Table 4 matching paper format with bootstrap CIs."""
    print("\n" + "=" * 72)
    print("TABLE 4 — Detection Performance (compare against paper)")
    print("=" * 72)
    print(f"{'Scenario':<26} {'DR':>5} {'Latency':>9} {'95% CI':>12} {'F1':>6} {'FP':>5}")
    print("-" * 72)

    scenario_order = [
        "http_flood", "slowloris", "connection_flood",
        "low_rate_distributed", "synchronized_burst",
    ]

    all_detected = []
    all_latencies = []

    for scenario_name in scenario_order:
        runs = [r for r in results if r.get("scenario", r.get("scenario_id")) == scenario_name]
        if not runs:
            continue

        detected = [r for r in runs if r["detected"]]
        dr = len(detected) / len(runs) * 100
        latencies = [r["detection_latency"] for r in detected
                     if r["detection_latency"] is not None]
        mean_lat = float(np.mean(latencies)) if latencies else float("nan")

        # Bootstrap 95% CI on detection rate
        rng = np.random.default_rng(42)
        boot_drs = []
        for _ in range(10000):
            sample = rng.choice([r["detected"] for r in runs],
                                size=len(runs), replace=True)
            boot_drs.append(float(np.mean(sample)) * 100)
        ci_lo, ci_hi = float(np.percentile(boot_drs, [2.5, 97.5])[0]), \
                       float(np.percentile(boot_drs, [2.5, 97.5])[1])

        # F1 score
        tp = len(detected)
        fn = len(runs) - tp
        precision = tp / max(tp, 1)  # no FP in attack-only runs
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)

        # Aggregate FP across reps
        fp_count = sum(r.get("fp_count", 0) for r in runs)

        all_detected.extend([r["detected"] for r in runs])
        all_latencies.extend(latencies)

        print(f"{scenario_name:<26} {dr:>4.0f}% {mean_lat:>7.1f}s "
              f"  ({ci_lo:.0f}-{ci_hi:.0f}%) {f1:>6.2f} {fp_count:>5}")

    print("-" * 72)
    overall_dr = sum(all_detected) / max(len(all_detected), 1) * 100
    overall_lat = float(np.mean(all_latencies)) if all_latencies else float("nan")
    print(f"{'Overall':<26} {overall_dr:>4.1f}% {overall_lat:>7.1f}s")
    print("=" * 72)

    print("\nPaper target values for comparison:")
    print("  HTTP Flood:          DR=95%   Latency=6.2s")
    print("  Slowloris:           DR=92%   Latency=12.8s")
    print("  Connection Flood:    DR=98%   Latency=4.5s")
    print("  Low-Rate Distr.:     DR=78%   Latency=45.3s")
    print("  Synchronized Burst:  DR=88%   Latency=8.7s")
    print("  Overall:             DR=90.2% Latency=15.5s")
    print("=" * 72)


def main():
    os.makedirs("results", exist_ok=True)

    print("=" * 70)
    print("SENTINEL Evaluation Suite")
    print("=" * 70)
    print("Running 15 attack experiments (5 scenarios x 3 repetitions)...")
    print("Expected runtime: 10-20 minutes on a laptop.\n")

    results, fp_results = run_all_experiments()

    compute_and_print_table4(results, fp_results)

    # Save raw results
    with open("results/experiment_results.json", "w") as f:
        serialisable = []
        for r in results:
            sr = {k: v for k, v in r.items() if k != "score_series"}
            sr["score_series_length"] = len(r.get("score_series", []))
            serialisable.append(sr)
        json.dump(serialisable, f, indent=2, default=str)
    print("\nRaw results saved to results/experiment_results.json")

    # Generate plots
    try:
        from evaluation.plots import generate_all_plots
        generate_all_plots(results, "results")
        print("Plots saved to results/")
    except Exception as e:
        print(f"Plot generation failed (non-critical): {e}")


if __name__ == "__main__":
    main()
