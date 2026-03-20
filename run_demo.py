#!/usr/bin/env python3
"""
SENTINEL Demo — supports simulation, data file, and live capture modes.

Usage:
  python run_demo.py                          # simulation mode (default)
  python run_demo.py --data path/to/file.csv  # CIC-DDoS2019 CSV
  python run_demo.py --data path/to/file.pcap # PCAP file
  python run_demo.py --data path/to/file.json # JSON flow list
  python run_demo.py --live --iface eth0      # live capture (root required)
"""
import argparse
import sys
import os
import time
import itertools

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def parse_args():
    p = argparse.ArgumentParser(
        description="SENTINEL DDoS Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_demo.py                          # built-in simulation
  python run_demo.py --data traffic.csv       # CIC-DDoS2019 CSV
  python run_demo.py --data capture.pcap      # PCAP file
  python run_demo.py --live --iface eth0      # live (requires root)
        """,
    )
    p.add_argument("--data", type=str, default=None,
                   help="Path to CIC-DDoS2019 CSV, PCAP, or JSON file")
    p.add_argument("--live", action="store_true",
                   help="Live capture mode (requires root + scapy)")
    p.add_argument("--iface", type=str, default="eth0",
                   help="Network interface for live capture")
    p.add_argument("--ports", nargs="+", type=int, default=[80, 443],
                   help="Ports to monitor in live mode")
    p.add_argument("--seed", type=int, default=42,
                   help="Random seed for simulation mode")
    p.add_argument("--scenario", type=str, default="http_flood",
                   choices=["http_flood", "slowloris", "connection_flood",
                            "low_rate_distributed", "synchronized_burst"],
                   help="Attack scenario for simulation mode")
    return p.parse_args()


def run_simulation_mode(args):
    """Simulation mode — works with no hardware required."""
    from sentinel.detector import SentinelDetector
    from sentinel.config import OBSERVATION_INTERVAL, DELTA_THRESH
    from simulation.traffic_generator import TrafficGenerator
    from simulation.scenarios import SCENARIOS

    print("=" * 70)
    print("SENTINEL Demo — simulation mode (no hardware required)")
    print(f"Scenario: {args.scenario}  |  Seed: {args.seed}")
    print("=" * 70)

    detector = SentinelDetector(simulation_mode=True)
    gen = TrafficGenerator(seed=args.seed)
    scenario = SCENARIOS[args.scenario]

    print("\n[Phase 1] Seeding baselines (120 intervals of normal traffic)...")
    detector.seed_baseline(n_intervals=120)
    print("Baselines initialized.\n")

    attack_start = scenario.attack_start
    cfg = {
        "type": scenario.id,
        "attack_start": attack_start,
        **scenario.generator_kwargs,
    }

    print(f"[Phase 2] Running scenario (attack starts at t={attack_start:.0f}s)\n")
    print(f"{'Time':>6} | {'Score':>7} | {'Tier':>4} | {'Top anomaly':<32} | Action")
    print("-" * 95)

    peak_score = 0.0
    all_results = []
    detection_time = None
    n_steps = min(int(scenario.duration / OBSERVATION_INTERVAL), 120)

    for step in range(n_steps):
        sim_time = float(step * OBSERVATION_INTERVAL)

        legit = gen.generate_legitimate(n_flows=50, sim_time=sim_time)
        if sim_time >= attack_start:
            attack = gen.generate_attack(cfg, sim_time=sim_time)
        else:
            attack = []

        result = detector.step(legit + attack, sim_time=sim_time)
        result["sim_time"] = sim_time
        all_results.append(result)
        score = result["score"]
        peak_score = max(peak_score, score)

        if detection_time is None and sim_time >= attack_start and score >= DELTA_THRESH:
            detection_time = sim_time - attack_start

        marker = " << ATTACK" if sim_time >= attack_start else ""
        top = (result.get("top_anomaly") or "none")[:32]
        action = (result.get("action_description") or "")[:25]
        print(f"{sim_time:>5.0f}s | {score:>7.4f} | T{result['tier']:>1d}   "
              f"| {top:<32} | {action}{marker}")
        time.sleep(0.02)

    attack_scores = [r["score"] for r in all_results
                     if r.get("sim_time", 0) >= attack_start]

    print("\n" + "=" * 70)
    print("SENTINEL Demo Summary")
    print("=" * 70)
    print(f"Attack started:        t={attack_start:.0f}s")
    if detection_time is not None:
        print(f"Detection latency:     {detection_time:.1f}s  [DETECTED]")
    else:
        print(f"Detection latency:     not detected within window")
    print(f"Peak correlation:      {peak_score:.4f}")
    if attack_scores:
        print(f"Score range (attack):  {min(attack_scores):.3f} — {max(attack_scores):.3f}")
    final_tier = all_results[-1]["tier"] if all_results else 0
    print(f"Final mitigation tier: {final_tier}")
    print("=" * 70)


def run_data_mode(args):
    """Run detector against a CSV, PCAP, or JSON file."""
    from sentinel.detector import SentinelDetector
    from sentinel.config import OBSERVATION_INTERVAL
    from data.ingest import load_cic_ddos2019, load_pcap, load_json_flows

    path = args.data
    ext = path.rsplit(".", 1)[-1].lower()

    print("=" * 70)
    print(f"SENTINEL — file mode: {path}")
    print("=" * 70)

    detector = SentinelDetector(simulation_mode=True)

    if ext == "csv":
        loader = load_cic_ddos2019(path)
        print("Format: CIC-DDoS2019 CSV")
    elif ext in ("pcap", "pcapng", "cap"):
        loader = load_pcap(path)
        print("Format: PCAP")
    elif ext == "json":
        loader = load_json_flows(path)
        print("Format: JSON flow list")
    else:
        print(f"Unknown file extension: .{ext}")
        print("Supported: .csv (CIC-DDoS2019), .pcap, .pcapng, .json")
        sys.exit(1)

    # Seed baseline from first 120 windows
    print("\n[Phase 1] Seeding baseline from first 120 traffic windows...")
    windows_seeded = 0
    seeding_buffer = []

    for window in loader:
        if windows_seeded < 120:
            features = detector.feature_extractor.extract(window)
            hour, dow = 12, 0
            for k, v in features.items():
                detector.baseline.update(k, float(v), hour=hour, day_of_week=dow)
            windows_seeded += 1
            seeding_buffer.append(window)
            if windows_seeded % 20 == 0:
                print(f"  Seeded {windows_seeded}/120 windows...")
        else:
            seeding_buffer.append(window)
            break

    if windows_seeded < 120:
        print(f"Warning: only {windows_seeded} windows available for seeding.")

    print(f"Baseline seeded from {windows_seeded} windows.\n")
    print("[Phase 2] Running detection on remaining traffic...\n")
    print(f"{'Window':>8} | {'Flows':>6} | {'Score':>7} | {'Tier':>4} | Top anomaly")
    print("-" * 75)

    peak_score = 0.0
    alerts = 0
    window_num = 0

    remaining = seeding_buffer[120:] if len(seeding_buffer) > 120 else []

    for window in itertools.chain(remaining, loader):
        window_num += 1
        result = detector.step(window, sim_time=float(window_num * OBSERVATION_INTERVAL))
        score = result["score"]
        peak_score = max(peak_score, score)

        if score >= 0.70:
            alerts += 1

        top = (result.get("top_anomaly") or "none")[:30]
        tier = result.get("tier", 0)
        print(f"{window_num:>7d}  | {len(window):>6d} | {score:>7.4f} | T{tier:>1d}   | {top}")

        if window_num % 100 == 0:
            print(f"  --- processed {window_num} windows, {alerts} alerts so far ---")

    print("\n" + "=" * 70)
    print("Results")
    print("=" * 70)
    print(f"Windows processed:     {window_num}")
    print(f"Alerts fired:          {alerts}")
    print(f"Peak correlation:      {peak_score:.4f}")
    print(f"Alert rate:            {alerts / max(window_num, 1) * 100:.2f}% of windows")
    print("=" * 70)


def run_live_mode(args):
    """Live capture mode. Requires root and scapy."""
    from sentinel.detector import SentinelDetector
    from sentinel.capture import LiveCapture
    from sentinel.config import OBSERVATION_INTERVAL

    print("=" * 70)
    print(f"SENTINEL — live capture on {args.iface}:{args.ports}")
    print("Requires root / CAP_NET_RAW. Press Ctrl+C to stop.")
    print("=" * 70)

    detector = SentinelDetector(simulation_mode=False)

    try:
        cap = LiveCapture(interface=args.iface, ports=args.ports)
    except ImportError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print("\n[Phase 1] Seeding baseline (120 intervals = 10 minutes)...")
    cap.start()
    for i in range(120):
        time.sleep(OBSERVATION_INTERVAL)
        batch = cap.get_batch()
        features = detector.feature_extractor.extract(batch)
        hour, dow = 12, 0
        for k, v in features.items():
            detector.baseline.update(k, float(v), hour=hour, day_of_week=dow)
        print(f"  Seeded interval {i + 1}/120 ({len(batch)} flows)")
    print("Baseline ready. Starting detection...\n")

    print(f"{'Time':>8} | {'Flows':>6} | {'Score':>7} | {'Tier':>4} | Action")
    print("-" * 65)

    start_wall = time.time()
    try:
        while True:
            time.sleep(OBSERVATION_INTERVAL)
            batch = cap.get_batch()
            sim_time = time.time() - start_wall
            result = detector.step(batch, sim_time=sim_time)
            score = result["score"]
            action = (result.get("action_description") or "monitoring")[:28]
            print(f"{sim_time:>7.0f}s | {len(batch):>6d} | {score:>7.4f} | "
                  f"T{result['tier']:>1d}   | {action}")
    except KeyboardInterrupt:
        print("\nStopping capture...")
        cap.stop()


def main():
    args = parse_args()
    if args.live:
        run_live_mode(args)
    elif args.data:
        run_data_mode(args)
    else:
        run_simulation_mode(args)


if __name__ == "__main__":
    main()
