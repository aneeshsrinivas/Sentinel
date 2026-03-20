"""
Evaluates SENTINEL against the CIC-DDoS2019 benchmark dataset.
Download from: https://www.unb.ca/cic/datasets/ddos-2019.html
Place CSV files in data/cic_ddos2019/
"""
import os
import sys
import json

import numpy as np
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.detector import SentinelDetector
from data.ingest import load_cic_ddos2019

CIC_DATA_DIR = Path("data/cic_ddos2019")

CIC_FILES = {
    "DrDoS_DNS.csv": "DNS_Amplification",
    "DrDoS_LDAP.csv": "LDAP_Amplification",
    "DrDoS_MSSQL.csv": "MSSQL_Amplification",
    "DrDoS_NetBIOS.csv": "NetBIOS_Amplification",
    "DrDoS_NTP.csv": "NTP_Amplification",
    "DrDoS_SNMP.csv": "SNMP_Amplification",
    "DrDoS_SSDP.csv": "SSDP_Amplification",
    "DrDoS_UDP.csv": "UDP_Flood",
    "Syn.csv": "SYN_Flood",
    "TFTP.csv": "TFTP_Flood",
    "UDPLag.csv": "UDP_Lag",
}


def evaluate_file(csv_path: Path, attack_type: str) -> dict:
    detector = SentinelDetector(simulation_mode=True)

    print(f"  Seeding from BENIGN rows in {csv_path.name}...")
    windows_seeded = 0

    for window in load_cic_ddos2019(str(csv_path)):
        benign_only = [f for f in window if f.get("response_status") == 200]
        if not benign_only:
            continue
        features = detector.feature_extractor.extract(benign_only)
        hour, dow = 12, 0
        for k, v in features.items():
            detector.baseline.update(k, float(v), hour=hour, day_of_week=dow)
        windows_seeded += 1
        if windows_seeded >= 120:
            break

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    attack_start_window = None
    first_detection_window = None

    window_num = 0
    for window in load_cic_ddos2019(str(csv_path)):
        window_num += 1
        has_attack = any(f.get("response_status") == 0 for f in window)

        if has_attack and attack_start_window is None:
            attack_start_window = window_num

        result = detector.step(window, sim_time=float(window_num * 5.0))
        detected = result["score"] >= 0.70

        if has_attack:
            if detected:
                tp += 1
                if first_detection_window is None:
                    first_detection_window = window_num
            else:
                fn += 1
        else:
            if detected:
                fp += 1
            else:
                tn += 1

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)

    latency_s = None
    if attack_start_window and first_detection_window:
        latency_s = (first_detection_window - attack_start_window) * 5.0

    return {
        "file": csv_path.name,
        "attack_type": attack_type,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "detection_latency_s": latency_s,
        "windows_total": window_num,
    }


def run_cic_evaluation():
    if not CIC_DATA_DIR.exists():
        print(f"ERROR: {CIC_DATA_DIR} not found.")
        print("Download CIC-DDoS2019 from:")
        print("  https://www.unb.ca/cic/datasets/ddos-2019.html")
        print(f"Then place CSV files in: {CIC_DATA_DIR.absolute()}")
        return

    available = [f for f in CIC_FILES if (CIC_DATA_DIR / f).exists()]
    if not available:
        print(f"No CIC-DDoS2019 CSV files found in {CIC_DATA_DIR}")
        return

    print(f"Found {len(available)}/{len(CIC_FILES)} CIC-DDoS2019 files")
    print("=" * 70)

    all_results = []
    for fname in available:
        attack_type = CIC_FILES[fname]
        print(f"\nEvaluating: {fname} ({attack_type})")
        result = evaluate_file(CIC_DATA_DIR / fname, attack_type)
        all_results.append(result)
        print(f"  Precision: {result['precision']:.3f}  "
              f"Recall: {result['recall']:.3f}  "
              f"F1: {result['f1']:.3f}  "
              f"Latency: {result['detection_latency_s']}s")

    print("\n" + "=" * 70)
    print("CIC-DDoS2019 Evaluation Summary")
    print("=" * 70)
    print(f"{'Attack type':<25} {'Precision':>10} {'Recall':>8} {'F1':>6} {'Latency':>10}")
    print("-" * 65)
    for r in all_results:
        lat = f"{r['detection_latency_s']:.1f}s" if r['detection_latency_s'] else "N/A"
        print(f"{r['attack_type']:<25} {r['precision']:>10.3f} "
              f"{r['recall']:>8.3f} {r['f1']:>6.3f} {lat:>10}")

    macro_f1 = float(np.mean([r["f1"] for r in all_results]))
    macro_recall = float(np.mean([r["recall"] for r in all_results]))
    print("-" * 65)
    print(f"{'Macro average':<25} {'':>10} {macro_recall:>8.3f} {macro_f1:>6.3f}")

    os.makedirs("results", exist_ok=True)
    with open("results/cic_ddos2019_results.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nSaved to results/cic_ddos2019_results.json")


if __name__ == "__main__":
    run_cic_evaluation()
