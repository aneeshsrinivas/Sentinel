# SENTINEL: Behavioral DDoS Detection Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)

Inline behavioral DDoS detection using adaptive EWMA baseline profiling,
leaky-accumulator persistence tracking, and weighted multi-signal temporal
correlation. No pre-labeled training data required.

Paper: *SENTINEL: A Behavioral DDoS Detection Framework Using Adaptive
Baseline Profiling and Multi-Dimensional Temporal Correlation*
Aneesh Srinivas, Dr. Madhura K, Dr. Shweta S Aladakatti
Manipal Institute of Technology Bengaluru, MAHE

## Quick start (5 minutes, no hardware required)

```bash
git clone https://github.com/aneeshsrinivas/Sentinel
cd Sentinel
pip install -r requirements.txt
python run_demo.py
```

Expected output: 120 timesteps showing score rising from ~0 to >0.70
after attack injection at t=30s, with detection latency ~5-10s.

## Run against your own data

```bash
# CIC-DDoS2019 CSV (download from https://www.unb.ca/cic/datasets/ddos-2019.html)
python run_demo.py --data path/to/DrDoS_DNS.csv

# PCAP file
pip install scapy
python run_demo.py --data path/to/capture.pcap

# Live capture (Linux, requires root)
sudo python run_demo.py --live --iface eth0 --ports 80 443
```

## Reproduce paper results

```bash
# Table 4 + Figures 5a, 5b, 6 (simulation)
python evaluation/run_experiments.py

# Table 8 ablation study
python evaluation/ablation.py

# CIC-DDoS2019 benchmark evaluation
# First: place CSV files in data/cic_ddos2019/
python evaluation/run_cic_eval.py
```

Results are saved to `results/`. Running time: ~15 min on a laptop.

## Architecture

```
Traffic input (simulation / CSV / PCAP / live)
        |
Feature extractor -- 18 behavioral features per 5s window
        |
Baseline store -- EWMA profiling (168 temporal contexts, alpha=0.3)
        |
Leaky accumulator -- persistence tracking per feature (lambda=0.8, thetaA=5.0)
        |
Heuristic rules -- 4 protocol-semantic rule categories
        |
Correlation engine -- weighted sliding window (W=60s, deltathresh=0.70)
        |
Mitigation controller -- 3-tier graduated response
```

## Key parameters (all in `sentinel/config.py`)

| Parameter | Value | Meaning |
|-----------|-------|---------|
| alpha | 0.3 | EWMA smoothing |
| lambda | 0.8 | Accumulator decay |
| tau_z | 3.0 | Z-score anomaly threshold |
| theta_A | 5.0 | Accumulator confirmation threshold |
| W | 60s | Correlation sliding window |
| delta_t | 5s | Observation interval |
| delta_thresh | 0.70 | Detection trigger |

## Adding your own attack scenarios

Edit `simulation/scenarios.py` and add an entry to the `SCENARIOS` dict.
See existing scenarios for the required dataclass fields.

Then run: `python run_demo.py --scenario my_scenario`

## Project structure

```
sentinel/
  config.py               Core parameters
  feature_extractor.py    18-feature computation
  baseline/               EWMA baseline store
  anomaly/                Leaky accumulator
  correlation/            Weighted scoring engine
  heuristics.py           4 rule categories
  mitigation.py           3-tier graduated response
  detector.py             Main Algorithm 1
  telemetry.py            SQLite persistence
  capture.py              Live packet capture
data/
  ingest.py               CIC-DDoS2019 / PCAP / JSON loaders
simulation/
  traffic_generator.py    Synthetic traffic generator
  scenarios.py            Attack scenario definitions
evaluation/
  run_experiments.py      15-run evaluation (Table 4)
  ablation.py             Ablation study (Table 8)
  run_cic_eval.py         CIC-DDoS2019 benchmark
  metrics.py              Metrics computation
  plots.py                Figure generation
tests/
  test_core.py            Unit tests
run_demo.py               Main entry point
scripts/
  check_release.py        Pre-release verification
```

## Citation

```bibtex
@article{srinivas2026sentinel,
  title={SENTINEL: A Behavioral DDoS Detection Framework Using
         Adaptive Baseline Profiling and Multi-Dimensional Temporal Correlation},
  author={Srinivas, Aneesh and K, Madhura and Aladakatti, Shweta S},
  journal={Future Internet},
  year={2026},
  doi={10.3390/fi1010000}
}
```

## License

Source code: MIT License
Dataset scripts: CC BY 4.0 (matching CIC-DDoS2019 dataset license)
