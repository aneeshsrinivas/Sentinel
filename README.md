<div align="center">

# SENTINEL
### A Behavioral DDoS Detection Framework Using Adaptive Baseline Profiling and Multi-Dimensional Temporal Correlation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-29%20passing-brightgreen.svg)](tests/)
[![Journal](https://img.shields.io/badge/journal-Future%20Internet-blue.svg)](https://doi.org/10.5281/zenodo.19132379)

**Aneesh Srinivas · Dr. Madhura K · Dr. Shweta S Aladakatti**

*Department of Computer Science and Engineering*
*Manipal Institute of Technology Bengaluru, Manipal Academy of Higher Education, Manipal, India*

[Quick Start](#quick-start) · [Reproduce Results](#reproducing-paper-results) · [Citation](#citation)

</div>

---

## Abstract

Distributed denial-of-service (DDoS) attacks at the application layer have evolved beyond the reach of conventional volumetric and signature-based defenses, because modern attack tools operate at request rates indistinguishable from organic user behavior when evaluated per individual source. SENTINEL is an inline behavioral detection framework that addresses this gap through three interlocking contributions:

1. **Adaptive baseline profiling** using exponentially weighted moving averages (EWMA) with temporal context-awareness (hour-of-day, day-of-week), capturing diurnal traffic cycles while resisting baseline poisoning
2. **Leaky-accumulator anomaly persistence** that distinguishes sustained attack behavior from transient traffic spikes, requiring anomalies to persist across multiple observation intervals before confirmation
3. **Weighted multi-signal temporal correlation** requiring concurrent deviations across independent behavioral dimensions before triggering mitigation — substantially reducing false positives compared to single-metric detectors

Experimental evaluation across five structurally distinct attack scenarios demonstrates a detection rate of **90.2%** (95% CI: 82.4–98.0%), mean detection latency of **15.5 s**, and a false-positive rate of **0.8 alerts per 12 hours** — 73% lower than single-metric anomaly detectors. SENTINEL requires no pre-labeled training data and produces explainable detection rationales, making it suitable for inline deployment without third-party dependencies.

---

## Key Results

| Scenario | Detection Rate | Latency | F1-Score |
|---|---|---|---|
| HTTP Flood | 95% (87–100%) | 6.2 s ± 1.4 | 0.95 |
| Slowloris | 92% (83–100%) | 12.8 s ± 3.2 | 0.90 |
| Connection Flood | 98% (90–100%) | 4.5 s ± 0.9 | 0.98 |
| Low-Rate Distributed | 78% (67–89%) | 45.3 s ± 12.7 | 0.75 |
| Synchronized Burst | 88% (78–98%) | 8.7 s ± 2.1 | 0.87 |
| **Overall** | **90.2% ± 7.8%** | **15.5 s** | **0.89** |

Graduated mitigation reduced server CPU utilization by **71%** (from 97.8% to 28.4%) under active attack while preserving a **94.1%** legitimate-request success rate.

> **Note on reproducibility:** Results above were obtained on a controlled virtual testbed (4-core VM, Ubuntu 22.04, 1 Gbps interconnect). When you run the evaluation suite, your numbers will differ based on your hardware, OS scheduling, and random seed — this is expected and scientifically correct. The detection *behavior* (score rising gradually, tiers firing in sequence, de-escalation during quiet periods) is deterministic given the same seed.

---

## Why SENTINEL?

Existing approaches to application-layer DDoS detection suffer from one or more of three fundamental limitations:

| Approach | Limitation |
|---|---|
| Signature-based (Snort, Suricata) | Cannot detect syntactically valid HTTP floods; blind to TLS-encrypted attacks |
| Static threshold / rate limiting | Circumvented by distributing traffic across hundreds of sources at individually benign rates |
| ML classifiers (Random Forest, Deep Learning) | Require pre-labeled training data unavailable during zero-day attacks; black-box decisions; poor cross-environment generalization |
| Cloud scrubbing services | Introduce round-trip latency; require routing changes; transfer traffic custody to third parties |

SENTINEL departs from each of these by performing **service-specific behavioral modeling at an inline gateway** with no third-party dependencies, producing **explainable detection rationales**, and using **multi-signal correlation** to suppress false positives.

---

## Architecture
```
Traffic input
(simulation / CIC-DDoS2019 CSV / PCAP / live capture)
                    │
                    ▼
        ┌─────────────────────┐
        │   Packet Capture    │  libpcap / scapy AsyncSniffer
        │   & Flow Aggregator │  5-tuple keyed flow table
        └──────────┬──────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │  Feature Extractor  │  18 behavioral features
        │                     │  (8 per-source, 5 per-dest, 5 global)
        └──────────┬──────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │   Baseline Store    │  EWMA profiling
        │                     │  168 temporal contexts (24h × 7d)
        │                     │  α = 0.3, IQR outlier filtering
        └──────────┬──────────┘
                   │  z-score per feature
                   ▼
        ┌─────────────────────┐
        │  Leaky Accumulator  │  Per-feature persistence tracking
        │                     │  λ = 0.8 decay, θA = 5.0 threshold
        └──────────┬──────────┘
                   │  confirmed anomaly events
                   ▼
        ┌─────────────────────┐
        │  Heuristic Rules    │  4 protocol-semantic categories
        │                     │  Connection exhaustion / Slowloris /
        │                     │  HTTP flood / Distributed coordination
        └──────────┬──────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │ Correlation Engine  │  Weighted sliding window W = 60s
        │                     │  8 anomaly types, δthresh = 0.70
        │                     │  Sequential template boost Δseq = 0.2
        └──────────┬──────────┘
                   │  correlation score S ∈ [0, 1]
                   ▼
        ┌─────────────────────┐
        │ Mitigation Control  │  3-tier graduated response
        │                     │  T1: rate-limit (S ≥ 0.70)
        │                     │  T2: challenge  (S ≥ 0.85)
        │                     │  T3: block      (S ≥ 0.90)
        └─────────────────────┘
```

---

## Detection Algorithm (Algorithm 1)

At each Δt = 5s observation interval:
```
for each feature k:
    z = (x[k] - μ[k]) / max(σ[k], ε)          # z-score vs EWMA baseline
    update baseline with EWMA(α=0.3)
    if |z| > τz:  A[k] = A[k] + (|z| - τz)    # leaky accumulator
    else:         A[k] = λ · A[k]
    if A[k] > θA: enqueue confirmed anomaly

for each heuristic rule r:
    if r.evaluate(flow_table): enqueue anomaly

S = Σ wᵢ · cᵢ  over W=60s window              # weighted correlation
if template matched: S += Δseq
apply mitigation tier based on S
```

---

## Anomaly Signal Weights

| Anomaly Type | Weight | Rationale |
|---|---|---|
| Distributed connection burst | 0.50 | Multi-source synchronization rare under legitimate load |
| Synchronized request timing | 0.40 | Organic traffic timing uncorrelated across sources |
| Incomplete handshake ratio spike | 0.35 | Characteristic of SYN floods |
| Geographic entropy reduction | 0.30 | Botnets often regionally concentrated |
| Session duration anomaly | 0.25 | Slow-rate attacks produce distinctive persistence patterns |
| Per-source request rate spike | 0.20 | High-rate individual clients occur legitimately |
| Protocol compliance violations | 0.15 | Attack toolkits and buggy clients both contribute |
| User-Agent homogeneity | 0.10 | Legitimate automation consistently shows low diversity |

---

## Quick Start

No network card, root access, or hardware required.
```bash
git clone https://github.com/aneeshsrinivas/Sentinel
cd Sentinel
pip install -r requirements.txt
python run_demo.py
```

**Expected output:**
```
[Phase 1] Seeding baselines (120 intervals of normal traffic)...
Baselines initialized.

  Time |   Score | Tier | Top anomaly                      | Action
    0s |  0.0000 | T0   | none                             | Monitoring
   ...
   30s |  0.1500 | T0   | inter_request_timing_variance    | Monitoring << ATTACK
   40s |  0.4168 | T0   | user_agent_homogeneity           | Monitoring << ATTACK
   55s |  0.8128 | T1   | user_agent_homogeneity           | TIER-1: Rate limiting
   60s |  0.9298 | T3   | user_agent_homogeneity           | TIER-3: BLOCKING

Detection latency: 25.0s  [DETECTED]
Peak correlation:  0.9298
```

The score remains at 0.0 during normal traffic, rises gradually after attack injection, and triggers graduated mitigation in sequence — demonstrating the leaky accumulator and multi-signal correlation working as designed.

---

## Running Against Your Own Data

### CIC-DDoS2019 Benchmark Dataset
```bash
# Download from https://www.unb.ca/cic/datasets/ddos-2019.html
# Place CSV files in data/cic_ddos2019/
python run_demo.py --data data/cic_ddos2019/Syn.csv
python evaluation/run_cic_eval.py
```

### PCAP File
```bash
pip install scapy
python run_demo.py --data path/to/capture.pcap
```

### JSON Flow Records
```bash
python run_demo.py --data path/to/flows.json
```

### Live Capture (Linux only, requires root)
```bash
sudo python run_demo.py --live --iface eth0 --ports 80 443
```

### Different Attack Scenarios
```bash
python run_demo.py --scenario slowloris
python run_demo.py --scenario connection_flood
python run_demo.py --scenario low_rate_distributed
python run_demo.py --scenario synchronized_burst
```

### Different Random Seeds
```bash
python run_demo.py --seed 42
python run_demo.py --seed 100
python run_demo.py --seed 999
```
Different seeds produce different detection latencies and peak scores,
demonstrating that results are emergent from the traffic data rather
than hardcoded.

---

## Reproducing Paper Results

### Table 4 — Detection Performance (15 runs, ~15 min)
```bash
python evaluation/run_experiments.py
```
Generates `results/experiment_results.json`, `results/fig5a_detection_rate.png`,
`results/fig5b_detection_latency.png`, `results/fig6_roc_curves.png`.

### Table 8 — Ablation Study
```bash
python evaluation/ablation.py
```
Runs five configurations: Full, NoEWMA, NoLeaky, NoWeight, Single.
Each configuration runs the actual detector with one component disabled.
Results are measured, never hardcoded.

### Comparative Evaluation
```bash
python evaluation/baselines.py
```
Evaluates SENTINEL against Static Threshold, Snort-sim, and
Random Forest on identical synthetic traffic.

### Unit Tests
```bash
python -m pytest tests/test_core.py -v
```
29 tests covering EWMA math, leaky accumulator, correlation engine,
feature extraction, heuristics, mitigation, and end-to-end integration.

### Pre-Release Verification
```bash
python scripts/check_release.py
```
21-point checklist verifying all paper parameters, module structure,
and absence of hardcoded outcome values.

---

## Adding Custom Attack Scenarios

Edit `simulation/scenarios.py` and add an entry to the `SCENARIOS` dictionary:
```python
"my_scenario": {
    "name": "My Custom Attack",
    "duration_steps": 120,       # 120 × 5s = 600s total
    "attack_start_step": 6,      # attack begins at t=30s
    "attack_config": {
        "n_sources": 200,          # number of attack sources
        "rate_per_source": 30.0,   # requests per source per second
        "timing_std": 0.5,         # timing synchronization (lower = tighter)
        "handshake_complete": 0.95,
        "bytes_per_req": 400,
        "ua_homogeneity": 0.7,     # 0=diverse, 1=single user-agent
        "geo_concentration": 0.6,  # 0=global spread, 1=single country
        "rampup_period": 5.0,      # seconds before full intensity
        "conn_duration_mean": 1.5,
        "conn_duration_std": 0.4,
        "subnet_concentration": 30,
    }
}
```
```bash
python run_demo.py --scenario my_scenario
```

The detection outcome — whether SENTINEL triggers, at what latency,
and at what confidence — is determined entirely by how the attack
config parameters interact with the learned baseline. No outcomes
are predetermined.

---

## Key Parameters

All parameters are defined in `sentinel/config.py` and match
the values reported in the paper exactly.

| Symbol | Value | Description |
|---|---|---|
| α | 0.3 | EWMA smoothing coefficient |
| λ | 0.8 | Leaky accumulator decay factor |
| τz | 3.0 | Z-score anomaly threshold |
| θA | 5.0 | Accumulator confirmation threshold |
| W | 60 s | Correlation sliding window duration |
| Δt | 5 s | Observation interval |
| δthresh | 0.70 | Detection trigger threshold |
| Δseq | 0.2 | Sequential template boost |

---

## Project Structure
```
Sentinel/
├── sentinel/                    Core detection engine
│   ├── config.py                All paper parameters
│   ├── feature_extractor.py     18-feature computation from flow dicts
│   ├── baseline/                EWMA baseline store (168 temporal contexts)
│   ├── anomaly/                 Leaky accumulator per feature
│   ├── correlation/             Weighted sliding-window scorer
│   ├── heuristics.py            4 protocol-semantic rule categories
│   ├── mitigation.py            3-tier graduated response with hysteresis
│   ├── detector.py              Main Algorithm 1 detection loop
│   ├── telemetry.py             SQLite WAL-mode persistence
│   └── capture.py               Live packet capture (scapy)
├── simulation/
│   ├── traffic_generator.py     Legitimate + attack traffic generator
│   └── scenarios.py             5 attack scenario configurations
├── data/
│   └── ingest.py                CIC-DDoS2019 CSV / PCAP / JSON loaders
├── evaluation/
│   ├── run_experiments.py       15-run evaluation suite (Table 4)
│   ├── ablation.py              Ablation study (Table 8)
│   ├── run_cic_eval.py          CIC-DDoS2019 benchmark evaluation
│   ├── baselines.py             Comparative system evaluation
│   ├── metrics.py               Detection rate, latency, F1, AUC, bootstrap CI
│   └── plots.py                 Figure 5a, 5b, 6 generation
├── tests/
│   └── test_core.py             29 unit tests
├── scripts/
│   └── check_release.py         21-point pre-release verification
├── run_demo.py                  Main entry point (simulation/data/live modes)
└── requirements.txt             numpy, scipy, scikit-learn, matplotlib,
                                 pandas, PyYAML, scapy
```

---

## Comparison With Existing Systems

| System | Det. Rate | FP Rate | Latency | Explainable | Training | Inline |
|---|---|---|---|---|---|---|
| Said et al. (2023) | 88% | 4.1% | medium | Yes | Yes | Yes |
| Almadhor et al. (2024) | 91% | 3.2% | medium | Yes | Yes | Yes |
| Hernandez et al. (2025) | 96% | 2.1% | high | No | Yes | No |
| Snort + rules | 72% | 8.0% | low | No | No (rules) | Yes |
| Static threshold | 65% | 15% | low | No | No | Yes |
| **SENTINEL (ours)** | **90.2%** | **0.8/12h** | **medium** | **Yes** | **No** | **Yes** |

SENTINEL achieves near state-of-the-art detection accuracy while uniquely combining explainability, zero training requirements, and inline deployment capability. Deep learning approaches (Hernandez et al., 96%) achieve higher detection rates but require labeled training data unavailable during zero-day attacks and cannot be deployed inline due to inference latency.

---

## Ethical Considerations

SENTINEL captures only TCP/IP packet headers and does not store or
inspect payload content, preserving end-user privacy. This design
aligns with the GDPR data minimisation principle (Article 5(1)(c)).

- Flow records are retained for 24 hours before aggregation
- Anomaly events are retained for 90 days for forensic investigation
- Source IP addresses may be pseudonymised using keyed HMAC-SHA256
  with 7-day key rotation for deployments subject to strict privacy requirements
- SENTINEL is intended for deployment on organisation-owned infrastructure
  where network ownership provides legal authority for traffic monitoring
- Deployment for censorship, content filtering, or user activity
  profiling beyond security needs is strongly discouraged

---

## Requirements
```
numpy>=1.24.0
scipy>=1.10.0
scikit-learn>=1.2.0
matplotlib>=3.7.0
PyYAML>=6.0
pandas>=2.0.0
scapy>=2.5.0      # only required for live capture mode
```

## Install with:
```bash
pip install -r requirements.txt
```

---

## Data Availability

The SENTINEL source code, simulation engine, and evaluation scripts are available at:

**DOI: 10.5281/zenodo.19132379**

Archive: [https://zenodo.org/records/19132379](https://zenodo.org/records/19132379)

GitHub: [https://github.com/aneeshsrinivas/Sentinel](https://github.com/aneeshsrinivas/Sentinel)

---

## Citation

If you use SENTINEL in your research, please cite:
```bibtex
@article{aneesh2026sentinel,
  title     = {SENTINEL: A Behavioral {DDoS} Detection Framework Using
               Adaptive Baseline Profiling and Multi-Dimensional
               Temporal Correlation},
  author    = {Srinivas, Aneesh and K, Madhura and Aladakatti, Shweta S},
  journal   = {Future Internet},
  year      = {2026},
  doi       = {10.5281/zenodo.19132379},
  publisher = {MDPI}
}
```

---

## License

| Component | License |
|---|---|
| Source code | [MIT License](LICENSE) |
| Dataset evaluation scripts | CC BY 4.0 (matching CIC-DDoS2019 dataset license) |

---

<div align="center">

*Department of Computer Science and Engineering*
*Manipal Institute of Technology Bengaluru*
*Manipal Academy of Higher Education, Manipal, India*

</div>
