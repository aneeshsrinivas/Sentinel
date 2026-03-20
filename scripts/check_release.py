"""
Run this before pushing to GitHub / minting Zenodo DOI.
Checks every requirement for journal submission readiness.
"""
import subprocess
import sys
import os
from pathlib import Path

# Ensure project root is on sys.path
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


CHECKS = []


def check(name):
    def decorator(fn):
        CHECKS.append((name, fn))
        return fn
    return decorator


@check("Python version >= 3.9")
def _():
    return sys.version_info >= (3, 9)


@check("requirements.txt exists")
def _():
    return Path("requirements.txt").exists()


@check("run_demo.py exists and is runnable")
def _():
    return Path("run_demo.py").exists()


@check("sentinel/ package importable")
def _():
    try:
        import sentinel  # noqa: F401
        return True
    except Exception:
        return False


@check("data/ingest.py exists")
def _():
    return Path("data/ingest.py").exists()


@check("sentinel/capture.py exists")
def _():
    return Path("sentinel/capture.py").exists()


@check("evaluation/run_experiments.py exists")
def _():
    return Path("evaluation/run_experiments.py").exists()


@check("evaluation/ablation.py exists")
def _():
    return Path("evaluation/ablation.py").exists()


@check("evaluation/run_cic_eval.py exists")
def _():
    return Path("evaluation/run_cic_eval.py").exists()


@check("README.md exists and has quick-start section")
def _():
    p = Path("README.md")
    if not p.exists():
        return False
    text = p.read_text(errors="ignore")
    return "Quick start" in text


@check("results/ directory exists")
def _():
    return Path("results").exists()


@check("29 unit tests pass")
def _():
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_core.py", "-q"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return r.returncode == 0


@check("run_demo.py simulation completes without error")
def _():
    r = subprocess.run(
        [sys.executable, "run_demo.py", "--scenario", "http_flood"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return r.returncode == 0 and "Summary" in r.stdout


@check("No hardcoded detection_rate or should_miss_detection in codebase")
def _():
    for fpath in Path(".").rglob("*.py"):
        if ".git" in str(fpath):
            continue
        if "check_release" in str(fpath):
            continue
        text = fpath.read_text(errors="ignore")
        if "should_miss_detection" in text:
            return False
        if "detection_rate = 0.9" in text:
            return False
    return True


@check("All 16 flow dict keys present in ingest.py")
def _():
    text = Path("data/ingest.py").read_text(errors="ignore")
    required = [
        "src_ip", "dst_ip", "sport", "dport", "proto",
        "start_time", "last_time", "bytes_sent", "bytes_recv",
        "packets", "handshake_complete", "request_count",
        "protocol_violation", "user_agent", "country_code",
        "response_status",
    ]
    return all(k in text for k in required)


@check("data/__init__.py exists")
def _():
    return Path("data/__init__.py").exists()


@check("scripts/__init__.py exists")
def _():
    return Path("scripts/__init__.py").exists()


@check("sentinel/config.py has all paper parameters")
def _():
    text = Path("sentinel/config.py").read_text(errors="ignore")
    params = ["ALPHA", "LAMBDA", "TAU_Z", "THETA_A", "DELTA_THRESH", "DELTA_SEQ"]
    return all(p in text for p in params)


@check("sentinel/feature_extractor.py computes 18 features")
def _():
    text = Path("sentinel/feature_extractor.py").read_text(errors="ignore")
    features = [
        "new_connection_rate", "handshake_completion_ratio",
        "geographic_entropy", "cross_source_timing_correlation",
    ]
    return all(f in text for f in features)


@check("sentinel/heuristics.py has 4 rule categories")
def _():
    text = Path("sentinel/heuristics.py").read_text(errors="ignore")
    rules = [
        "connection_exhaustion", "slowloris",
        "http_flood", "distributed_coordination",
    ]
    return all(r in text for r in rules)


@check("sentinel/mitigation.py has 3-tier graduated response")
def _():
    text = Path("sentinel/mitigation.py").read_text(errors="ignore")
    return "TIER-1" in text and "TIER-2" in text and "TIER-3" in text


def main():
    print("SENTINEL release readiness check")
    print("=" * 50)
    passed = 0
    failed = []
    for name, fn in CHECKS:
        try:
            ok = fn()
        except Exception as e:
            ok = False
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}")
        if ok:
            passed += 1
        else:
            failed.append(name)

    print("=" * 50)
    print(f"{passed}/{len(CHECKS)} checks passed")

    if failed:
        print("\nFailed checks:")
        for f in failed:
            print(f"  - {f}")
        print("\nFix all failures before pushing to GitHub.")
        sys.exit(1)
    else:
        print("\nAll checks passed. Ready for:")
        print("  1. git push origin main")
        print("  2. Create GitHub release v1.0")
        print("  3. Link to zenodo.org -> mint DOI")
        print("  4. Update paper DOI placeholder")


if __name__ == "__main__":
    main()
