import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.engine import SentinelEngine

print("Initializing Sentinel Engine for HTTP Flood Simulation...")
engine = SentinelEngine(config_dir="configs")

# Mock benign traffic for baseline
print("Generating baseline benign traffic...")
for i in range(10):
    engine.process_features({"per_source_request_rate_spike": 1.0, "geographic_entropy_reduction": 1.0})

# Attack phase
print("Initiating HTTP Flood (50x baseline rate)...")
for i in range(30):
    engine.process_features({"per_source_request_rate_spike": 50.0, "geographic_entropy_reduction": 0.2})
    
print("HTTP Flood Scenario complete.")
