import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.engine import SentinelEngine

print("Initializing Sentinel Engine for Slowloris Simulation...")
engine = SentinelEngine(config_dir="configs")

for i in range(10):
    engine.process_features({"session_duration_anomaly": 1.0, "incomplete_handshake_ratio_spike": 0.0})

print("Initiating Slowloris (long session durations)...")
for i in range(30):
    engine.process_features({"session_duration_anomaly": 45.0, "incomplete_handshake_ratio_spike": 0.1})
    
print("Slowloris Scenario complete.")
