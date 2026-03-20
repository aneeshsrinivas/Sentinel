import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.engine import SentinelEngine

print("Initializing Sentinel Engine for Burst Attack Simulation...")
engine = SentinelEngine(config_dir="configs")

for i in range(10):
    engine.process_features({"synchronized_request_timing": 0.1})

print("Initiating Burst Attack (periodic massive bursts)...")
for i in range(30):
    if i % 5 == 0:
        engine.process_features({"synchronized_request_timing": 50.0})
    else:
        engine.process_features({"synchronized_request_timing": 0.1})
    
print("Burst Attack Scenario complete.")
