import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.engine import SentinelEngine

print("Initializing Sentinel Engine for Low-Rate Distributed Simulation...")
engine = SentinelEngine(config_dir="configs")

for i in range(10):
    engine.process_features({"synchronized_request_timing": 0.1, "geographic_entropy_reduction": 1.0})

print("Initiating Low-rate Distributed Attack (stealthy accumulation)...")
for i in range(60):
    # Weak signal taking longer to accumulate
    engine.process_features({"synchronized_request_timing": 0.8, "geographic_entropy_reduction": 0.4})
    
print("Low-rate Distributed Scenario complete.")
