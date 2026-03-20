import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.engine import SentinelEngine

print("Initializing Sentinel Engine for Conn Flood Simulation...")
engine = SentinelEngine(config_dir="configs")

for i in range(10):
    engine.process_features({"distributed_connection_burst": 10.0})

print("Initiating Conn Flood (massive parallel bursts)...")
for i in range(30):
    engine.process_features({"distributed_connection_burst": 5000.0})
    
print("Conn Flood Scenario complete.")
