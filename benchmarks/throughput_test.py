import time
import os
import sys

# Add parent dir to path to import sentinel
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel.engine import SentinelEngine  # type: ignore

def run_benchmark(num_packets=100000):
    print(f"Initializing Sentinel engine for {num_packets} packets...")
    engine = SentinelEngine(config_dir="configs")
    
    # Pre-generate 100 random feature dicts to reduce overhead of generation during timing
    import random
    features = [{"per_source_request_rate_spike": random.random() * 10} for _ in range(100)]
    
    print("Starting benchmark...")
    start_time = time.time()
    
    for i in range(num_packets):
        # Mute stdout internally to prevent massive logging during benchmark
        import io
        import sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            engine.process_features(features[i % 100], timestamp=start_time + (i * 0.001))
        finally:
            sys.stdout = old_stdout
            
    end_time = time.time()
    duration = end_time - start_time
    pps = num_packets / duration
    
    print(f"Processed {num_packets} packets in {duration:.2f} seconds.")
    print(f"Throughput: {pps:.2f} packets/second.")

if __name__ == "__main__":
    run_benchmark()
