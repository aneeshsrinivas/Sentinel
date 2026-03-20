import json
import time
import random

def extract_features(pcap_path, output_path):
    print(f"Extracting features from {pcap_path}...")
    
    # Mocking extraction process
    features = [
        {"timestamp": time.time(), "per_source_request_rate_spike": random.uniform(0, 10)},
        {"timestamp": time.time() + 1, "session_duration_anomaly": random.uniform(0, 5)},
    ]
    
    with open(output_path, 'w') as f:
        for feat in features:
            f.write(json.dumps(feat) + "\n")
            
    print(f"Extracted {len(features)} flows to {output_path}")

if __name__ == "__main__":
    extract_features("data/raw_pcaps/sample.pcap", "data/processed_flows/sample_features.json")
