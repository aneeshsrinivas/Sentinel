class LeakyAccumulator:
    def __init__(self, decay_rate=0.8, z_threshold=3.0, alert_threshold=5.0):
        self.decay_rate = decay_rate
        self.z_threshold = z_threshold
        self.alert_threshold = alert_threshold
        self.accumulators = {}
        
    def process_zscore(self, feature_name, z_score):
        if feature_name not in self.accumulators:
            self.accumulators[feature_name] = 0.0
        
        current = self.accumulators[feature_name]
        
        if abs(z_score) > self.z_threshold:
            current += (abs(z_score) - self.z_threshold)
        else:
            current *= self.decay_rate
        
        self.accumulators[feature_name] = current
        
        is_anomalous = current > self.alert_threshold
        return current, is_anomalous
