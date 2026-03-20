class EWMABaseline:
    def __init__(self, alpha=0.3):
        self.alpha = alpha
        self.means = {}
        self.variances = {}
        
    def update_and_get_zscore(self, feature_name, value):
        if feature_name not in self.means:
            self.means[feature_name] = value
            self.variances[feature_name] = 0.0
            return 0.0
            
        old_mean = self.means[feature_name]
        new_mean = self.alpha * value + (1 - self.alpha) * old_mean
        
        diff = value - new_mean
        new_var = self.alpha * (diff ** 2) + (1 - self.alpha) * self.variances[feature_name]
        
        self.means[feature_name] = new_mean
        self.variances[feature_name] = new_var
        
        std_dev = new_var ** 0.5
        if std_dev == 0:
            return 0.0
            
        z_score = (value - new_mean) / std_dev
        return z_score
