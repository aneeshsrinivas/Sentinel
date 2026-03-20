"""
SENTINEL Evaluation Metrics Module

Computes detection rate, latency, false positives, F1, AUC, and bootstrap CIs.

Reference: Section 5.3 in "SENTINEL: A Behavioral DDoS Detection Framework"
"""

import math
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict


def compute_detection_rate(results: List[Dict]) -> float:
    """Compute detection rate: fraction of runs where attack was detected."""
    if not results:
        return 0.0
    detected = sum(1 for r in results if r.get('detected', False))
    return detected / len(results)


def compute_detection_latency(results: List[Dict]) -> Dict[str, float]:
    """Compute detection latency statistics."""
    latencies = [r.get('latency') for r in results 
                 if r.get('latency') is not None]
    
    if not latencies:
        return {'mean': 0.0, 'std': 0.0, 'min': 0.0, 'max': 0.0, 'median': 0.0}
    
    return {
        'mean': np.mean(latencies),
        'std': np.std(latencies),
        'min': np.min(latencies),
        'max': np.max(latencies),
        'median': np.median(latencies),
        'p95': np.percentile(latencies, 95),
        'p99': np.percentile(latencies, 99),
    }


def compute_false_positive_rate(results: List[Dict], window_hours: float = 12.0) -> float:
    """Compute false positives per monitoring window."""
    if not results:
        return 0.0
    
    total_fp = sum(r.get('false_positives', 0) for r in results)
    total_duration = sum(r.get('duration', 0) for r in results)
    
    if total_duration == 0:
        return 0.0
    
    fp_per_hour = total_fp / (total_duration / 3600)
    return fp_per_hour * window_hours


def compute_precision_recall(results: List[Dict]) -> Dict[str, float]:
    """Compute precision, recall, and F1 score."""
    total_tp = sum(r.get('true_positives', 0) for r in results)
    total_fp = sum(r.get('false_positives', 0) for r in results)
    total_tn = sum(r.get('true_negatives', 0) for r in results)
    total_fn = sum(r.get('false_negatives', 0) for r in results)
    
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    specificity = total_tn / (total_tn + total_fp) if (total_tn + total_fp) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        'precision': precision,
        'recall': recall,
        'specificity': specificity,
        'f1': f1,
        'tp': total_tp,
        'fp': total_fp,
        'tn': total_tn,
        'fn': total_fn,
    }


def compute_roc_points(
    results: List[Dict],
    thresholds: Optional[List[float]] = None
) -> Tuple[List[float], List[float]]:
    """
    Compute ROC curve points by varying detection threshold.
    
    Returns (false_positive_rates, true_positive_rates) at each threshold.
    """
    if thresholds is None:
        thresholds = [i / 100.0 for i in range(50, 100)]
    
    scores = [r.get('peak_score', 0) for r in results]
    actual_positives = [1 if r.get('detected') else 0 for r in results]
    
    if not scores or not actual_positives:
        return ([0.0], [0.0])
    
    fprs = []
    tprs = []
    
    for thresh in thresholds:
        predicted_positives = sum(1 for s in scores if s >= thresh)
        actual_pos = sum(actual_positives)
        actual_neg = len(actual_positives) - actual_pos
        
        tp = sum(1 for s, a in zip(scores, actual_positives) if s >= thresh and a == 1)
        fp = sum(1 for s, a in zip(scores, actual_positives) if s >= thresh and a == 0)
        
        tpr = tp / actual_pos if actual_pos > 0 else 0.0
        fpr = fp / actual_neg if actual_neg > 0 else 0.0
        
        fprs.append(fpr)
        tprs.append(tpr)
    
    return (fprs, tprs)


def compute_auc(fprs: List[float], tprs: List[float]) -> float:
    """Compute Area Under ROC Curve using trapezoidal rule."""
    if len(fprs) < 2 or len(tprs) < 2:
        return 0.0
    
    auc = 0.0
    for i in range(len(fprs) - 1):
        width = fprs[i + 1] - fprs[i]
        height = (tprs[i] + tprs[i + 1]) / 2
        auc += width * height
    
    return max(0.0, min(1.0, auc))


def compute_bootstrap_ci(
    values: List[float],
    n_iterations: int = 10000,
    ci: float = 0.95
) -> Tuple[float, float]:
    """
    Compute bootstrap confidence interval for a metric.
    
    Reference: Section 5.3 in the paper.
    """
    if len(values) < 2:
        return (values[0] if values else 0.0, values[0] if values else 0.0)
    
    bootstrap_means = []
    n = len(values)
    
    for _ in range(n_iterations):
        sample = np.random.choice(values, size=n, replace=True)
        bootstrap_means.append(np.mean(sample))
    
    alpha = (1 - ci) / 2
    lower = np.percentile(bootstrap_means, alpha * 100)
    upper = np.percentile(bootstrap_means, (1 - alpha) * 100)
    
    return (lower, upper)


def compute_mitigation_effectiveness(
    mitigated_results: List[Dict],
    unmitigated_results: List[Dict]
) -> float:
    """
    Compute mitigation effectiveness as % reduction in server CPU proxy.
    
    Assumes peak_score correlates with server load.
    """
    if not mitigated_results or not unmitigated_results:
        return 0.0
    
    mitigated_score = np.mean([r.get('peak_score', 0) for r in mitigated_results])
    unmitigated_score = np.mean([r.get('peak_score', 0) for r in unmitigated_results])
    
    if unmitigated_score == 0:
        return 0.0
    
    reduction = (unmitigated_score - mitigated_score) / unmitigated_score
    return max(0.0, min(1.0, reduction)) * 100


class MetricsComputer:
    """
    Computes all evaluation metrics from test results.
    """
    
    def __init__(self, bootstrap_iterations: int = 10000, ci: float = 0.95):
        self.bootstrap_iterations = bootstrap_iterations
        self.ci = ci
    
    def compute_all(
        self,
        results: List[Dict],
        scenario_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Compute all metrics for a set of results.
        
        Returns comprehensive metrics dictionary.
        """
        filtered_results = results
        if scenario_id:
            filtered_results = [r for r in results if r.get('scenario_id') == scenario_id]
        
        if not filtered_results:
            return {}
        
        detection_rate = compute_detection_rate(filtered_results)
        latency_stats = compute_detection_latency(filtered_results)
        fp_rate = compute_false_positive_rate(filtered_results)
        pr_stats = compute_precision_recall(filtered_results)
        
        fprs, tprs = compute_roc_points(filtered_results)
        auc = compute_auc(fprs, tprs)
        
        latencies = [r.get('latency') for r in filtered_results 
                     if r.get('latency') is not None]
        if latencies:
            latency_ci = compute_bootstrap_ci(latencies, self.bootstrap_iterations, self.ci)
        else:
            latency_ci = (0.0, 0.0)
        
        detection_rates = [1.0 if r.get('detected') else 0.0 for r in filtered_results]
        detection_ci = compute_bootstrap_ci(detection_rates, self.bootstrap_iterations, self.ci)
        
        return {
            'detection_rate': detection_rate,
            'detection_rate_ci': detection_ci,
            'latency': latency_stats,
            'latency_ci': latency_ci,
            'false_positives_per_12h': fp_rate,
            'precision': pr_stats['precision'],
            'recall': pr_stats['recall'],
            'specificity': pr_stats['specificity'],
            'f1': pr_stats['f1'],
            'auc': auc,
            'peak_scores': [r.get('peak_score', 0) for r in filtered_results],
            'avg_peak_score': np.mean([r.get('peak_score', 0) for r in filtered_results]),
            'total_tp': pr_stats['tp'],
            'total_fp': pr_stats['fp'],
            'total_tn': pr_stats['tn'],
            'total_fn': pr_stats['fn'],
        }
    
    def compute_by_scenario(
        self,
        results: List[Dict]
    ) -> Dict[str, Dict[str, Any]]:
        """Compute metrics for each scenario separately."""
        scenarios = set(r.get('scenario_id') for r in results)
        
        return {
            scenario_id: self.compute_all(results, scenario_id)
            for scenario_id in scenarios
        }
    
    def compute_ablation_results(
        self,
        full_results: List[Dict],
        ablation_results: Dict[str, List[Dict]]
    ) -> Dict[str, Any]:
        """Compare ablation configurations against full system."""
        full_metrics = self.compute_all(full_results)
        
        ablation_comparison = {}
        for config_name, config_results in ablation_results.items():
            config_metrics = self.compute_all(config_results)
            
            ablation_comparison[config_name] = {
                'detection_rate': config_metrics.get('detection_rate', 0),
                'detection_rate_delta': (
                    config_metrics.get('detection_rate', 0) - full_metrics.get('detection_rate', 0)
                ),
                'f1': config_metrics.get('f1', 0),
                'f1_delta': (
                    config_metrics.get('f1', 0) - full_metrics.get('f1', 0)
                ),
                'auc': config_metrics.get('auc', 0),
            }
        
        return ablation_comparison
    
    def format_metrics_table(self, metrics: Dict[str, Any]) -> str:
        """Format metrics as a readable table."""
        lines = []
        lines.append("=" * 60)
        lines.append("SENTINEL Evaluation Metrics")
        lines.append("=" * 60)
        lines.append(f"Detection Rate:       {metrics.get('detection_rate', 0):.3f}")
        
        dr_ci = metrics.get('detection_rate_ci', (0, 0))
        lines.append(f"Detection Rate 95% CI: [{dr_ci[0]:.3f}, {dr_ci[1]:.3f}]")
        
        latency = metrics.get('latency', {})
        lines.append(f"Mean Latency:         {latency.get('mean', 0):.2f}s")
        lines.append(f"Latency Std Dev:      {latency.get('std', 0):.2f}s")
        
        lat_ci = metrics.get('latency_ci', (0, 0))
        lines.append(f"Latency 95% CI:       [{lat_ci[0]:.2f}, {lat_ci[1]:.2f}]s")
        
        lines.append(f"False Positives/12h:  {metrics.get('false_positives_per_12h', 0):.1f}")
        lines.append(f"Precision:             {metrics.get('precision', 0):.3f}")
        lines.append(f"Recall:               {metrics.get('recall', 0):.3f}")
        lines.append(f"Specificity:           {metrics.get('specificity', 0):.3f}")
        lines.append(f"F1 Score:             {metrics.get('f1', 0):.3f}")
        lines.append(f"AUC:                  {metrics.get('auc', 0):.3f}")
        lines.append("=" * 60)
        
        return "\n".join(lines)
