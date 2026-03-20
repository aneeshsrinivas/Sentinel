"""
SENTINEL Feature Extractor - Computes 18 features from flow dicts for simulation mode.
"""
import math
import numpy as np
from collections import defaultdict
from typing import Dict, List, Any

from .config import OBSERVATION_INTERVAL, WINDOW_SIZE


class FeatureExtractor:
    """Extracts 18 features from a list of flow dictionaries."""

    def __init__(self):
        self._prev_geo_entropy = 0.0

    def extract(self, flows: List[Dict[str, Any]]) -> Dict[str, float]:
        if not flows:
            return self._zero()

        dt = float(OBSERVATION_INTERVAL)
        w = float(WINDOW_SIZE)
        now = max(f.get('last_time', 0) for f in flows) if flows else 0.0

        # Per-source aggregation
        src_info = defaultdict(lambda: {
            'flows': [], 'new': 0, 'concurrent': 0, 'durations': [],
            'handshakes': [], 'requests': 0, 'violations': [],
        })
        for f in flows:
            s = f['src_ip']
            src = src_info[s]
            src['flows'].append(f)
            dur = max(f.get('last_time', 0) - f.get('start_time', 0), 0)
            if f.get('start_time', 0) >= now - dt:
                src['new'] += 1
            if f.get('last_time', 0) >= now - w:
                src['concurrent'] += 1
                src['durations'].append(dur)
            src['handshakes'].append(1 if f.get('handshake_complete') else 0)
            src['requests'] += f.get('request_count', 0)
            src['violations'].append(1 if f.get('protocol_violation') else 0)

        n_srcs = len(src_info)
        total_new = sum(s['new'] for s in src_info.values())
        all_durations = [d for s in src_info.values() for d in s['durations']]
        all_handshakes = [h for s in src_info.values() for h in s['handshakes']]
        total_requests = sum(s['requests'] for s in src_info.values())
        all_violations = [v for s in src_info.values() for v in s['violations']]
        per_src_requests = [s['requests'] for s in src_info.values()]

        new_connection_rate = total_new / dt
        concurrent_connection_count = (sum(s['concurrent'] for s in src_info.values()) / max(n_srcs, 1))
        mean_connection_duration = float(np.mean(all_durations)) if all_durations else 0.0
        variance_connection_duration = float(np.var(all_durations)) if all_durations else 0.0
        handshake_completion_ratio = float(np.mean(all_handshakes)) if all_handshakes else 0.0
        request_rate = total_requests / dt
        inter_request_timing_variance = float(np.var(per_src_requests)) if per_src_requests else 0.0
        protocol_compliance_score = 1.0 - (float(np.mean(all_violations)) if all_violations else 0.0)

        # Per-destination aggregation
        dst_info = defaultdict(lambda: {'requests': 0, 'srcs': set(), 'countries': [], 'errors': 0, 'latencies': []})
        for f in flows:
            d = f['dst_ip']
            di = dst_info[d]
            di['requests'] += f.get('request_count', 0)
            di['srcs'].add(f['src_ip'])
            if f.get('country_code'):
                di['countries'].append(f['country_code'])
            if f.get('response_status', 0) >= 400:
                di['errors'] += 1
            if f.get('handshake_complete'):
                di['latencies'].append(max(f.get('last_time', 0) - f.get('start_time', 0), 0))

        all_requests = sum(d['requests'] for d in dst_info.values())
        unique_srcs = set()
        for d in dst_info.values():
            unique_srcs.update(d['srcs'])
        all_countries = [c for d in dst_info.values() for c in d['countries']]
        all_errors = sum(d['errors'] for d in dst_info.values())
        all_latencies = [l for d in dst_info.values() for l in d['latencies']]

        total_request_rate = all_requests / dt
        unique_source_count = len(unique_srcs)
        geographic_entropy = self._entropy(all_countries)
        backend_error_rate = all_errors / max(all_requests, 1)
        response_latency_mean = float(np.mean(all_latencies)) if all_latencies else 0.0

        # Geo shift
        geo_shift = abs(geographic_entropy - self._prev_geo_entropy)
        self._prev_geo_entropy = geographic_entropy

        # Global features
        source_diversity_per_minute = len(unique_srcs) * (60.0 / dt)

        # Cross-source timing correlation (proxy: CV of per-source request counts)
        if len(per_src_requests) >= 2:
            mn = float(np.mean(per_src_requests))
            std = float(np.std(per_src_requests))
            cross_source_timing_correlation = min(std / max(mn, 1e-9), 1.0)
        else:
            cross_source_timing_correlation = 0.0

        # Protocol frequency ratio
        tcp_count = sum(1 for f in flows if f.get('proto', '').upper() == 'TCP')
        protocol_frequency_ratio = tcp_count / max(len(flows), 1)

        # Payload entropy proxy
        bytes_sent_list = [f.get('bytes_sent', 0) for f in flows]
        payload_entropy_proxy = self._entropy(bytes_sent_list)

        return {
            "new_connection_rate": float(new_connection_rate),
            "concurrent_connection_count": float(concurrent_connection_count),
            "mean_connection_duration": float(mean_connection_duration),
            "variance_connection_duration": float(variance_connection_duration),
            "handshake_completion_ratio": float(handshake_completion_ratio),
            "request_rate": float(request_rate),
            "inter_request_timing_variance": float(inter_request_timing_variance),
            "protocol_compliance_score": float(protocol_compliance_score),
            "total_request_rate": float(total_request_rate),
            "unique_source_count": float(unique_source_count),
            "geographic_entropy": float(geographic_entropy),
            "backend_error_rate": float(backend_error_rate),
            "response_latency_mean": float(response_latency_mean),
            "source_diversity_per_minute": float(source_diversity_per_minute),
            "geo_distribution_shift_rate": float(geo_shift),
            "cross_source_timing_correlation": float(cross_source_timing_correlation),
            "protocol_frequency_ratio": float(protocol_frequency_ratio),
            "payload_entropy_proxy": float(payload_entropy_proxy),
        }

    def _entropy(self, values):
        if not values:
            return 0.0
        vals = [str(v) for v in values]
        _, counts = np.unique(vals, return_counts=True)
        probs = counts / len(vals)
        probs = probs[probs > 0]
        return float(-np.sum(probs * np.log2(probs)))

    def _zero(self):
        return {k: 0.0 for k in [
            "new_connection_rate", "concurrent_connection_count", "mean_connection_duration",
            "variance_connection_duration", "handshake_completion_ratio", "request_rate",
            "inter_request_timing_variance", "protocol_compliance_score", "total_request_rate",
            "unique_source_count", "geographic_entropy", "backend_error_rate",
            "response_latency_mean", "source_diversity_per_minute", "geo_distribution_shift_rate",
            "cross_source_timing_correlation", "protocol_frequency_ratio", "payload_entropy_proxy",
        ]}
