"""
SENTINEL Heuristic Engine - Rule-based anomaly detection.
"""
import time
from collections import defaultdict
from typing import Dict, List
import math

from .config import (
    CONNECTION_EXHAUSTION_THRESHOLD, INCOMPLETE_HANDSHAKE_THRESHOLD,
    SLOWLORIS_CONCURRENT_THRESHOLD, SLOWLORIS_BYTES_THRESHOLD,
    HTTP_FLOOD_MULTIPLIER, UA_DIVERSITY_THRESHOLD, UA_MIN_REQUESTS,
    DISTRIBUTED_SOURCE_THRESHOLD, DISTRIBUTED_WINDOW,
    CROSS_CORRELATION_THRESHOLD, OBSERVATION_INTERVAL,
)


class AnomalyEvent:
    """Anomaly event emitted by heuristic rules."""
    __slots__ = ('feature_id', 'confidence', 'timestamp')

    def __init__(self, feature_id: str, confidence: float, timestamp: float):
        self.feature_id = feature_id
        self.confidence = confidence
        self.timestamp = timestamp

    def to_dict(self):
        return {"feature_id": self.feature_id, "confidence": self.confidence, "timestamp": self.timestamp}


class HeuristicEngine:
    """Evaluates 4 heuristic rule categories against flow lists."""

    def __init__(self):
        self._baseline_request_rate = 50.0
        self._baseline_alpha = 0.1

    def evaluate(self, flows: List[Dict]) -> List[AnomalyEvent]:
        events = []
        ts = time.time()

        events.extend(self._rule_connection_exhaustion(flows, ts))
        events.extend(self._rule_slowloris(flows, ts))
        events.extend(self._rule_http_flood(flows, ts))
        events.extend(self._rule_distributed_coordination(flows, ts))
        return events

    def _rule_connection_exhaustion(self, flows, ts):
        events = []
        by_src = defaultdict(list)
        by_subnet24 = defaultdict(int)
        for f in flows:
            by_src[f['src_ip']].append(f)
            if not f.get('handshake_complete'):
                subnet24 = '.'.join(f['src_ip'].split('.')[:3])
                by_subnet24[subnet24] += 1

        for src_ip, src_flows in by_src.items():
            concurrent = sum(1 for f in src_flows if not f.get('handshake_complete'))
            if concurrent > CONNECTION_EXHAUSTION_THRESHOLD:
                events.append(AnomalyEvent("incomplete_handshake_spike", 1.0, ts))
                return events

        for subnet, count in by_subnet24.items():
            if count > INCOMPLETE_HANDSHAKE_THRESHOLD:
                events.append(AnomalyEvent("incomplete_handshake_spike", 1.0, ts))
                return events
        return events

    def _rule_slowloris(self, flows, ts):
        events = []
        slow_count = 0
        tiny_count = 0
        for f in flows:
            dur = max(f.get('last_time', 0) - f.get('start_time', 0), 0)
            if dur > 10 and f.get('bytes_sent', 0) < SLOWLORIS_BYTES_THRESHOLD:
                slow_count += 1
            if dur > 5 and f.get('bytes_sent', 0) < 100:
                tiny_count += 1
        # Require at least 10 tiny flows (not just 1) to avoid FP on legit traffic
        if tiny_count >= 10:
            events.append(AnomalyEvent("session_duration_anomaly", 1.0, ts))
            return events
        if slow_count > SLOWLORIS_CONCURRENT_THRESHOLD:
            events.append(AnomalyEvent("session_duration_anomaly", 1.0, ts))
        return events

    def _rule_http_flood(self, flows, ts):
        events = []
        dt = float(OBSERVATION_INTERVAL)
        by_src = defaultdict(lambda: {'requests': 0, 'duration': 0, 'uas': set()})
        total_flows = len(flows)
        all_uas = set()

        for f in flows:
            src = f['src_ip']
            by_src[src]['requests'] += f.get('request_count', 0)
            dur = max(f.get('last_time', 0) - f.get('start_time', 0), dt)
            by_src[src]['duration'] = max(by_src[src]['duration'], dur)
            ua = f.get('user_agent')
            if ua:
                by_src[src]['uas'].add(ua)
                all_uas.add(ua)

        for src, info in by_src.items():
            rate = info['requests'] / max(info['duration'], dt)
            if rate > HTTP_FLOOD_MULTIPLIER * self._baseline_request_rate:
                events.append(AnomalyEvent("per_source_request_spike", 1.0, ts))
                self._update_baseline(rate)
                return events

        if total_flows >= UA_MIN_REQUESTS:
            diversity = len(all_uas) / total_flows
            if diversity < UA_DIVERSITY_THRESHOLD:
                events.append(AnomalyEvent("user_agent_homogeneity", 1.0, ts))

        self._update_baseline(
            sum(info['requests'] for info in by_src.values()) / max(len(by_src), 1) / dt
        )
        return events

    def _rule_distributed_coordination(self, flows, ts):
        events = []
        dt = float(OBSERVATION_INTERVAL)
        recent_sources_by_subnet16 = defaultdict(set)
        all_srcs = set()

        for f in flows:
            src = f['src_ip']
            all_srcs.add(src)
            if f.get('start_time', 0) >= (max(g.get('last_time', 0) for g in flows) if flows else 0) - DISTRIBUTED_WINDOW:
                subnet16 = '.'.join(src.split('.')[:2])
                recent_sources_by_subnet16[subnet16].add(src)

        for subnet, sources in recent_sources_by_subnet16.items():
            if len(sources) > DISTRIBUTED_SOURCE_THRESHOLD:
                events.append(AnomalyEvent("distributed_connection_burst", 1.0, ts))
                return events

        if len(all_srcs) >= 100:
            by_src_reqs = defaultdict(list)
            for f in flows:
                by_src_reqs[f['src_ip']].append(f.get('request_count', 0))
            src_vals = [sum(v) for v in by_src_reqs.values()]
            if len(src_vals) >= 2:
                mn = sum(src_vals) / len(src_vals)
                variance = sum((x - mn) ** 2 for x in src_vals) / len(src_vals)
                std = math.sqrt(variance)
                corr = std / max(mn, 1e-9)
                if corr > CROSS_CORRELATION_THRESHOLD:
                    events.append(AnomalyEvent("synchronized_request_timing", 1.0, ts))
        return events

    def _update_baseline(self, current_rate):
        self._baseline_request_rate = (
            self._baseline_alpha * current_rate +
            (1 - self._baseline_alpha) * self._baseline_request_rate
        )
