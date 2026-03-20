"""
SENTINEL Testbed Module

Orchestrates multi-scenario test runs for evaluation.

Reference: Section 5.2 in "SENTINEL: A Behavioral DDoS Detection Framework"
"""

import time
import random
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..sentinel.detector import SentinelDetector, DetectorFactory
from ..sentinel.config import RANDOM_SEED
from .scenarios import get_all_scenarios, get_scenario, Scenario
from .traffic_generator import TrafficGenerator, TrafficFlow


@dataclass
class TestRun:
    """Single test run result."""
    scenario_id: str
    repetition: int
    duration: float
    attack_start: float
    detection_time: Optional[float]
    latency: Optional[float]
    detected: bool
    peak_score: float
    mitigation_tier: int
    false_positives: int
    true_positives: int
    false_negatives: int
    true_negatives: int
    metrics: Dict[str, float]
    
    def to_dict(self) -> Dict:
        return {
            'scenario_id': self.scenario_id,
            'repetition': self.repetition,
            'duration': self.duration,
            'attack_start': self.attack_start,
            'detection_time': self.detection_time,
            'latency': self.latency,
            'detected': self.detected,
            'peak_score': self.peak_score,
            'mitigation_tier': self.mitigation_tier,
            'false_positives': self.false_positives,
            'true_positives': self.true_positives,
            'false_negatives': self.false_negatives,
            'true_negatives': self.true_negatives,
            'metrics': self.metrics,
        }


class Testbed:
    """
    Orchestrates test runs across scenarios and repetitions.
    
    Runs 15 test runs (5 scenarios × 3 repetitions) as specified.
    
    Reference: Section 5.2 in the paper.
    """
    
    def __init__(
        self,
        repetitions: int = 3,
        attack_start: float = 30.0,
        parallel: bool = False,
        max_workers: int = 4
    ):
        self.repetitions = repetitions
        self.attack_start = attack_start
        self.parallel = parallel
        self.max_workers = max_workers
        
        self.scenarios = get_all_scenarios()
        self.results: List[TestRun] = []
        
        random.seed(RANDOM_SEED)
    
    def run_single_scenario(
        self,
        scenario: Scenario,
        repetition: int,
        duration: Optional[float] = None
    ) -> TestRun:
        """
        Run a single test scenario.
        
        For each run:
        1. Reset all SENTINEL state (baselines pre-seeded)
        2. Start legitimate traffic
        3. Inject attack at t=30s
        4. Record detection timestamp
        5. Run to scenario end and collect metrics
        """
        detector = DetectorFactory.create_simulation_detector(
            skip_learning=True,
            enable_telemetry=False
        )
        
        traffic_gen = TrafficGenerator()
        traffic_gen.set_attack_scenario(
            scenario.id,
            **scenario.generator_kwargs
        )
        
        legit_gen = traffic_gen.legitimate_generator
        
        dur = duration or scenario.duration
        
        detection_time: Optional[float] = None
        peak_score = 0.0
        mitigation_tier = -1
        
        false_positives = 0
        true_positives = 0
        false_negatives = 0
        true_negatives = 0
        
        current_time = 0.0
        cycle_interval = 5.0
        
        while current_time < dur:
            flows_this_interval = []
            
            num_legit = int(legit_gen.baseline_rate * cycle_interval / 100)
            for _ in range(num_legit):
                flow = legit_gen._generate_single_flow(current_time)
                flows_this_interval.append(flow)
            
            if current_time >= self.attack_start:
                num_attack = self._get_attack_flow_rate(scenario) // 20
                for _ in range(min(num_attack, 50)):
                    attack_flow = self._generate_attack_flow(scenario, current_time)
                    flows_this_interval.append(attack_flow)
            
            for flow in flows_this_interval:
                detector.add_flow(
                    src_ip=flow.src_ip,
                    src_port=flow.src_port,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    proto=flow.proto,
                    bytes_sent=flow.bytes_sent,
                    bytes_recv=flow.bytes_recv,
                    handshake_completed=flow.handshake_completed,
                    http_request=flow.http_request,
                    protocol_violation=flow.protocol_violation,
                    user_agent=flow.user_agent,
                    country_code=flow.country_code
                )
            
            result = detector.process_cycle(current_time)
            
            if result.score > peak_score:
                peak_score = result.score
            
            if result.tier > mitigation_tier:
                mitigation_tier = result.tier
            
            is_attack_active = current_time >= self.attack_start
            
            if result.score >= 0.7:
                if is_attack_active:
                    true_positives += 1
                    if detection_time is None:
                        detection_time = current_time
                else:
                    false_positives += 1
            else:
                if is_attack_active:
                    false_negatives += 1
                else:
                    true_negatives += 1
            
            current_time += cycle_interval
        
        latency = None
        detected = False
        if detection_time is not None:
            latency = detection_time - self.attack_start
            detected = True
        
        return TestRun(
            scenario_id=scenario.id,
            repetition=repetition,
            duration=dur,
            attack_start=self.attack_start,
            detection_time=detection_time,
            latency=latency,
            detected=detected,
            peak_score=peak_score,
            mitigation_tier=mitigation_tier,
            false_positives=false_positives,
            true_positives=true_positives,
            false_negatives=false_negatives,
            true_negatives=true_negatives,
            metrics={
                'detection_rate': true_positives / max(true_positives + false_negatives, 1),
                'precision': true_positives / max(true_positives + false_positives, 1),
                'recall': true_positives / max(true_positives + false_negatives, 1),
                'f1': 2 * true_positives / max(2 * true_positives + false_positives + false_negatives, 1),
            }
        )
    
    def _get_attack_flow_rate(self, scenario: Scenario) -> int:
        """Get attack flow rate for scenario."""
        kwargs = scenario.generator_kwargs
        return int(kwargs.get('rate_per_source', 50) * kwargs.get('sources', 100))
    
    def _generate_attack_flow(self, scenario: Scenario, timestamp: float) -> TrafficFlow:
        """Generate an attack flow."""
        kwargs = scenario.generator_kwargs
        sources = kwargs.get('sources', 100)
        
        src_base = int(timestamp * 10) % sources
        
        return TrafficFlow(
            src_ip=f"172.16.{src_base // 256}.{src_base % 256}",
            src_port=50000 + (src_base % 15000),
            dst_ip='192.168.1.100',
            dst_port=80,
            proto='HTTP',
            timestamp=timestamp,
            bytes_sent=200,
            bytes_recv=0,
            handshake_completed=True,
            http_request=True,
            protocol_violation=False,
            user_agent='Mozilla/5.0',
            country_code='CN',
            is_attack=True
        )
    
    def run_all_scenarios(
        self,
        progress_callback: Optional[Callable[[int, int, TestRun], None]] = None
    ) -> List[TestRun]:
        """
        Run all 15 test runs (5 scenarios × 3 repetitions).
        """
        self.results = []
        total_runs = len(self.scenarios) * self.repetitions
        current_run = 0
        
        if self.parallel:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                
                for scenario in self.scenarios:
                    for rep in range(self.repetitions):
                        futures.append(
                            executor.submit(self.run_single_scenario, scenario, rep)
                        )
                
                for future in as_completed(futures):
                    result = future.result()
                    self.results.append(result)
                    current_run += 1
                    
                    if progress_callback:
                        progress_callback(current_run, total_runs, result)
        else:
            for scenario in self.scenarios:
                for rep in range(self.repetitions):
                    result = self.run_single_scenario(scenario, rep)
                    self.results.append(result)
                    current_run += 1
                    
                    if progress_callback:
                        progress_callback(current_run, total_runs, result)
        
        return self.results
    
    def get_results_by_scenario(self, scenario_id: str) -> List[TestRun]:
        """Get results for a specific scenario."""
        return [r for r in self.results if r.scenario_id == scenario_id]
    
    def get_aggregate_metrics(self) -> Dict[str, Any]:
        """Compute aggregate metrics across all runs."""
        if not self.results:
            return {}
        
        detected_runs = [r for r in self.results if r.detected]
        
        total_tp = sum(r.true_positives for r in self.results)
        total_fp = sum(r.false_positives for r in self.results)
        total_tn = sum(r.true_negatives for r in self.results)
        total_fn = sum(r.false_negatives for r in self.results)
        
        latencies = [r.latency for r in detected_runs if r.latency is not None]
        
        return {
            'total_runs': len(self.results),
            'detected_runs': len(detected_runs),
            'detection_rate': len(detected_runs) / len(self.results),
            'avg_latency': sum(latencies) / len(latencies) if latencies else None,
            'max_latency': max(latencies) if latencies else None,
            'min_latency': min(latencies) if latencies else None,
            'peak_scores': [r.peak_score for r in self.results],
            'avg_peak_score': sum(r.peak_score for r in self.results) / len(self.results),
            'total_tp': total_tp,
            'total_fp': total_fp,
            'total_tn': total_tn,
            'total_fn': total_fn,
            'precision': total_tp / max(total_tp + total_fp, 1),
            'recall': total_tp / max(total_tp + total_fn, 1),
            'f1': 2 * total_tp / max(2 * total_tp + total_fp + total_fn, 1),
        }
    
    def get_scenario_summary(self) -> Dict[str, Dict]:
        """Get summary statistics per scenario."""
        summary = {}
        
        for scenario_id in set(r.scenario_id for r in self.results):
            scenario_results = self.get_results_by_scenario(scenario_id)
            detected = [r for r in scenario_results if r.detected]
            latencies = [r.latency for r in detected if r.latency is not None]
            
            summary[scenario_id] = {
                'runs': len(scenario_results),
                'detected': len(detected),
                'detection_rate': len(detected) / len(scenario_results),
                'avg_latency': sum(latencies) / len(latencies) if latencies else None,
                'avg_peak_score': sum(r.peak_score for r in scenario_results) / len(scenario_results),
                'avg_f1': sum(r.metrics.get('f1', 0) for r in scenario_results) / len(scenario_results),
            }
        
        return summary
    
    def export_results(self, filepath: str):
        """Export results to JSON file."""
        import json
        
        data = {
            'results': [r.to_dict() for r in self.results],
            'aggregate': self.get_aggregate_metrics(),
            'by_scenario': self.get_scenario_summary(),
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
