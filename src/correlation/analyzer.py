#!/usr/bin/env python3
"""
Enhanced Cross-Layer Performance Analyzer "analyzer.py"

Provides comprehensive statistical analysis including:
- Latency metrics (avg, median, percentiles)
- Throughput analysis
- Error rate tracking
- Blind spot detection and categorization
- Performance recommendations
- Comparison reports (baseline vs cross-layer)
"""
import json
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import statistics
import sys
from pathlib import Path


@dataclass
class PerformanceMetrics:
    """Performance statistics for a single request."""
    request_id: int
    latency_ms: float
    bytes_sent: int
    bytes_received: int
    throughput_bps: float  # bits per second
    kernel_events_count: int
    connection_duration_ns: int
    success: bool
    error_type: Optional[str] = None


@dataclass
class AggregatedStatistics:
    """Aggregated performance statistics across all requests."""
    # Request counts
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    
    # Latency statistics (ms)
    latency_avg: float = 0.0
    latency_median: float = 0.0
    latency_min: float = 0.0
    latency_max: float = 0.0
    latency_stddev: float = 0.0
    latency_p50: float = 0.0
    latency_p90: float = 0.0
    latency_p95: float = 0.0
    latency_p99: float = 0.0
    
    # Throughput statistics
    throughput_avg_mbps: float = 0.0
    throughput_total_mb: float = 0.0
    bytes_sent_total: int = 0
    bytes_received_total: int = 0
    
    # Kernel metrics
    kernel_events_avg: float = 0.0
    kernel_events_total: int = 0
    bytes_per_event_avg: float = 0.0
    connection_duration_avg_ms: float = 0.0
    
    # Rates
    success_rate_pct: float = 100.0
    error_rate_pct: float = 0.0
    requests_per_second: float = 0.0
    events_per_second: float = 0.0
    
    # Cross-layer insights
    blind_spots_count: int = 0
    blind_spots_pct: float = 0.0
    discrepancy_types: Dict[str, int] = None
    
    # Performance flags
    high_latency_count: int = 0
    low_throughput_count: int = 0
    timeout_count: int = 0
    
    def __post_init__(self):
        if self.discrepancy_types is None:
            self.discrepancy_types = {}


class PerformanceAnalyzer:
    """
    Comprehensive performance analyzer for cross-layer monitoring data.
    """
    
    def __init__(
        self,
        high_latency_threshold_ms: float = 100.0,
        low_throughput_threshold_mbps: float = 1.0,
        debug: bool = False
    ):
        self.high_latency_threshold_ms = high_latency_threshold_ms
        self.low_throughput_threshold_mbps = low_throughput_threshold_mbps
        self.debug = debug
        
        self.metrics: List[PerformanceMetrics] = []
        self.stats = AggregatedStatistics()
    
    def load_correlations(self, filepath: str) -> Dict:
        """Load correlation data from JSON file."""
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def load_app_metrics(self, filepath: str) -> List[Dict]:
        """Load application metrics for baseline comparison."""
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def analyze_correlations(self, correlation_data: Dict):
        """
        Analyze correlation data and extract performance metrics.
        
        Args:
            correlation_data: Dict from correlator output
        """
        correlations = correlation_data.get('correlations', [])
        
        if not correlations:
            print("Warning: No correlations found in data")
            return
        
        # Extract performance metrics from each correlation
        for corr in correlations:
            # Calculate throughput
            total_bytes = corr.get('kernel_bytes_sent', 0) + corr.get('kernel_bytes_recv', 0)
            latency_ms = corr.get('app_latency_ms', 0)
            
            if latency_ms > 0:
                throughput_bps = (total_bytes * 8) / (latency_ms / 1000.0)
            else:
                throughput_bps = 0.0
            
            # Determine success
            success = corr.get('app_success', True)
            error_type = None
            if not success:
                if 'timeout' in str(corr.get('discrepancy_reason', '')).lower():
                    error_type = 'timeout'
                else:
                    error_type = 'error'
            
            # Create metrics object
            metric = PerformanceMetrics(
                request_id=corr.get('request_id', 0),
                latency_ms=latency_ms,
                bytes_sent=corr.get('kernel_bytes_sent', 0),
                bytes_received=corr.get('kernel_bytes_recv', 0),
                throughput_bps=throughput_bps,
                kernel_events_count=corr.get('kernel_events_count', 0),
                connection_duration_ns=corr.get('kernel_connection_duration_ns', 0),
                success=success,
                error_type=error_type
            )
            
            self.metrics.append(metric)
        
        # Calculate aggregated statistics
        self._calculate_statistics(correlation_data)
    
    def analyze_baseline(self, app_metrics: List[Dict]):
        """
        Analyze baseline (app-only) metrics for comparison.
        
        Args:
            app_metrics: List of application metrics without kernel data
        """
        for metric in app_metrics:
            success = metric.get('result') == 'success' or metric.get('status_code') == 200
            
            perf_metric = PerformanceMetrics(
                request_id=metric.get('request_id', 0),
                latency_ms=metric.get('latency_ms', 0),
                bytes_sent=0,  # Not available in app-only
                bytes_received=0,
                throughput_bps=0,
                kernel_events_count=0,
                connection_duration_ns=0,
                success=success,
                error_type=metric.get('result') if not success else None
            )
            
            self.metrics.append(perf_metric)
        
        # Calculate statistics
        self._calculate_baseline_statistics()
    
    def _calculate_statistics(self, correlation_data: Dict):
        """Calculate comprehensive statistics from metrics."""
        if not self.metrics:
            return
        
        # Basic counts
        self.stats.total_requests = len(self.metrics)
        self.stats.successful_requests = sum(1 for m in self.metrics if m.success)
        self.stats.failed_requests = self.stats.total_requests - self.stats.successful_requests
        
        # Success/error rates
        if self.stats.total_requests > 0:
            self.stats.success_rate_pct = (self.stats.successful_requests / self.stats.total_requests) * 100
            self.stats.error_rate_pct = 100 - self.stats.success_rate_pct
        
        # Latency statistics
        latencies = [m.latency_ms for m in self.metrics]
        if latencies:
            self.stats.latency_avg = statistics.mean(latencies)
            self.stats.latency_median = statistics.median(latencies)
            self.stats.latency_min = min(latencies)
            self.stats.latency_max = max(latencies)
            
            if len(latencies) > 1:
                self.stats.latency_stddev = statistics.stdev(latencies)
            
            # Calculate percentiles
            sorted_latencies = sorted(latencies)
            n = len(sorted_latencies)
            self.stats.latency_p50 = self._percentile(sorted_latencies, 50)
            self.stats.latency_p90 = self._percentile(sorted_latencies, 90)
            self.stats.latency_p95 = self._percentile(sorted_latencies, 95)
            self.stats.latency_p99 = self._percentile(sorted_latencies, 99)
        
        # Throughput statistics
        throughputs = [m.throughput_bps for m in self.metrics if m.throughput_bps > 0]
        if throughputs:
            self.stats.throughput_avg_mbps = statistics.mean(throughputs) / 1_000_000
        
        self.stats.bytes_sent_total = sum(m.bytes_sent for m in self.metrics)
        self.stats.bytes_received_total = sum(m.bytes_received for m in self.metrics)
        self.stats.throughput_total_mb = (self.stats.bytes_sent_total + self.stats.bytes_received_total) / 1_000_000
        
        # Kernel metrics
        event_counts = [m.kernel_events_count for m in self.metrics if m.kernel_events_count > 0]
        if event_counts:
            self.stats.kernel_events_avg = statistics.mean(event_counts)
            self.stats.kernel_events_total = sum(event_counts)
            
            total_bytes = self.stats.bytes_sent_total + self.stats.bytes_received_total
            if self.stats.kernel_events_total > 0:
                self.stats.bytes_per_event_avg = total_bytes / self.stats.kernel_events_total
        
        # Connection duration
        durations = [m.connection_duration_ns / 1_000_000 for m in self.metrics if m.connection_duration_ns > 0]
        if durations:
            self.stats.connection_duration_avg_ms = statistics.mean(durations)
        
        # Performance flags
        self.stats.high_latency_count = sum(
            1 for m in self.metrics if m.latency_ms > self.high_latency_threshold_ms
        )
        self.stats.low_throughput_count = sum(
            1 for m in self.metrics 
            if m.throughput_bps > 0 and m.throughput_bps < (self.low_throughput_threshold_mbps * 1_000_000)
        )
        self.stats.timeout_count = sum(1 for m in self.metrics if m.error_type == 'timeout')
        
        # Blind spots from correlation data
        self.stats.blind_spots_count = correlation_data.get('blind_spots_detected', 0)
        if self.stats.total_requests > 0:
            self.stats.blind_spots_pct = (self.stats.blind_spots_count / self.stats.total_requests) * 100
        
        # Categorize blind spot types
        self.stats.discrepancy_types = correlation_data.get('blind_spot_types', {})
        
        # Calculate request rate (if we have correlation data with timing)
        if 'summary' in correlation_data:
            summary = correlation_data['summary']
            # Request rate would need to be calculated from actual time span
            # For now, leave as 0 unless provided
    
    def _calculate_baseline_statistics(self):
        """Calculate statistics for baseline (app-only) data."""
        if not self.metrics:
            return
        
        self.stats.total_requests = len(self.metrics)
        self.stats.successful_requests = sum(1 for m in self.metrics if m.success)
        self.stats.failed_requests = self.stats.total_requests - self.stats.successful_requests
        
        if self.stats.total_requests > 0:
            self.stats.success_rate_pct = (self.stats.successful_requests / self.stats.total_requests) * 100
            self.stats.error_rate_pct = 100 - self.stats.success_rate_pct
        
        # Latency statistics
        latencies = [m.latency_ms for m in self.metrics]
        if latencies:
            self.stats.latency_avg = statistics.mean(latencies)
            self.stats.latency_median = statistics.median(latencies)
            self.stats.latency_min = min(latencies)
            self.stats.latency_max = max(latencies)
            
            if len(latencies) > 1:
                self.stats.latency_stddev = statistics.stdev(latencies)
            
            sorted_latencies = sorted(latencies)
            self.stats.latency_p50 = self._percentile(sorted_latencies, 50)
            self.stats.latency_p90 = self._percentile(sorted_latencies, 90)
            self.stats.latency_p95 = self._percentile(sorted_latencies, 95)
            self.stats.latency_p99 = self._percentile(sorted_latencies, 99)
        
        # Performance flags
        self.stats.high_latency_count = sum(
            1 for m in self.metrics if m.latency_ms > self.high_latency_threshold_ms
        )
        self.stats.timeout_count = sum(1 for m in self.metrics if m.error_type == 'timeout')
    
    def _percentile(self, sorted_data: List[float], percentile: int) -> float:
        """Calculate percentile from sorted data."""
        if not sorted_data:
            return 0.0
        n = len(sorted_data)
        index = int((percentile / 100.0) * n)
        if index >= n:
            index = n - 1
        return sorted_data[index]
    
    def generate_recommendations(self) -> List[str]:
        """Generate actionable performance recommendations."""
        recommendations = []
        
        # Latency recommendations
        if self.stats.latency_p95 > 50:
            recommendations.append(
                f"⚠️ High P95 latency ({self.stats.latency_p95:.2f}ms): "
                f"95% of requests exceed 50ms. Investigate slow requests and optimize critical path."
            )
        
        if self.stats.latency_max > 1000:
            recommendations.append(
                f"⚠️ Very high maximum latency ({self.stats.latency_max:.2f}ms): "
                f"Extreme outliers detected. Check for timeouts or resource contention."
            )
        
        # Throughput recommendations
        if self.stats.throughput_avg_mbps > 0 and self.stats.throughput_avg_mbps < self.low_throughput_threshold_mbps:
            recommendations.append(
                f"⚠️ Low average throughput ({self.stats.throughput_avg_mbps:.2f} Mbps): "
                f"Network performance below {self.low_throughput_threshold_mbps} Mbps threshold. "
                f"Check network configuration, MTU settings, or increase buffer sizes."
            )
        
        # Error rate recommendations
        if self.stats.error_rate_pct > 5:
            recommendations.append(
                f"⚠️ High error rate ({self.stats.error_rate_pct:.1f}%): "
                f"{self.stats.failed_requests}/{self.stats.total_requests} requests failed. "
                f"Investigate root cause of failures."
            )
        
        if self.stats.timeout_count > 0:
            timeout_pct = (self.stats.timeout_count / self.stats.total_requests) * 100
            recommendations.append(
                f"⚠️ Timeout issues ({self.stats.timeout_count} timeouts, {timeout_pct:.1f}%): "
                f"Increase timeout values or optimize slow operations."
            )
        
        # Efficiency recommendations
        if self.stats.bytes_per_event_avg > 0 and self.stats.bytes_per_event_avg < 512:
            recommendations.append(
                f"⚠️ Low data transfer efficiency ({self.stats.bytes_per_event_avg:.1f} bytes/event): "
                f"Many small packets detected. Consider batching data or increasing buffer sizes."
            )
        
        if self.stats.kernel_events_avg > 100:
            recommendations.append(
                f"⚠️ High kernel event count ({self.stats.kernel_events_avg:.1f} events/request): "
                f"Excessive system calls detected. Consider reducing syscall overhead through batching."
            )
        
        # Blind spot recommendations
        if self.stats.blind_spots_pct > 10:
            recommendations.append(
                f"🔍 Significant monitoring blind spots ({self.stats.blind_spots_pct:.1f}%): "
                f"Cross-layer monitoring reveals issues missed by app-only monitoring. "
                f"Types: {', '.join(f'{k}: {v}' for k, v in self.stats.discrepancy_types.items())}"
            )
        
        # Connection duration
        if self.stats.connection_duration_avg_ms > 50:
            recommendations.append(
                f"⚠️ Slow connection setup ({self.stats.connection_duration_avg_ms:.2f}ms avg): "
                f"Consider connection pooling, keepalive, or faster DNS resolution."
            )
        
        # Positive feedback
        if not recommendations:
            if self.stats.success_rate_pct == 100:
                recommendations.append(
                    "✅ All requests successful! System is operating within normal parameters."
                )
            if self.stats.latency_p95 < 50:
                recommendations.append(
                    f"✅ Good latency performance (P95: {self.stats.latency_p95:.2f}ms < 50ms threshold)."
                )
            if self.stats.blind_spots_pct == 0:
                recommendations.append(
                    "✅ No blind spots detected. App-layer and kernel-layer monitoring are aligned."
                )
        
        return recommendations
    
    def print_summary(self):
        """Print a formatted summary of the analysis."""
        print("\n" + "="*70)
        print(" PERFORMANCE ANALYSIS SUMMARY")
        print("="*70)
        
        print(f"\n📊 Request Statistics:")
        print(f"  Total Requests:      {self.stats.total_requests}")
        print(f"  Successful:          {self.stats.successful_requests} ({self.stats.success_rate_pct:.1f}%)")
        print(f"  Failed:              {self.stats.failed_requests} ({self.stats.error_rate_pct:.1f}%)")
        print(f"  Timeouts:            {self.stats.timeout_count}")
        
        print(f"\n⏱️  Latency Metrics (milliseconds):")
        print(f"  Average:             {self.stats.latency_avg:.2f} ms")
        print(f"  Median (P50):        {self.stats.latency_median:.2f} ms")
        print(f"  P90:                 {self.stats.latency_p90:.2f} ms")
        print(f"  P95:                 {self.stats.latency_p95:.2f} ms")
        print(f"  P99:                 {self.stats.latency_p99:.2f} ms")
        print(f"  Min:                 {self.stats.latency_min:.2f} ms")
        print(f"  Max:                 {self.stats.latency_max:.2f} ms")
        if self.stats.latency_stddev > 0:
            print(f"  Std Deviation:       {self.stats.latency_stddev:.2f} ms")
        
        if self.stats.throughput_avg_mbps > 0:
            print(f"\n📈 Throughput Metrics:")
            print(f"  Average:             {self.stats.throughput_avg_mbps:.2f} Mbps")
            print(f"  Total Data:          {self.stats.throughput_total_mb:.2f} MB")
            print(f"    Sent:              {self.stats.bytes_sent_total / 1_000_000:.2f} MB")
            print(f"    Received:          {self.stats.bytes_received_total / 1_000_000:.2f} MB")
        
        if self.stats.kernel_events_total > 0:
            print(f"\n🔧 Kernel Metrics:")
            print(f"  Total Events:        {self.stats.kernel_events_total}")
            print(f"  Avg Events/Request:  {self.stats.kernel_events_avg:.1f}")
            print(f"  Bytes/Event:         {self.stats.bytes_per_event_avg:.1f}")
            if self.stats.connection_duration_avg_ms > 0:
                print(f"  Avg Connection Time: {self.stats.connection_duration_avg_ms:.2f} ms")
        
        if self.stats.blind_spots_count > 0:
            print(f"\n🔍 Cross-Layer Insights:")
            print(f"  Blind Spots:         {self.stats.blind_spots_count} ({self.stats.blind_spots_pct:.1f}%)")
            if self.stats.discrepancy_types:
                print(f"  Discrepancy Types:")
                for dtype, count in self.stats.discrepancy_types.items():
                    print(f"    - {dtype}: {count}")
        
        print(f"\n⚠️  Performance Flags:")
        print(f"  High Latency:        {self.stats.high_latency_count} (>{self.high_latency_threshold_ms}ms)")
        print(f"  Low Throughput:      {self.stats.low_throughput_count} (<{self.low_throughput_threshold_mbps} Mbps)")
        
        recommendations = self.generate_recommendations()
        if recommendations:
            print(f"\n💡 Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
        
        print("\n" + "="*70)
    
    def export_report(self, output_path: str = "performance_report.json"):
        """Export detailed performance report to JSON."""
        report = {
            'summary': asdict(self.stats),
            'recommendations': self.generate_recommendations(),
            'detailed_metrics': [
                {
                    'request_id': m.request_id,
                    'latency_ms': m.latency_ms,
                    'throughput_mbps': m.throughput_bps / 1_000_000,
                    'bytes_sent': m.bytes_sent,
                    'bytes_received': m.bytes_received,
                    'kernel_events': m.kernel_events_count,
                    'connection_duration_ms': m.connection_duration_ns / 1_000_000,
                    'success': m.success,
                    'error_type': m.error_type,
                }
                for m in self.metrics
            ],
            'thresholds': {
                'high_latency_ms': self.high_latency_threshold_ms,
                'low_throughput_mbps': self.low_throughput_threshold_mbps,
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report exported to: {output_path}")
    
    def compare_with_baseline(self, baseline_stats: 'AggregatedStatistics') -> Dict:
        """
        Compare cross-layer monitoring with baseline (app-only) monitoring.
        
        Returns improvement metrics.
        """
        comparison = {
            'latency_improvement_pct': 0.0,
            'error_detection_improvement_pct': 0.0,
            'blind_spots_unique_to_cross_layer': self.stats.blind_spots_count,
            'additional_insights': [],
        }
        
        # Latency comparison
        if baseline_stats.latency_avg > 0:
            latency_diff = ((baseline_stats.latency_avg - self.stats.latency_avg) / baseline_stats.latency_avg) * 100
            comparison['latency_improvement_pct'] = latency_diff
        
        # Error detection
        baseline_detected_errors = baseline_stats.failed_requests
        crosslayer_detected_errors = self.stats.failed_requests + self.stats.blind_spots_count
        
        if baseline_detected_errors > 0:
            additional_errors = crosslayer_detected_errors - baseline_detected_errors
            comparison['error_detection_improvement_pct'] = (additional_errors / baseline_detected_errors) * 100
        
        # Additional insights
        if self.stats.blind_spots_pct > 0:
            comparison['additional_insights'].append(
                f"Cross-layer monitoring detected {self.stats.blind_spots_count} additional issues "
                f"({self.stats.blind_spots_pct:.1f}%) that app-only monitoring missed"
            )
        
        if self.stats.kernel_events_avg > 0:
            comparison['additional_insights'].append(
                f"Kernel-level visibility: avg {self.stats.kernel_events_avg:.1f} events per request"
            )
        
        return comparison


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Analyze cross-layer monitoring performance"
    )
    parser.add_argument(
        '--correlations',
        required=True,
        help='Correlation JSON file from correlator'
    )
    parser.add_argument(
        '--baseline',
        help='Optional baseline (app-only) metrics for comparison'
    )
    parser.add_argument(
        '--output',
        default='performance_report.json',
        help='Output JSON file for detailed report'
    )
    parser.add_argument(
        '--high-latency-threshold',
        type=float,
        default=100.0,
        help='High latency threshold in ms (default: 100)'
    )
    parser.add_argument(
        '--low-throughput-threshold',
        type=float,
        default=1.0,
        help='Low throughput threshold in Mbps (default: 1.0)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )
    
    args = parser.parse_args()
    
    # Analyze cross-layer correlations
    print("Loading correlation data...")
    analyzer = PerformanceAnalyzer(
        high_latency_threshold_ms=args.high_latency_threshold,
        low_throughput_threshold_mbps=args.low_throughput_threshold,
        debug=args.debug
    )
    
    correlation_data = analyzer.load_correlations(args.correlations)
    analyzer.analyze_correlations(correlation_data)
    
    # Print summary
    analyzer.print_summary()
    
    # Export detailed report
    analyzer.export_report(args.output)
    
    # Compare with baseline if provided
    if args.baseline:
        print(f"\nLoading baseline data for comparison...")
        baseline_analyzer = PerformanceAnalyzer()
        baseline_data = baseline_analyzer.load_app_metrics(args.baseline)
        baseline_analyzer.analyze_baseline(baseline_data)
        
        print("\n" + "="*70)
        print(" BASELINE COMPARISON")
        print("="*70)
        
        comparison = analyzer.compare_with_baseline(baseline_analyzer.stats)
        
        print(f"\nImprovement Metrics:")
        if comparison['latency_improvement_pct'] != 0:
            print(f"  Latency:             {comparison['latency_improvement_pct']:+.1f}%")
        if comparison['error_detection_improvement_pct'] > 0:
            print(f"  Error Detection:     +{comparison['error_detection_improvement_pct']:.1f}%")
        print(f"  Blind Spots Found:   {comparison['blind_spots_unique_to_cross_layer']}")
        
        if comparison['additional_insights']:
            print(f"\nAdditional Insights:")
            for insight in comparison['additional_insights']:
                print(f"  • {insight}")
        
        print("="*70)


if __name__ == '__main__':
    main()