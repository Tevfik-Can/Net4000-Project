#!/usr/bin/env python3
"""
Cross-Layer Event Correlator (Fixed)

This module correlates kernel-level eBPF events with application-level metrics
to provide enhanced observability and detect blind spots in traditional monitoring.
"""
import json
from typing import List, Dict, Tuple
from dataclasses import dataclass
from collections import defaultdict
import sys


@dataclass
class CorrelatedEvent:
    """Represents a correlated kernel + application event."""
    request_id: int
    app_latency_ms: float
    app_status_code: int
    kernel_events: List[Dict]
    kernel_total_bytes_sent: int
    kernel_total_bytes_recv: int
    kernel_connection_events: int
    kernel_event_count: int
    discrepancy_detected: bool
    discrepancy_reason: str = None


class CrossLayerCorrelator:
    """
    Correlates eBPF kernel events with application-level metrics.
    
    This is the core of the cross-layer observability framework, enabling
    detection of issues that are invisible to single-layer monitoring.
    """
    
    def __init__(self, time_window_ms: float = 500.0, debug: bool = False):
        """
        Initialize the correlator.
        
        Args:
            time_window_ms: Time window for correlating events (milliseconds)
            debug: Enable debug output
        """
        self.time_window_ns = time_window_ms * 1_000_000  # Convert to nanoseconds
        self.correlations: List[CorrelatedEvent] = []
        self.debug = debug
    
    def load_app_metrics(self, filepath: str) -> List[Dict]:
        """Load application metrics from JSON file."""
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def load_ebpf_events(self, filepath: str) -> List[Dict]:
        """Load eBPF events from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
            # Handle both direct list and nested structure
            if isinstance(data, dict) and 'ebpf_events' in data:
                return data['ebpf_events']
            return data
    
    def correlate(self, app_metrics: List[Dict], ebpf_events: List[Dict]) -> List[CorrelatedEvent]:
        """
        Correlate application metrics with eBPF events.
        
        Args:
            app_metrics: List of application-level metrics
            ebpf_events: List of kernel-level eBPF events
            
        Returns:
            List of correlated events with cross-layer insights
        """
        self.correlations = []
        
        if self.debug:
            print(f"\n=== Debug Info ===")
            print(f"Total app metrics: {len(app_metrics)}")
            print(f"Total eBPF events: {len(ebpf_events)}")
            
            if ebpf_events:
                print(f"\nSample eBPF event:")
                print(json.dumps(ebpf_events[0], indent=2))
                
                # Show time range
                timestamps = [e['timestamp_ns'] for e in ebpf_events]
                print(f"\neBPF time range:")
                print(f"  First: {min(timestamps)}")
                print(f"  Last:  {max(timestamps)}")
                print(f"  Span:  {(max(timestamps) - min(timestamps)) / 1e9:.2f} seconds")
            
            if app_metrics:
                print(f"\nSample app metric:")
                print(json.dumps(app_metrics[0], indent=2))
                
                # Show time range
                start_times = [m['start_time'] for m in app_metrics]
                print(f"\nApp time range:")
                print(f"  First: {min(start_times)}")
                print(f"  Last:  {max(start_times)}")
                print(f"  Span:  {max(start_times) - min(start_times):.2f} seconds")
        
        # Get PIDs involved (for filtering if needed)
        pids_in_events = set(e['pid'] for e in ebpf_events)
        if self.debug:
            print(f"\nPIDs in eBPF events: {sorted(pids_in_events)}")
        
        for metric in app_metrics:
            # Convert app timestamps to nanoseconds
            start_ns = int(metric['start_time'] * 1_000_000_000)
            end_ns = int(metric['end_time'] * 1_000_000_000)
            
            # Find kernel events within the time window
            matching_events = self._find_matching_events(
                ebpf_events, 
                start_ns, 
                end_ns
            )
            
            # Analyze kernel events
            kernel_stats = self._analyze_kernel_events(matching_events)
            
            # Detect discrepancies
            discrepancy, reason = self._detect_discrepancy(metric, kernel_stats, matching_events)
            
            if self.debug and metric['request_id'] <= 3:
                print(f"\n--- Request {metric['request_id']} ---")
                print(f"App time: {start_ns} to {end_ns}")
                print(f"Matched {len(matching_events)} kernel events")
                print(f"Bytes sent: {kernel_stats['bytes_sent']}, recv: {kernel_stats['bytes_recv']}")
                if matching_events:
                    print(f"Sample matched event: {matching_events[0]}")
            
            # Create correlated event
            correlated = CorrelatedEvent(
                request_id=metric['request_id'],
                app_latency_ms=metric['latency_ms'],
                app_status_code=metric.get('status_code'),
                kernel_events=matching_events,
                kernel_total_bytes_sent=kernel_stats['bytes_sent'],
                kernel_total_bytes_recv=kernel_stats['bytes_recv'],
                kernel_connection_events=kernel_stats['connections'],
                kernel_event_count=len(matching_events),
                discrepancy_detected=discrepancy,
                discrepancy_reason=reason
            )
            
            self.correlations.append(correlated)
        
        return self.correlations
    
    def _find_matching_events(
        self, 
        ebpf_events: List[Dict], 
        start_ns: int, 
        end_ns: int
    ) -> List[Dict]:
        """
        Find eBPF events that occurred during the application request.
        
        Applies a time window buffer to catch events that might be
        slightly before or after the measured app timestamps.
        """
        matching = []
        window_start = start_ns - self.time_window_ns
        window_end = end_ns + self.time_window_ns
        
        for event in ebpf_events:
            ts = event['timestamp_ns']
            if window_start <= ts <= window_end:
                matching.append(event)
        
        return matching
    
    def _analyze_kernel_events(self, events: List[Dict]) -> Dict:
        """
        Analyze kernel events to extract statistics.
        
        Returns:
            Dictionary with aggregated statistics
        """
        stats = {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'connections': 0,
            'closes': 0,
            'event_types': defaultdict(int)
        }
        
        for event in events:
            event_type = event['event_type']
            stats['event_types'][event_type] += 1
            
            if event_type == 'send':
                stats['bytes_sent'] += event['bytes']
            elif event_type == 'recv':
                stats['bytes_recv'] += event['bytes']
            elif event_type == 'connect':
                stats['connections'] += 1
            elif event_type == 'close':
                stats['closes'] += 1
        
        return stats
    
    def _detect_discrepancy(
        self, 
        app_metric: Dict, 
        kernel_stats: Dict,
        matching_events: List[Dict]
    ) -> Tuple[bool, str]:
        """
        Detect discrepancies between application and kernel observations.
        
        This is where cross-layer insights reveal monitoring blind spots.
        
        Returns:
            Tuple of (discrepancy_detected: bool, reason: str)
        """
        # First, check if we have ANY matching kernel events
        if len(matching_events) == 0:
            # No kernel events matched - this could be:
            # 1. Wrong PID (app running in different process)
            # 2. Time desync
            # 3. eBPF not capturing this connection
            return True, "No kernel events matched this request (possible PID mismatch or time desync)"
        
        # Case 1: Application reports success but minimal/no data transfer
        if app_metric.get('result') == 'success' or app_metric.get('status_code') == 200:
            # For HTTP, we expect at least some data exchange
            # Loopback connections often show 0 bytes in BPF due to optimization
            if kernel_stats['bytes_sent'] == 0 and kernel_stats['bytes_recv'] == 0:
                # Check if there are send/recv events even with 0 bytes (loopback optimization)
                if kernel_stats['event_types'].get('send', 0) > 0 or kernel_stats['event_types'].get('recv', 0) > 0:
                    # Events exist but show 0 bytes - likely loopback optimization
                    return False, None
                else:
                    return True, "App reports success but no kernel send/recv events detected"
        
        # Case 2: High latency but minimal kernel activity
        if app_metric['latency_ms'] > 100:  # Threshold for "high" latency
            expected_events = 4  # connect, send, recv, close
            if len(kernel_stats['event_types']) < expected_events:
                return True, f"High latency ({app_metric['latency_ms']:.2f}ms) with only {len(kernel_stats['event_types'])} event types"
        
        # Case 3: Application timeout but kernel shows activity
        if app_metric.get('result') == 'timeout':
            if kernel_stats['bytes_sent'] > 0:
                return True, "App timeout but kernel shows data was sent"
        
        # Case 4: Connection established but no data sent
        if kernel_stats['connections'] > 0 and kernel_stats['bytes_sent'] == 0:
            if kernel_stats['event_types'].get('send', 0) == 0:
                return True, "Connection established but no send attempts"
        
        # Case 5: Asymmetric data transfer (potential packet loss)
        if kernel_stats['bytes_sent'] > 0 and kernel_stats['bytes_recv'] == 0:
            if app_metric.get('status_code') == 200:
                if kernel_stats['event_types'].get('recv', 0) == 0:
                    return True, "Data sent but no response received at kernel level (app thinks success)"
        
        # Case 6: No connection events but data transfer
        if kernel_stats['connections'] == 0 and (kernel_stats['bytes_sent'] > 0 or kernel_stats['bytes_recv'] > 0):
            return True, "Data transfer without connection event (reused socket?)"
        
        return False, None
    
    def get_blind_spots(self) -> List[CorrelatedEvent]:
        """
        Get all events where cross-layer monitoring detected issues
        that single-layer monitoring would miss.
        
        Returns:
            List of events with discrepancies (blind spots)
        """
        return [c for c in self.correlations if c.discrepancy_detected]
    
    def export_correlations(self, output_path: str = "correlations.json"):
        """Export correlated events to JSON."""
        blind_spots = self.get_blind_spots()
        
        data = {
            'total_requests': len(self.correlations),
            'blind_spots_detected': len(blind_spots),
            'blind_spot_types': self._categorize_blind_spots(blind_spots),
            'correlations': [
                {
                    'request_id': c.request_id,
                    'app_latency_ms': c.app_latency_ms,
                    'app_status_code': c.app_status_code,
                    'kernel_events_count': c.kernel_event_count,
                    'kernel_bytes_sent': c.kernel_total_bytes_sent,
                    'kernel_bytes_recv': c.kernel_total_bytes_recv,
                    'discrepancy_detected': c.discrepancy_detected,
                    'discrepancy_reason': c.discrepancy_reason,
                    'kernel_events': c.kernel_events
                }
                for c in self.correlations
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\nExported {len(self.correlations)} correlations to {output_path}")
        print(f"Blind spots detected: {len(blind_spots)}")
        
        # Print summary of blind spot types
        if blind_spots:
            print(f"\nBlind spot categories:")
            for category, count in data['blind_spot_types'].items():
                print(f"  {category}: {count}")
    
    def _categorize_blind_spots(self, blind_spots: List[CorrelatedEvent]) -> Dict[str, int]:
        """Categorize blind spots by type."""
        categories = defaultdict(int)
        for bs in blind_spots:
            if bs.discrepancy_reason:
                # Extract category from reason
                if "No kernel events matched" in bs.discrepancy_reason:
                    categories["Time/PID mismatch"] += 1
                elif "no kernel send/recv events" in bs.discrepancy_reason:
                    categories["Missing data transfer events"] += 1
                elif "High latency" in bs.discrepancy_reason:
                    categories["Latency with minimal kernel activity"] += 1
                elif "timeout" in bs.discrepancy_reason:
                    categories["Timeout discrepancies"] += 1
                elif "no send attempts" in bs.discrepancy_reason:
                    categories["Connection without data"] += 1
                elif "no response received" in bs.discrepancy_reason:
                    categories["Asymmetric transfer"] += 1
                elif "without connection event" in bs.discrepancy_reason:
                    categories["Data without connection"] += 1
                else:
                    categories["Other"] += 1
        return dict(categories)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cross-layer event correlator"
    )
    parser.add_argument(
        '--app-metrics',
        required=True,
        help='Application metrics JSON file'
    )
    parser.add_argument(
        '--ebpf-events',
        required=True,
        help='eBPF events JSON file'
    )
    parser.add_argument(
        '--output',
        default='correlations.json',
        help='Output file for correlations'
    )
    parser.add_argument(
        '--time-window',
        type=float,
        default=500.0,
        help='Time window for correlation (milliseconds)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )
    
    args = parser.parse_args()
    
    correlator = CrossLayerCorrelator(
        time_window_ms=args.time_window,
        debug=args.debug
    )
    
    print(f"Loading application metrics from {args.app_metrics}")
    app_metrics = correlator.load_app_metrics(args.app_metrics)
    
    print(f"Loading eBPF events from {args.ebpf_events}")
    ebpf_events = correlator.load_ebpf_events(args.ebpf_events)
    
    print(f"Correlating {len(app_metrics)} requests with {len(ebpf_events)} kernel events...")
    correlations = correlator.correlate(app_metrics, ebpf_events)
    
    print(f"\nCorrelation complete:")
    print(f"  Total requests: {len(correlations)}")
    print(f"  Blind spots detected: {len(correlator.get_blind_spots())}")
    
    # Print sample blind spots
    blind_spots = correlator.get_blind_spots()
    if blind_spots:
        print(f"\nSample blind spots (showing first 5):")
        for bs in blind_spots[:5]:
            print(f"  Request {bs.request_id}: {bs.discrepancy_reason}")
        if len(blind_spots) > 5:
            print(f"  ... and {len(blind_spots) - 5} more")
    
    correlator.export_correlations(args.output)


if __name__ == '__main__':
    main()