#!/usr/bin/env python3
"""
Cross-Layer Event Correlator "correlator.py"

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
        Detect TRUE blind spots: Issues visible in kernel but hidden from app.
        
        The app layer thinks everything is fine, but kernel reveals problems.
        """
        
        # Skip if no kernel events (this is a tool limitation, not a blind spot)
        if len(matching_events) == 0:
            return False, None  # Changed from True - not a research finding
        
        # ONLY flag as blind spot if app reports success
        app_success = (app_metric.get('result') == 'success' or 
                    app_metric.get('status_code') == 200)
        
        if not app_success:
            # App already knows there's a problem - not a blind spot
            return False, None
        
        # ============================================================
        # TRUE BLIND SPOTS: App says OK, but kernel reveals issues
        # ============================================================
        
        # BLIND SPOT 1: Hidden retransmissions
        # App: "Success in 50ms"
        # Kernel: Actually retransmitted packets (network struggling)
        retransmit_events = [e for e in matching_events if e.get('event_type') == 'retransmit']
        if len(retransmit_events) > 0:
            return True, f"App reports success but kernel detected {len(retransmit_events)} TCP retransmissions (hidden network issues)"
        
        # BLIND SPOT 2: Multiple connection attempts
        # App: "Success"
        # Kernel: Connection failed multiple times before succeeding
        connect_events = kernel_stats['event_types'].get('connect', 0)
        if connect_events > 1:
            return True, f"App reports success but kernel shows {connect_events} connection attempts (reliability issues masked)"
        
        # BLIND SPOT 3: Excessive kernel events for simple operation
        # App: "Success in 5ms"
        # Kernel: 50+ events (something is inefficient)
        if app_metric['latency_ms'] < 10 and len(matching_events) > 50:
            return True, f"App reports fast success ({app_metric['latency_ms']:.2f}ms) but kernel shows {len(matching_events)} events (hidden inefficiency)"
        
        # BLIND SPOT 4: Asymmetric data flow
        # App: "Success"
        # Kernel: Sent data but received nothing (or vice versa)
        bytes_sent = kernel_stats['bytes_sent']
        bytes_recv = kernel_stats['bytes_recv']
        
        # Significant data sent but no response
        if bytes_sent > 1000 and bytes_recv == 0:
            return True, "App reports success but kernel shows data sent with no response received (potential packet loss)"
        
        # Response received but nothing sent (unexpected)
        if bytes_recv > 1000 and bytes_sent == 0:
            return True, "App reports success but kernel shows data received without prior send (protocol anomaly)"
        
        # BLIND SPOT 5: Latency mismatch
        # App: "Low latency"
        # Kernel: Many events suggest delays
        if app_metric['latency_ms'] < 20:
            # For low app-reported latency, shouldn't have many events
            close_events = kernel_stats['event_types'].get('close', 0)
            if close_events > 2:
                return True, f"App reports low latency ({app_metric['latency_ms']:.2f}ms) but kernel shows {close_events} close attempts (hidden connection issues)"
        
        # BLIND SPOT 6: Connection reuse masking issues
        # Kernel shows data transfer without connection establishment
        # (App reused connection but kernel shows connection was problematic)
        if kernel_stats['connections'] == 0 and (bytes_sent > 0 or bytes_recv > 0):
            # This is connection reuse - check if there were problems
            if len(matching_events) > 20:
                return True, "App reused connection (appears fast) but kernel shows excessive events (hidden connection issues)"
        
        # BLIND SPOT 7: High kernel activity despite app success
        # App: "Success, normal operation"
        # Kernel: Excessive send/recv attempts (retries, buffering issues)
        send_count = kernel_stats['event_types'].get('send', 0)
        recv_count = kernel_stats['event_types'].get('recv', 0)
        
        # For a simple HTTP request, expect ~2-4 send/recv events
        if send_count > 10 or recv_count > 10:
            return True, f"App reports success but kernel shows {send_count} sends and {recv_count} receives (excessive system calls indicate inefficiency)"
        
        # No blind spot detected - app and kernel agree
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
        """Categorize TRUE blind spots by type."""
        categories = defaultdict(int)
        for bs in blind_spots:
            if bs.discrepancy_reason:
                if "retransmissions" in bs.discrepancy_reason:
                    categories["Hidden TCP retransmissions"] += 1
                elif "connection attempts" in bs.discrepancy_reason:
                    categories["Multiple connection attempts masked"] += 1
                elif "hidden inefficiency" in bs.discrepancy_reason:
                    categories["Excessive kernel events for fast operation"] += 1
                elif "packet loss" in bs.discrepancy_reason or "no response" in bs.discrepancy_reason:
                    categories["Asymmetric data transfer"] += 1
                elif "protocol anomaly" in bs.discrepancy_reason:
                    categories["Protocol-level anomalies"] += 1
                elif "close attempts" in bs.discrepancy_reason:
                    categories["Hidden connection issues"] += 1
                elif "connection reuse" in bs.discrepancy_reason or "connection issues" in bs.discrepancy_reason:
                    categories["Connection reuse masking problems"] += 1
                elif "excessive system calls" in bs.discrepancy_reason:
                    categories["Inefficient kernel interactions"] += 1
                else:
                    categories["Other kernel-visible issues"] += 1
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