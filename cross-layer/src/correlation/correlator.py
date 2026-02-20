import json
from typing import List, Dict, Tuple
from dataclasses import dataclass
from collections import defaultdict
import sys

@dataclass
class CorrelatedEvent:
    request_id: int
    app_latency_ms: float
    app_status_code: int
    kernel_total_bytes_sent: int
    kernel_total_bytes_recv: int
    kernel_connection_events: int
    kernel_event_count: int
    discrepancy_detected: bool
    discrepancy_reason: str = None


class CrossLayerCorrelator:
    def __init__(self, time_window_ms: float = 50.0, debug: bool = False):
        self.time_window_ns = time_window_ms * 1_000_000
        self.correlations: List[CorrelatedEvent] = []
        self.debug = debug

    def load_app_metrics(self, filepath: str) -> List[Dict]:
        with open(filepath, 'r') as f:
            return json.load(f)

    def load_ebpf_events(self, filepath: str) -> List[Dict]:
        with open(filepath, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict) and 'ebpf_events' in data:
                return data['ebpf_events']
            return data

    def correlate(self, app_metrics: List[Dict], ebpf_events: List[Dict]) -> List[CorrelatedEvent]:
        self.correlations = []

        if self.debug:
            print(f"\n=== Debug Info ===")
            print(f"Total app metrics: {len(app_metrics)}")
            print(f"Total eBPF events: {len(ebpf_events)}")
            if ebpf_events:
                print(f"\nSample eBPF event:")
                print(json.dumps(ebpf_events[0], indent=2))
                timestamps = [e['timestamp_ns'] for e in ebpf_events]
                print(f"\neBPF time range:")
                print(f"  First: {min(timestamps)}")
                print(f"  Last:  {max(timestamps)}")
                print(f"  Span:  {(max(timestamps) - min(timestamps)) / 1e9:.2f} seconds")
            if app_metrics:
                print(f"\nSample app metric:")
                print(json.dumps(app_metrics[0], indent=2))
                start_times = [m['start_time'] for m in app_metrics]
                print(f"\nApp time range:")
                print(f"  First: {min(start_times)}")
                print(f"  Last:  {max(start_times)}")
                print(f"  Span:  {max(start_times) - min(start_times):.2f} seconds")

        for metric in app_metrics:
            start_ns = int(metric['start_time'] * 1_000_000_000)
            end_ns   = int(metric['end_time']   * 1_000_000_000)

            matching_events = self._find_matching_events(ebpf_events, start_ns, end_ns)
            kernel_stats    = self._analyze_kernel_events(matching_events)
            discrepancy, reason = self._detect_discrepancy(metric, kernel_stats, matching_events)

            if self.debug and metric['request_id'] <= 3:
                print(f"\n--- Request {metric['request_id']} ---")
                print(f"App time: {start_ns} to {end_ns}")
                print(f"Matched {len(matching_events)} kernel events")
                print(f"Bytes sent: {kernel_stats['bytes_sent']}, recv: {kernel_stats['bytes_recv']}")
                if matching_events:
                    print(f"Sample matched event: {matching_events[0]}")

            correlated = CorrelatedEvent(
                request_id=metric['request_id'],
                app_latency_ms=metric['latency_ms'],
                app_status_code=metric.get('status_code'),
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
        window_start = start_ns - self.time_window_ns
        window_end   = end_ns   + self.time_window_ns
        return [e for e in ebpf_events if window_start <= e['timestamp_ns'] <= window_end]

    def _analyze_kernel_events(self, events: List[Dict]) -> Dict:
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
        if len(matching_events) == 0:
            return False, None

        app_success = (app_metric.get('result') == 'success' or
                       app_metric.get('status_code') == 200)
        if not app_success:
            return False, None

        retransmit_events = [e for e in matching_events if e.get('event_type') == 'retransmit']
        if retransmit_events:
            return True, (
                f"App reports success but kernel detected "
                f"{len(retransmit_events)} TCP retransmission(s) — hidden network issue"
            )

        bytes_sent = kernel_stats['bytes_sent']
        bytes_recv = kernel_stats['bytes_recv']
        if bytes_sent > 2000 and bytes_recv == 0:
            return True, (
                f"App reports success but kernel shows {bytes_sent} bytes sent "
                f"with no data received — potential packet loss"
            )

        send_count = kernel_stats['event_types'].get('send', 0)
        recv_count = kernel_stats['event_types'].get('recv', 0)
        latency_ms = app_metric['latency_ms']
        if latency_ms < 5 and (send_count + recv_count) > 30:
            return True, (
                f"App reports {latency_ms:.2f}ms latency but kernel shows "
                f"{send_count + recv_count} send/recv events — hidden fragmentation "
                f"or inefficiency"
            )

        return False, None

    def get_blind_spots(self) -> List[CorrelatedEvent]:
        return [c for c in self.correlations if c.discrepancy_detected]

    def export_correlations(self, output_path: str = "correlations.json"):
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
                }
                for c in self.correlations
            ]
        }
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\nExported {len(self.correlations)} correlations to {output_path}")
        print(f"Blind spots detected: {len(blind_spots)}")
        if blind_spots:
            print(f"\nBlind spot categories:")
            for category, count in data['blind_spot_types'].items():
                print(f"  {category}: {count}")

    def _categorize_blind_spots(self, blind_spots: List[CorrelatedEvent]) -> Dict[str, int]:
        categories = defaultdict(int)
        for bs in blind_spots:
            if bs.discrepancy_reason:
                if "retransmission" in bs.discrepancy_reason:
                    categories["Hidden TCP retransmissions"] += 1
                elif "packet loss" in bs.discrepancy_reason:
                    categories["Asymmetric data transfer"] += 1
                elif "fragmentation" in bs.discrepancy_reason:
                    categories["Hidden fragmentation or inefficiency"] += 1
                else:
                    categories["Other kernel-visible issues"] += 1
        return dict(categories)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Cross-layer event correlator")
    parser.add_argument('--app-metrics', required=True, help='Application metrics JSON file')
    parser.add_argument('--ebpf-events', required=True, help='eBPF events JSON file')
    parser.add_argument('--output', default='correlations.json', help='Output file for correlations')
    parser.add_argument('--time-window', type=float, default=50.0, help='Time window for correlation (milliseconds)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    correlator = CrossLayerCorrelator(time_window_ms=args.time_window, debug=args.debug)

    print(f"Loading application metrics from {args.app_metrics}")
    app_metrics = correlator.load_app_metrics(args.app_metrics)

    print(f"Loading eBPF events from {args.ebpf_events}")
    ebpf_events = correlator.load_ebpf_events(args.ebpf_events)

    print(f"Correlating {len(app_metrics)} requests with {len(ebpf_events)} kernel events...")
    correlations = correlator.correlate(app_metrics, ebpf_events)

    print(f"\nCorrelation complete:")
    print(f"  Total requests: {len(correlations)}")
    print(f"  Blind spots detected: {len(correlator.get_blind_spots())}")

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
