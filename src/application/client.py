#!/usr/bin/env python3
"""
HTTP Client Load Generator

Generates HTTP requests and collects application-level metrics.
"""
import requests
import time
import json
import sys
import signal
from typing import List, Dict


class LoadGenerator:
    def __init__(self, server_url: str, interval_ms: int = 200, timeout_ms: int = 5000):
        """
        Initialize the load generator.
        
        Args:
            server_url: Target server URL
            interval_ms: Time between requests in milliseconds
            timeout_ms: Request timeout in milliseconds
        """
        self.server_url = server_url
        self.interval_s = interval_ms / 1000.0
        self.timeout_s = timeout_ms / 1000.0
        self.metrics: List[Dict] = []
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\nStopping load generator...")
        self.running = False
    
    def make_request(self, request_id: int) -> Dict:
        """
        Make a single HTTP request and record metrics.
        
        Args:
            request_id: Unique identifier for this request
            
        Returns:
            Dictionary containing request metrics
        """
        start_time = time.time()
        
        try:
            response = requests.get(
                self.server_url,
                timeout=self.timeout_s
            )
            end_time = time.time()
            latency_ms = (end_time - start_time) * 1000
            
            metric = {
                "request_id": request_id,
                "start_time": start_time,
                "end_time": end_time,
                "latency_ms": latency_ms,
                "result": "success",
                "status_code": response.status_code
            }
            
            print(f"Request {request_id:4d}: {latency_ms:7.2f} ms - HTTP {response.status_code}", 
                  file=sys.stderr)
        
        except requests.exceptions.Timeout:
            end_time = time.time()
            latency_ms = (end_time - start_time) * 1000
            
            metric = {
                "request_id": request_id,
                "start_time": start_time,
                "end_time": end_time,
                "latency_ms": latency_ms,
                "result": "timeout",
                "status_code": None
            }
            
            print(f"Request {request_id:4d}: {latency_ms:7.2f} ms - TIMEOUT", 
                  file=sys.stderr)
        
        except Exception as e:
            end_time = time.time()
            latency_ms = (end_time - start_time) * 1000
            
            metric = {
                "request_id": request_id,
                "start_time": start_time,
                "end_time": end_time,
                "latency_ms": latency_ms,
                "result": f"error",
                "status_code": None,
                "error": str(e)
            }
            
            print(f"Request {request_id:4d}: {latency_ms:7.2f} ms - ERROR: {str(e)}", 
                  file=sys.stderr)
        
        return metric
    
    def run(self, num_requests: int = None, duration_s: int = None):
        """
        Generate load by making repeated requests.
        
        Args:
            num_requests: Number of requests to make (if specified)
            duration_s: Duration to run for in seconds (if specified)
        """
        request_id = 0
        start = time.time()
        
        print(f"Starting load generation to {self.server_url}", file=sys.stderr)
        print(f"Interval: {self.interval_s * 1000:.0f} ms", file=sys.stderr)
        
        while self.running:
            request_id += 1
            
            # Make request and record metrics
            metric = self.make_request(request_id)
            self.metrics.append(metric)
            
            # Check stopping conditions
            if num_requests and request_id >= num_requests:
                break
            
            if duration_s and (time.time() - start) >= duration_s:
                break
            
            # Wait before next request
            time.sleep(self.interval_s)
        
        self._print_summary()
    
    def _print_summary(self):
        """Print summary statistics."""
        if not self.metrics:
            return
        
        total = len(self.metrics)
        successful = len([m for m in self.metrics if m["result"] == "success"])
        timeouts = len([m for m in self.metrics if m["result"] == "timeout"])
        errors = len([m for m in self.metrics if m["result"].startswith("error")])
        
        latencies = [m["latency_ms"] for m in self.metrics]
        avg_latency = sum(latencies) / len(latencies)
        min_latency = min(latencies)
        max_latency = max(latencies)
        
        # Calculate percentiles
        sorted_latencies = sorted(latencies)
        p50 = sorted_latencies[int(len(sorted_latencies) * 0.50)]
        p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
        p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]
        
        print("\n=== Load Generation Summary ===", file=sys.stderr)
        print(f"Total requests:    {total}", file=sys.stderr)
        print(f"Successful:        {successful} ({successful/total*100:.1f}%)", file=sys.stderr)
        print(f"Timeouts:          {timeouts} ({timeouts/total*100:.1f}%)", file=sys.stderr)
        print(f"Errors:            {errors} ({errors/total*100:.1f}%)", file=sys.stderr)
        print(f"\nLatency Statistics:", file=sys.stderr)
        print(f"  Min:     {min_latency:7.2f} ms", file=sys.stderr)
        print(f"  Avg:     {avg_latency:7.2f} ms", file=sys.stderr)
        print(f"  Max:     {max_latency:7.2f} ms", file=sys.stderr)
        print(f"  P50:     {p50:7.2f} ms", file=sys.stderr)
        print(f"  P95:     {p95:7.2f} ms", file=sys.stderr)
        print(f"  P99:     {p99:7.2f} ms", file=sys.stderr)
    
    def export_metrics(self, output_path: str = "client_metrics.json"):
        """Export metrics to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"\nMetrics exported to {output_path}", file=sys.stderr)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="HTTP Load Generator")
    parser.add_argument(
        '--url',
        default='http://127.0.0.1:8080',
        help='Target server URL'
    )
    parser.add_argument(
        '--requests',
        type=int,
        default=10,
        help='Number of requests to make'
    )
    parser.add_argument(
        '--duration',
        type=int,
        help='Duration to run for (seconds)'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=200,
        help='Interval between requests (milliseconds)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=5000,
        help='Request timeout (milliseconds)'
    )
    parser.add_argument(
        '--output',
        default='client_metrics.json',
        help='Output JSON file'
    )
    
    args = parser.parse_args()
    
    generator = LoadGenerator(
        server_url=args.url,
        interval_ms=args.interval,
        timeout_ms=args.timeout
    )
    
    try:
        generator.run(
            num_requests=args.requests if not args.duration else None,
            duration_s=args.duration
        )
    finally:
        generator.export_metrics(args.output)


if __name__ == '__main__':
    main()
