#!/usr/bin/env python3
"""
Application-Only Monitoring Test
(For baseline comparison against cross-layer monitoring)
"""
import time
import threading
import json
import sys
import os
from pathlib import Path
import argparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from http.server import HTTPServer, BaseHTTPRequestHandler
import requests


class TestHTTPServer:
    """Minimal HTTP server for testing."""
    
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.server = None
    
    def start(self):
        """Start server in background thread."""
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            
            def log_message(self, *args):
                pass
        
        self.server = HTTPServer((self.host, self.port), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        print(f"Test server started on {self.host}:{self.port}")
    
    def stop(self):
        """Stop the server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()


class LoadGenerator:
    """HTTP load generator (app-only, no eBPF)."""
    
    def __init__(self, url='http://127.0.0.1:8080'):
        self.url = url
        self.metrics = []
    
    def run(self, num_requests=10, interval_s=0.1):
        """Generate load and collect app-only metrics."""
        print(f"Generating {num_requests} requests (APP-ONLY)...")
        
        for i in range(num_requests):
            start = time.time()
            
            try:
                r = requests.get(self.url, timeout=2)
                end = time.time()
                latency = (end - start) * 1000
                
                self.metrics.append({
                    "request_id": i + 1,
                    "start_time": start,
                    "end_time": end,
                    "latency_ms": latency,
                    "status_code": r.status_code,
                    "result": "success" if r.status_code == 200 else "error"
                })
            except Exception as e:
                end = time.time()
                latency = (end - start) * 1000
                
                self.metrics.append({
                    "request_id": i + 1,
                    "start_time": start,
                    "end_time": end,
                    "latency_ms": latency,
                    "status_code": None,
                    "result": "error",
                    "error": str(e)
                })
            
            time.sleep(interval_s)
        
        print(f"Load generation complete")


def run_app_only_test(num_requests=10, output_dir='./results/baseline'):
    """
    Run application-only monitoring test.
    
    Args:
        num_requests: Number of HTTP requests to make
        output_dir: Directory for output files
    """
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 60)
    print("Application-Only Monitoring Test (Baseline)")
    print("=" * 60)
    
    # Start HTTP server
    server = TestHTTPServer()
    server.start()
    time.sleep(0.5)
    
    # Generate load (NO eBPF)
    load_gen = LoadGenerator()
    load_gen.run(num_requests=num_requests)
    
    # Stop server
    server.stop()
    
    # Calculate statistics
    app_metrics = load_gen.metrics
    successful = len([m for m in app_metrics if m["result"] == "success"])
    avg_latency = sum(m["latency_ms"] for m in app_metrics) / len(app_metrics)
    
    # Export app-only metrics
    output_file = f"{output_dir}/app_only_baseline.json"
    with open(output_file, 'w') as f:
        json.dump({
            "application_metrics": app_metrics,
            "summary": {
                "total_requests": len(app_metrics),
                "successful_requests": successful,
                "avg_latency_ms": avg_latency,
                "test_type": "app_only_baseline",
                "test_timestamp": time.time()
            }
        }, f, indent=2)
    
    # Also save just the metrics for correlator
    metrics_file = f"{output_dir}/app_metrics_baseline.json"
    with open(metrics_file, 'w') as f:
        json.dump(app_metrics, f, indent=2)
    
    print(f"\nApp-only test complete:")
    print(f"  Requests:     {len(app_metrics)}")
    print(f"  Successful:   {successful} ({successful/len(app_metrics)*100:.1f}%)")
    print(f"  Avg latency:  {avg_latency:.2f} ms")
    print(f"\nOutput files:")
    print(f"  Baseline:    {output_file}")
    print(f"  Metrics:     {metrics_file}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Application-only monitoring test (baseline)"
    )
    parser.add_argument(
        '--requests',
        type=int,
        default=10,
        help='Number of HTTP requests to generate'
    )
    parser.add_argument(
        '--output',
        default='./results/baseline',
        help='Output directory'
    )
    
    args = parser.parse_args()
    
    try:
        run_app_only_test(num_requests=args.requests, output_dir=args.output)
    except KeyboardInterrupt:
        print("\nTest interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()