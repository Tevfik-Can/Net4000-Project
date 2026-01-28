#!/usr/bin/env python3
"""
Instrumented HTTP Server for Testing

This server provides endpoints for testing and includes built-in metrics collection.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import time
import json
import os
import signal
import sys


class InstrumentedHandler(BaseHTTPRequestHandler):
    # Class-level metrics storage
    metrics = {
        "requests": [],
        "start_time": None
    }
    
    def do_GET(self):
        """Handle GET requests with timing."""
        request_start = time.time()
        
        if self.path == '/':
            self._handle_root(request_start)
        elif self.path == '/health':
            self._handle_health(request_start)
        elif self.path == '/metrics':
            self._handle_metrics()
        else:
            self._handle_not_found(request_start)
    
    def _handle_root(self, request_start):
        """Handle root endpoint."""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(b"OK")
        self._record_metric(request_start, 200, self.path)
    
    def _handle_health(self, request_start):
        """Handle health check endpoint."""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        health = {
            "status": "healthy",
            "uptime": time.time() - self.metrics["start_time"],
            "pid": os.getpid()
        }
        self.wfile.write(json.dumps(health).encode())
        self._record_metric(request_start, 200, self.path)
    
    def _handle_metrics(self):
        """Handle metrics endpoint."""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        # Calculate statistics
        total_requests = len(self.metrics["requests"])
        if total_requests > 0:
            latencies = [m["latency_ms"] for m in self.metrics["requests"]]
            stats = {
                "total_requests": total_requests,
                "avg_latency_ms": sum(latencies) / len(latencies),
                "min_latency_ms": min(latencies),
                "max_latency_ms": max(latencies),
                "uptime_seconds": time.time() - self.metrics["start_time"]
            }
        else:
            stats = {"total_requests": 0, "uptime_seconds": time.time() - self.metrics["start_time"]}
        
        self.wfile.write(json.dumps(stats).encode())
    
    def _handle_not_found(self, request_start):
        """Handle 404 errors."""
        self.send_response(404)
        self.end_headers()
        self._record_metric(request_start, 404, self.path)
    
    def _record_metric(self, request_start, status_code, path):
        """Record request metrics."""
        latency_ms = (time.time() - request_start) * 1000
        self.metrics["requests"].append({
            "timestamp": request_start,
            "latency_ms": latency_ms,
            "status_code": status_code,
            "path": path
        })
    
    def log_message(self, format, *args):
        """Minimal logging to reduce overhead."""
        # Only log errors
        if args[1] != '200':
            sys.stderr.write(f"{self.address_string()} - {format % args}\n")


class MetricsServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server = None
        InstrumentedHandler.metrics["start_time"] = time.time()
    
    def start(self):
        """Start the HTTP server."""
        self.server = HTTPServer((self.host, self.port), InstrumentedHandler)
        print(f"Server listening on {self.host}:{self.port}")
        print(f"PID: {os.getpid()}")
        print("Endpoints:")
        print("  GET /         - Root endpoint")
        print("  GET /health   - Health check")
        print("  GET /metrics  - Server metrics")
        print("\nPress Ctrl+C to stop")
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)
        
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._export_metrics()
    
    def _shutdown(self, signum, frame):
        """Graceful shutdown."""
        print("\nShutting down server...")
        if self.server:
            self.server.shutdown()
            self.server.server_close()
    
    def _export_metrics(self):
        """Export metrics on shutdown."""
        output_file = "server_metrics.json"
        with open(output_file, 'w') as f:
            json.dump(InstrumentedHandler.metrics, f, indent=2)
        print(f"Metrics exported to {output_file}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Instrumented HTTP Server")
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    
    args = parser.parse_args()
    
    server = MetricsServer(host=args.host, port=args.port)
    server.start()


if __name__ == '__main__':
    main()
