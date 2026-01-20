#!/usr/bin/env python3
"""
Simple all-in-one test script
"""
import json
import subprocess
import time
import requests
from threading import Thread
import sys

def run_server():
    """Run HTTP server in background"""
    cmd = ['python3', '-c', '''
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def log_message(self, *args): pass
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
''']
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_ebpf_monitor(duration=15):
    """Run eBPF monitor"""
    cmd = ['sudo', 'timeout', str(duration), 'tcpconnect-bpfcc', '-t']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(2)  # Let it start
    return proc

def run_client_requests():
    """Make HTTP requests"""
    metrics = []
    for i in range(1, 11):
        start = time.time()
        try:
            r = requests.get('http://127.0.0.1:8080', timeout=2)
            latency = (time.time() - start) * 1000
            metrics.append({
                'request_id': i,
                'latency_ms': latency,
                'result': 'success' if r.status_code == 200 else 'error',
                'status_code': r.status_code
            })
            print(f'Request {i}: {latency:.2f} ms - success')
        except Exception as e:
            latency = (time.time() - start) * 1000
            metrics.append({
                'request_id': i,
                'latency_ms': latency,
                'result': f'error: {str(e)}',
                'status_code': None
            })
            print(f'Request {i}: {latency:.2f} ms - error')
        time.sleep(0.2)
    return metrics

def main():
    print("=== Simple Cross-Layer Test ===")
    
    # Start server
    print("1. Starting server...")
    server = run_server()
    time.sleep(3)
    
    # Start eBPF monitor
    print("2. Starting eBPF monitor...")
    ebpf = run_ebpf_monitor()
    
    # Run client requests
    print("3. Making HTTP requests...")
    app_metrics = run_client_requests()
    
    # Collect eBPF output
    print("4. Collecting eBPF data...")
    ebpf_output, _ = ebpf.communicate()
    ebpf_events = []
    for line in ebpf_output.split('\n'):
        if line.strip() and 'TIME(s)' not in line:
            ebpf_events.append({'data': line.strip()})
    
    # Stop server
    print("5. Stopping server...")
    server.terminate()
    
    # Save results
    data = {
        'application_metrics': app_metrics,
        'ebpf_metrics': ebpf_events,
        'summary': {
            'total_requests': len(app_metrics),
            'successful': len([m for m in app_metrics if m['result'] == 'success']),
            'avg_latency': sum(m['latency_ms'] for m in app_metrics) / len(app_metrics),
            'ebpf_events': len(ebpf_events)
        }
    }
    
    with open('simple_cross_layer.json', 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n=== Results ===")
    print(f"Requests: {len(app_metrics)}")
    print(f"Successful: {data['summary']['successful']}")
    print(f"Avg Latency: {data['summary']['avg_latency']:.2f} ms")
    print(f"eBPF Events: {len(ebpf_events)}")
    
    if ebpf_events:
        print(f"\nSample eBPF events:")
        for event in ebpf_events[:3]:
            print(f"  {event['data']}")
    
    print(f"\nData saved to simple_cross_layer.json")

if __name__ == "__main__":
    main()
