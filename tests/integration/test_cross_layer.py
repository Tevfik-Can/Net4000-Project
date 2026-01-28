#!/usr/bin/env python3
"""
Cross-Layer Integration Test (FIXED - Synchronized Timestamps)

This test runs the complete cross-layer monitoring stack with proper time synchronization.
"""
import time
import threading
import json
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from http.server import HTTPServer, BaseHTTPRequestHandler
from bcc import BPF
import requests


# eBPF program for TCP monitoring
EBPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <bcc/proto.h>

#define EVT_CONNECT 1
#define EVT_SEND    2
#define EVT_RECV    3
#define EVT_CLOSE   4

struct net_event_t {
    u64 ts_ns;
    u32 pid;
    u32 ppid;
    u32 bytes;
    u8  event_type;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

static __always_inline int submit_event(
    struct pt_regs *ctx,
    u8 event_type,
    u32 bytes
) {
    struct net_event_t e = {};
    struct task_struct *task;

    e.ts_ns = bpf_ktime_get_ns();
    e.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    e.ppid = task->real_parent->tgid;

    e.bytes = bytes;
    e.event_type = event_type;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx) { return submit_event(ctx, EVT_CONNECT, 0); }
int kprobe__tcp_sendmsg(struct pt_regs *ctx)   { u32 size = (u32)PT_REGS_PARM3(ctx); return submit_event(ctx, EVT_SEND, size); }
int kprobe__tcp_recvmsg(struct pt_regs *ctx)   { u32 size = (u32)PT_REGS_PARM3(ctx); return submit_event(ctx, EVT_RECV, size); }
int kprobe__tcp_close(struct pt_regs *ctx)     { return submit_event(ctx, EVT_CLOSE, 0); }
"""

EVENT_TYPE_MAP = {
    1: "connect",
    2: "send",
    3: "recv",
    4: "close"
}


def get_boot_time_offset():
    """
    Calculate the offset between boot time and Unix epoch.
    
    Returns offset in nanoseconds to convert boot time to epoch time.
    """
    # Read system uptime
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.read().split()[0])
    
    # Current epoch time
    current_epoch = time.time()
    
    # Boot time in epoch
    boot_time_epoch = current_epoch - uptime_seconds
    
    # Convert to nanoseconds
    offset_ns = int(boot_time_epoch * 1e9)
    
    return offset_ns


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
                pass  # Suppress logs
        
        self.server = HTTPServer((self.host, self.port), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        print(f"Test server started on {self.host}:{self.port}")
    
    def stop(self):
        """Stop the server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()


class eBPFMonitor:
    """eBPF TCP event monitor with synchronized timestamps."""
    
    def __init__(self):
        self.events = []
        self.bpf = None
        self.running = False
        self.thread = None
        self.boot_time_offset = get_boot_time_offset()
        print(f"Boot time offset: {self.boot_time_offset / 1e9:.3f} seconds")
    
    def start(self):
        """Load eBPF program and start monitoring."""
        print("Loading eBPF program...")
        self.bpf = BPF(text=EBPF_PROGRAM, debug=0)
        
        def handle_event(cpu, data, size):
            e = self.bpf["events"].event(data)
            
            # Convert boot time to epoch time
            timestamp_epoch_ns = e.ts_ns + self.boot_time_offset
            
            self.events.append({
                "timestamp_ns": timestamp_epoch_ns,  # Now in epoch time!
                "timestamp_boot_ns": e.ts_ns,  # Original boot time for reference
                "pid": e.pid,
                "ppid": e.ppid,
                "bytes": e.bytes,
                "event_type": EVENT_TYPE_MAP.get(e.event_type, "unknown"),
                "comm": e.comm.decode(errors="replace")
            })
        
        self.bpf["events"].open_perf_buffer(handle_event)
        
        # Start polling in background
        self.running = True
        def poll_loop():
            while self.running:
                self.bpf.perf_buffer_poll(timeout=100)
        
        self.thread = threading.Thread(target=poll_loop)
        self.thread.start()
        print("eBPF monitoring started")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print(f"eBPF monitoring stopped. Captured {len(self.events)} events")


class LoadGenerator:
    """Simple HTTP load generator with synchronized timestamps."""
    
    def __init__(self, url='http://127.0.0.1:8080'):
        self.url = url
        self.metrics = []
    
    def run(self, num_requests=10, interval_s=0.1):
        """Generate load and collect metrics."""
        print(f"Generating {num_requests} requests...")
        
        for i in range(num_requests):
            # Use monotonic time converted to nanoseconds for start
            start = time.time()
            
            try:
                r = requests.get(self.url, timeout=2)
                end = time.time()
                latency = (end - start) * 1000
                
                self.metrics.append({
                    "request_id": i + 1,
                    "start_time": start,  # Epoch time in seconds
                    "end_time": end,      # Epoch time in seconds
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


def run_test(num_requests=10, output_dir='./results/cross_layer'):
    """
    Run the complete cross-layer monitoring test.
    
    Args:
        num_requests: Number of HTTP requests to make
        output_dir: Directory for output files
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 60)
    print("Cross-Layer Observability Integration Test")
    print("(FIXED - Synchronized Timestamps)")
    print("=" * 60)
    
    # Start HTTP server
    server = TestHTTPServer()
    server.start()
    time.sleep(0.5)  # Let server initialize
    
    # Start eBPF monitoring
    ebpf = eBPFMonitor()
    ebpf.start()
    time.sleep(0.5)  # Let eBPF attach
    
    # Generate load
    load_gen = LoadGenerator()
    load_gen.run(num_requests=num_requests)
    
    # Give eBPF time to capture remaining events
    time.sleep(0.5)
    
    # Stop monitoring
    ebpf.stop()
    server.stop()
    
    # Calculate summary statistics
    app_metrics = load_gen.metrics
    ebpf_events = ebpf.events
    
    successful = len([m for m in app_metrics if m["result"] == "success"])
    avg_latency = sum(m["latency_ms"] for m in app_metrics) / len(app_metrics)
    
    # Verify time synchronization
    print(f"\n=== Time Synchronization Check ===")
    if app_metrics and ebpf_events:
        app_first_ns = int(app_metrics[0]['start_time'] * 1e9)
        app_last_ns = int(app_metrics[-1]['end_time'] * 1e9)
        ebpf_first_ns = ebpf_events[0]['timestamp_ns']
        ebpf_last_ns = ebpf_events[-1]['timestamp_ns']
        
        print(f"App first event:  {app_first_ns}")
        print(f"eBPF first event: {ebpf_first_ns}")
        print(f"Difference: {abs(app_first_ns - ebpf_first_ns) / 1e9:.3f} seconds")
        
        if abs(app_first_ns - ebpf_first_ns) < 10e9:  # Within 10 seconds
            print("✓ Timestamps are synchronized!")
        else:
            print("⚠ Warning: Large time difference detected")
    
    # Export data
    output = {
        "application_metrics": app_metrics,
        "ebpf_events": ebpf_events,
        "summary": {
            "total_requests": len(app_metrics),
            "successful_requests": successful,
            "avg_latency_ms": avg_latency,
            "total_ebpf_events": len(ebpf_events),
            "test_timestamp": time.time(),
            "boot_time_offset_ns": ebpf.boot_time_offset
        }
    }
    
    # Save combined output
    combined_file = f"{output_dir}/test_output.json"
    with open(combined_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    # Save separate files for correlation
    app_file = f"{output_dir}/app_metrics.json"
    with open(app_file, 'w') as f:
        json.dump(app_metrics, f, indent=2)
    
    ebpf_file = f"{output_dir}/ebpf_events.json"
    with open(ebpf_file, 'w') as f:
        json.dump(ebpf_events, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"HTTP requests:         {len(app_metrics)}")
    print(f"Successful requests:   {successful} ({successful/len(app_metrics)*100:.1f}%)")
    print(f"Average latency:       {avg_latency:.2f} ms")
    print(f"TCP events captured:   {len(ebpf_events)}")
    print(f"\nOutput files:")
    print(f"  Combined:   {combined_file}")
    print(f"  App only:   {app_file}")
    print(f"  eBPF only:  {ebpf_file}")
    print("\nNext step: Run correlation analysis")
    print(f"  python3 src/correlation/correlator.py \\")
    print(f"    --app-metrics {app_file} \\")
    print(f"    --ebpf-events {ebpf_file}")
    print("=" * 60)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cross-layer observability integration test (with time sync fix)"
    )
    parser.add_argument(
        '--requests',
        type=int,
        default=10,
        help='Number of HTTP requests to generate'
    )
    parser.add_argument(
        '--output',
        default='./results/cross_layer',
        help='Output directory'
    )
    
    args = parser.parse_args()
    
    try:
        run_test(num_requests=args.requests, output_dir=args.output)
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