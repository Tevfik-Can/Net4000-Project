#!/usr/bin/env python3

import os
import sys
import time
import json
import threading
import argparse
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from bcc import BPF

EBPF_PROGRAM_ENHANCED = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define EVT_CONNECT     1
#define EVT_SEND        2
#define EVT_RECV        3
#define EVT_CLOSE       4
#define EVT_RETRANSMIT  5
#define EVT_TIMEOUT     7

struct tcp_event_t {
    u64 ts_ns;
    u32 pid;
    u32 ppid;
    u64 bytes;
    u32 event_type;
    u32 retries;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

static int submit_event(struct pt_regs *ctx, u32 event_type, u64 bytes, u32 retries) {
    struct tcp_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid >> 32;
    event.ppid = pid_tgid & 0xFFFFFFFF;
    event.bytes = bytes;
    event.event_type = event_type;
    event.retries = retries;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    return submit_event(ctx, EVT_CONNECT, 0, 0);
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    return submit_event(ctx, EVT_SEND, size, 0);
}

int kretprobe__tcp_recvmsg(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        return submit_event(ctx, EVT_RECV, ret, 0);
    }
    return 0;
}

int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk, long timeout) {
    return submit_event(ctx, EVT_CLOSE, 0, 0);
}

int kprobe__tcp_retransmit_skb(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret == 0) {
        return submit_event(ctx, EVT_RETRANSMIT, 0, 1);
    }
    return 0;
}

int kprobe__tcp_write_timer_handler(struct pt_regs *ctx) {
    return submit_event(ctx, EVT_TIMEOUT, 0, 0);
}
"""

EVENT_TYPE_MAP = {
    1: "connect",
    2: "send",
    3: "recv",
    4: "close",
    5: "retransmit",
    7: "timeout"
}

def get_boot_time_offset():
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.read().split()[0])
    current_epoch = time.time()
    boot_time_epoch = current_epoch - uptime_seconds
    offset_ns = int(boot_time_epoch * 1e9)
    return offset_ns


class TestHTTPServer:
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.server = None

    def start(self):
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
        if self.server:
            self.server.shutdown()
            self.server.server_close()


class eBPFMonitor:
    def __init__(self):
        self.events = []
        self.bpf = None
        self.running = False
        self.thread = None
        self.boot_time_offset = get_boot_time_offset()
        self.attached_kprobes = []
        print(f"Boot time offset: {self.boot_time_offset / 1e9:.3f} seconds")

    def start(self):
        print("Loading eBPF program...")
        
        try:
            self.bpf = BPF(text=EBPF_PROGRAM_ENHANCED, debug=0)
        except Exception as e:
            print(f"ERROR: Failed to compile BPF program: {e}")
            raise
        
        kprobes_to_attach = [
            ('tcp_v4_connect', False, 'kprobe__tcp_v4_connect', 'Connection'),
            ('tcp_sendmsg', False, 'kprobe__tcp_sendmsg', 'Send'),
            ('tcp_recvmsg', True, 'kretprobe__tcp_recvmsg', 'Receive'),
            ('tcp_close', False, 'kprobe__tcp_close', 'Close'),
            ('tcp_retransmit_skb', False, 'kprobe__tcp_retransmit_skb', 'Retransmit'),
            ('tcp_write_timer_handler', False, 'kprobe__tcp_write_timer_handler', 'Timeout'),
        ]
        
        print("\n=== Attaching Kprobes ===")
        for kernel_fn, is_retprobe, fn_name, description in kprobes_to_attach:
            try:
                if is_retprobe:
                    self.bpf.attach_kretprobe(event=kernel_fn, fn_name=fn_name)
                else:
                    self.bpf.attach_kprobe(event=kernel_fn, fn_name=fn_name)
                print(f"  ✓ {description:30s} ({kernel_fn})")
                self.attached_kprobes.append(kernel_fn)
            except Exception as e:
                print(f"  ✗ {description:30s} ({kernel_fn}) - {e}")
        
        if not self.attached_kprobes:
            raise Exception("Failed to attach any kprobes!")
        
        print(f"\nSuccessfully attached {len(self.attached_kprobes)} kprobes")
        
        def handle_event(cpu, data, size):
            e = self.bpf["events"].event(data)
            timestamp_epoch_ns = e.ts_ns + self.boot_time_offset
            
            self.events.append({
                "timestamp_ns": timestamp_epoch_ns,
                "timestamp_boot_ns": e.ts_ns,
                "pid": e.pid,
                "ppid": e.ppid,
                "bytes": e.bytes,
                "event_type": EVENT_TYPE_MAP.get(e.event_type, "unknown"),
                "retries": e.retries,
                "comm": e.comm.decode(errors="replace")
            })
        
        self.bpf["events"].open_perf_buffer(handle_event)
        self.running = True
        
        def poll_loop():
            while self.running:
                self.bpf.perf_buffer_poll(timeout=100)
        
        self.thread = threading.Thread(target=poll_loop)
        self.thread.start()
        print("eBPF monitoring started\n")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print(f"eBPF monitoring stopped. Captured {len(self.events)} events")


class LoadGenerator:
    def __init__(self, url='http://127.0.0.1:8080'):
        self.url = url
        self.metrics = []

    def run(self, num_requests=10, interval_s=0.1):
        print(f"Generating {num_requests} requests...")
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


def analyze_blindspots(app_metrics, ebpf_events):
    print("\n" + "=" * 60)
    print("BLINDSPOT ANALYSIS")
    print("=" * 60)
    
    event_counts = {}
    for event in ebpf_events:
        event_type = event['event_type']
        event_counts[event_type] = event_counts.get(event_type, 0) + 1
    
    print("\neBPF Event Distribution:")
    for event_type, count in sorted(event_counts.items()):
        print(f"  {event_type:15s}: {count:5d}")
    
    total_requests = len(app_metrics)
    successful = len([m for m in app_metrics if m['result'] == 'success'])
    failed = total_requests - successful
    
    print(f"\nApplication Metrics:")
    print(f"  Total requests:  {total_requests}")
    print(f"  Successful:      {successful}")
    print(f"  Failed:          {failed}")
    
    blindspots = []
    
    retransmit_count = event_counts.get('retransmit', 0)
    if retransmit_count > 0 and successful > 0:
        blindspots.append({
            "type": "HIDDEN_RETRANSMISSIONS",
            "severity": "MEDIUM",
            "description": f"eBPF detected {retransmit_count} retransmissions, but application reported {successful} successful requests",
            "impact": "Network issues not visible to application layer"
        })
    
    timeout_count = event_counts.get('timeout', 0)
    if timeout_count > 0:
        blindspots.append({
            "type": "KERNEL_TIMEOUTS",
            "severity": "HIGH",
            "description": f"eBPF detected {timeout_count} kernel-level timeouts",
            "impact": "Connection delays not visible at application layer"
        })
    
    if app_metrics:
        latencies = [m['latency_ms'] for m in app_metrics]
        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        
        if max_latency > 100:
            blindspots.append({
                "type": "HIGH_LATENCY",
                "severity": "MEDIUM",
                "description": f"Maximum latency: {max_latency:.2f}ms (avg: {avg_latency:.2f}ms)",
                "impact": "Performance degradation may indicate network issues"
            })
    
    expected_events_per_request = 4
    expected_total = total_requests * expected_events_per_request
    actual_total = len(ebpf_events)
    
    if actual_total < expected_total * 0.8:
        blindspots.append({
            "type": "MISSING_EVENTS",
            "severity": "MEDIUM",
            "description": f"Expected ~{expected_total} events, got {actual_total}",
            "impact": "Some TCP events not captured by eBPF"
        })
    
    if blindspots:
        print(f"\n{'='*60}")
        print(f"DETECTED {len(blindspots)} BLINDSPOT(S)")
        print("=" * 60)
        
        for i, bs in enumerate(blindspots, 1):
            print(f"\n[{i}] {bs['type']} (Severity: {bs['severity']})")
            print(f"    {bs['description']}")
            print(f"    Impact: {bs['impact']}")
    else:
        print("\n✓ No significant blindspots detected")
    
    return blindspots


def run_test(num_requests=10, output_dir='./results/cross_layer'):
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 60)
    print("Cross-Layer Observability Integration Test")
    print("(WSL2 Optimized - Working Kprobes Only)")
    print("=" * 60)
    
    server = TestHTTPServer()
    server.start()
    time.sleep(0.5)
    
    ebpf = eBPFMonitor()
    ebpf.start()
    time.sleep(0.5)
    
    load_gen = LoadGenerator()
    load_gen.run(num_requests=num_requests)
    
    time.sleep(0.5)
    
    ebpf.stop()
    server.stop()
    
    app_metrics = load_gen.metrics
    ebpf_events = ebpf.events
    
    print(f"\n=== Time Synchronization Check ===")
    if app_metrics and ebpf_events:
        app_first_ns = int(app_metrics[0]['start_time'] * 1e9)
        ebpf_first_ns = ebpf_events[0]['timestamp_ns']
        diff_s = abs(app_first_ns - ebpf_first_ns) / 1e9
        
        print(f"App first event:  {app_first_ns}")
        print(f"eBPF first event: {ebpf_first_ns}")
        print(f"Difference: {diff_s:.3f} seconds")
        
        if diff_s < 10:
            print("✓ Timestamps are synchronized!")
        else:
            print("⚠ Warning: Large time difference detected")
    
    blindspots = analyze_blindspots(app_metrics, ebpf_events)
    
    successful = len([m for m in app_metrics if m["result"] == "success"])
    avg_latency = sum(m["latency_ms"] for m in app_metrics) / len(app_metrics) if app_metrics else 0
    
    output = {
        "application_metrics": app_metrics,
        "ebpf_events": ebpf_events,
        "blindspots": blindspots,
        "attached_kprobes": ebpf.attached_kprobes,
        "summary": {
            "total_requests": len(app_metrics),
            "successful_requests": successful,
            "avg_latency_ms": avg_latency,
            "total_ebpf_events": len(ebpf_events),
            "blindspots_count": len(blindspots),
            "test_timestamp": time.time(),
            "boot_time_offset_ns": ebpf.boot_time_offset
        }
    }
    
    combined_file = f"{output_dir}/test_output.json"
    with open(combined_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    app_file = f"{output_dir}/app_metrics.json"
    with open(app_file, 'w') as f:
        json.dump(app_metrics, f, indent=2)
    
    ebpf_file = f"{output_dir}/ebpf_events.json"
    with open(ebpf_file, 'w') as f:
        json.dump(ebpf_events, f, indent=2)
    
    blindspots_file = f"{output_dir}/blindspots.json"
    with open(blindspots_file, 'w') as f:
        json.dump(blindspots, f, indent=2)
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"HTTP requests:         {len(app_metrics)}")
    print(f"Successful requests:   {successful} ({successful/len(app_metrics)*100:.1f}%)")
    print(f"Average latency:       {avg_latency:.2f} ms")
    print(f"TCP events captured:   {len(ebpf_events)}")
    print(f"Kprobes attached:      {len(ebpf.attached_kprobes)}")
    print(f"Blindspots detected:   {len(blindspots)}")
    
    print(f"\nOutput files:")
    print(f"  Combined:   {combined_file}")
    print(f"  App only:   {app_file}")
    print(f"  eBPF only:  {ebpf_file}")
    print(f"  Blindspots: {blindspots_file}")
    
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Cross-layer observability integration test (WSL2 optimized)"
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