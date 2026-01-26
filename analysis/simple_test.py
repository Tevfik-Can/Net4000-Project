#!/usr/bin/env python3
import time
import threading
import requests
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from bcc import BPF

# -------------------------------
# eBPF program (TCP events)
# -------------------------------
bpf_program = """
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

# Mapping numeric codes to human-readable words
EVENT_TYPE_MAP = {
    1: "connect",
    2: "send",
    3: "recv",
    4: "close"
}

# -------------------------------
# HTTP Server
# -------------------------------
def run_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        def log_message(self, *args): pass

    server = HTTPServer(("127.0.0.1", 8080), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server

# -------------------------------
# Client Requests
# -------------------------------
def run_client_requests(num_requests=10):
    metrics = []
    for i in range(num_requests):
        start = time.time()
        try:
            r = requests.get("http://127.0.0.1:8080", timeout=2)
            latency = (time.time() - start) * 1000
            metrics.append({
                "request_id": i + 1,
                "latency_ms": latency,
                "status_code": r.status_code,
                "success": r.status_code == 200
            })
        except Exception as e:
            latency = (time.time() - start) * 1000
            metrics.append({
                "request_id": i + 1,
                "latency_ms": latency,
                "status_code": None,
                "success": False,
                "error": str(e)
            })
        time.sleep(0.1)
    return metrics

# -------------------------------
# Main
# -------------------------------
def main():
    print("=== Starting HTTP Server ===")
    server = run_server()
    time.sleep(1)  # let server start

    print("=== Loading eBPF program ===")
    b = BPF(text=bpf_program, debug=0)  # suppress warnings

    # Collect eBPF events
    ebpf_events = []

    def handle_event(cpu, data, size):
        e = b["events"].event(data)
        ebpf_events.append({
            "timestamp_ns": e.ts_ns,
            "pid": e.pid,
            "ppid": e.ppid,
            "bytes": e.bytes,
            "event_type": EVENT_TYPE_MAP.get(e.event_type, "unknown"),
            "comm": e.comm.decode(errors="replace")
        })

    b["events"].open_perf_buffer(handle_event)

    # BPF polling thread
    stop_bpf = False
    def poll_bpf():
        while not stop_bpf:
            b.perf_buffer_poll(timeout=100)

    t = threading.Thread(target=poll_bpf)
    t.start()

    # Send HTTP requests
    print("=== Sending HTTP requests ===")
    request_metrics = run_client_requests(num_requests=10)

    # Give BPF a short moment to catch remaining events
    time.sleep(0.5)
    stop_bpf = True
    t.join()

    # Shutdown server
    server.shutdown()
    server.server_close()

    # Compute average latency
    avg_latency = sum(m["latency_ms"] for m in request_metrics) / len(request_metrics)

    # Save results
    output = {
        "application_metrics": request_metrics,
        "ebpf_events": ebpf_events,
        "summary": {
            "total_requests": len(request_metrics),
            "successful_requests": len([m for m in request_metrics if m["success"]]),
            "avg_latency_ms": avg_latency,
            "total_ebpf_events": len(ebpf_events)
        }
    }

    with open("tcp_events_output.json", "w") as f:
        json.dump(output, f, indent=2)

    print("\n=== Summary ===")
    print(f"HTTP requests sent: {len(request_metrics)}")
    print(f"Successful requests: {len([m for m in request_metrics if m['success']])}")
    print(f"Average latency: {avg_latency:.2f} ms")
    print(f"TCP events captured by eBPF: {len(ebpf_events)}")
    print("Detailed events exported to tcp_events_output.json")

if __name__ == "__main__":
    main()
