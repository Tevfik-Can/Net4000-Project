#!/usr/bin/env python3
import time
import threading
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from bcc import BPF

# -------------------------------
# eBPF program (network TCP probe)
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

/* TCP connection start */
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
    return submit_event(ctx, EVT_CONNECT, 0);
}

/* Data sent */
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    u32 size = (u32)PT_REGS_PARM3(ctx);
    return submit_event(ctx, EVT_SEND, size);
}

/* Data received */
int kprobe__tcp_recvmsg(struct pt_regs *ctx) {
    u32 size = (u32)PT_REGS_PARM3(ctx);
    return submit_event(ctx, EVT_RECV, size);
}

/* Connection close */
int kprobe__tcp_close(struct pt_regs *ctx) {
    return submit_event(ctx, EVT_CLOSE, 0);
}
"""

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
            latency = (time.time() - start) * 1000  # in ms
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
    time.sleep(1)  # Give server a moment to start

    print("=== Loading eBPF program ===")
    b = BPF(text=bpf_program, debug=0)  # debug=0 suppresses warnings

    # TCP event counters
    event_counts = {"connect": 0, "send": 0, "recv": 0, "close": 0}

    # Callback for perf buffer
    def handle_event(cpu, data, size):
        e = b["events"].event(data)
        if e.event_type == 1:
            event_counts["connect"] += 1
        elif e.event_type == 2:
            event_counts["send"] += 1
        elif e.event_type == 3:
            event_counts["recv"] += 1
        elif e.event_type == 4:
            event_counts["close"] += 1

    b["events"].open_perf_buffer(handle_event)

    # Poll BPF events in a background thread
    stop_bpf = False
    def poll_bpf():
        while not stop_bpf:
            b.perf_buffer_poll(timeout=100)

    t = threading.Thread(target=poll_bpf)
    t.start()

    # Run client HTTP requests
    print("=== Sending HTTP requests ===")
    request_metrics = run_client_requests(num_requests=10)

    # Give BPF a short moment to catch remaining events
    time.sleep(0.5)
    stop_bpf = True
    t.join()

    # Shutdown HTTP server
    server.shutdown()
    server.server_close()

    # Compute average latency
    avg_latency = sum(m["latency_ms"] for m in request_metrics) / len(request_metrics)

    # Summary output
    print("\n=== Summary ===")
    print(f"HTTP requests sent: {len(request_metrics)}")
    print(f"Successful requests: {len([m for m in request_metrics if m['success']])}")
    print(f"Average latency: {avg_latency:.2f} ms")
    print(f"TCP events captured by eBPF: {sum(event_counts.values())}")
    print(f"Event breakdown: {event_counts}")

if __name__ == "__main__":
    main()
