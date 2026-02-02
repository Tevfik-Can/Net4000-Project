#!/usr/bin/env python3
"""
eBPF TCP Event Monitor Runner

This script loads the eBPF program and collects TCP events from the kernel.
It can optionally filter events by PID.
"""
from bcc import BPF
import ctypes
import sys
import json
import signal
from pathlib import Path

EVENT_NAMES = {
    1: "CONNECT",
    2: "SEND",
    3: "RECV",
    4: "CLOSE",
}


class TCPMonitor:
    def __init__(self, ebpf_source_path="tcp_monitor.c", target_pids=None):
        """
        Initialize the TCP monitor.
        
        Args:
            ebpf_source_path: Path to the eBPF C source file
            target_pids: Optional list of PIDs to monitor
        """
        self.ebpf_source = Path(ebpf_source_path)
        if not self.ebpf_source.exists():
            raise FileNotFoundError(f"eBPF source not found: {ebpf_source_path}")
        
        self.bpf = BPF(src_file=str(self.ebpf_source))
        self.events = []
        self.running = True
        
        # Setup target PIDs if provided
        if target_pids:
            for pid in target_pids:
                self.bpf["target_pids"][ctypes.c_uint(pid)] = ctypes.c_ubyte(1)
                print(f"Monitoring PID: {pid}")
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print("\nShutting down...")
        self.running = False
    
    def handle_event(self, cpu, data, size):
        """Process incoming eBPF events."""
        class Event(ctypes.Structure):
            _fields_ = [
                ("ts_ns", ctypes.c_ulonglong),
                ("pid", ctypes.c_uint),
                ("ppid", ctypes.c_uint),
                ("bytes", ctypes.c_uint),
                ("event_type", ctypes.c_ubyte),
                ("comm", ctypes.c_char * 16),
            ]
        
        e = ctypes.cast(data, ctypes.POINTER(Event)).contents
        
        event_data = {
            "timestamp_ns": e.ts_ns,
            "pid": e.pid,
            "ppid": e.ppid,
            "bytes": e.bytes,
            "event_type": EVENT_NAMES.get(e.event_type, "UNKNOWN"),
            "comm": e.comm.decode('utf-8', errors='replace')
        }
        
        self.events.append(event_data)
        
        # Print to console
        print(
            f"{e.ts_ns} | "
            f"{EVENT_NAMES.get(e.event_type, 'UNKNOWN'):8s} | "
            f"PID={e.pid:6d} ({e.comm.decode('utf-8', errors='replace'):16s}) | "
            f"bytes={e.bytes:6d}"
        )
    
    def start(self):
        """Start monitoring TCP events."""
        self.bpf["events"].open_perf_buffer(self.handle_event)
        print("Monitoring TCP activity (Ctrl-C to stop)...")
        
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
    
    def export_events(self, output_path="tcp_events.json"):
        """Export collected events to JSON."""
        with open(output_path, 'w') as f:
            json.dump(self.events, f, indent=2)
        print(f"Exported {len(self.events)} events to {output_path}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="eBPF TCP Event Monitor")
    parser.add_argument(
        '--pids',
        type=int,
        nargs='+',
        help='PIDs to monitor (optional)'
    )
    parser.add_argument(
        '--output',
        default='tcp_events.json',
        help='Output JSON file (default: tcp_events.json)'
    )
    parser.add_argument(
        '--source',
        default='tcp_monitor.c',
        help='eBPF source file (default: tcp_monitor.c)'
    )
    
    args = parser.parse_args()
    
    try:
        monitor = TCPMonitor(
            ebpf_source_path=args.source,
            target_pids=args.pids
        )
        monitor.start()
        monitor.export_events(args.output)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
