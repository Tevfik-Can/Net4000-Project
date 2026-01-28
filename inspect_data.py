#!/usr/bin/env python3
"""
Data Inspector - Debug correlation issues

This script helps diagnose why correlation isn't working properly.
"""
import json
import sys

def inspect_data(app_file, ebpf_file):
    """Inspect the data files to understand the correlation issue."""
    
    print("=" * 70)
    print("DATA INSPECTION REPORT")
    print("=" * 70)
    
    # Load data
    with open(app_file) as f:
        app_data = json.load(f)
    
    with open(ebpf_file) as f:
        ebpf_data = json.load(f)
        if isinstance(ebpf_data, dict) and 'ebpf_events' in ebpf_data:
            ebpf_events = ebpf_data['ebpf_events']
        else:
            ebpf_events = ebpf_data
    
    print(f"\n1. DATA OVERVIEW")
    print(f"   App metrics:  {len(app_data)} requests")
    print(f"   eBPF events:  {len(ebpf_events)} events")
    
    # Sample app metric
    print(f"\n2. SAMPLE APP METRIC (Request 1)")
    print(json.dumps(app_data[0], indent=4))
    
    # Sample eBPF event
    print(f"\n3. SAMPLE EBPF EVENT")
    print(json.dumps(ebpf_events[0], indent=4))
    
    # Time analysis
    print(f"\n4. TIME RANGE ANALYSIS")
    
    app_start_times = [m['start_time'] for m in app_data]
    app_end_times = [m['end_time'] for m in app_data]
    app_first = min(app_start_times)
    app_last = max(app_end_times)
    
    print(f"   Application:")
    print(f"     First request start: {app_first}")
    print(f"     Last request end:    {app_last}")
    print(f"     Duration:            {app_last - app_first:.3f} seconds")
    
    ebpf_timestamps = [e['timestamp_ns'] for e in ebpf_events]
    ebpf_first = min(ebpf_timestamps)
    ebpf_last = max(ebpf_timestamps)
    ebpf_first_sec = ebpf_first / 1e9
    ebpf_last_sec = ebpf_last / 1e9
    
    print(f"   eBPF (in nanoseconds):")
    print(f"     First event: {ebpf_first}")
    print(f"     Last event:  {ebpf_last}")
    print(f"     Duration:    {(ebpf_last - ebpf_first) / 1e9:.3f} seconds")
    
    print(f"   eBPF (converted to seconds since epoch):")
    print(f"     First event: {ebpf_first_sec}")
    print(f"     Last event:  {ebpf_last_sec}")
    
    # Check if times overlap
    app_first_ns = app_first * 1e9
    app_last_ns = app_last * 1e9
    
    print(f"\n5. TIME OVERLAP CHECK")
    if ebpf_first > app_last_ns:
        print(f"   ⚠ WARNING: eBPF events start AFTER app requests end")
        print(f"   Gap: {(ebpf_first - app_last_ns) / 1e9:.3f} seconds")
    elif ebpf_last < app_first_ns:
        print(f"   ⚠ WARNING: eBPF events end BEFORE app requests start")
        print(f"   Gap: {(app_first_ns - ebpf_last) / 1e9:.3f} seconds")
    else:
        print(f"   ✓ Times overlap - correlation should be possible")
    
    # PID analysis
    print(f"\n6. PROCESS ID (PID) ANALYSIS")
    pids_in_ebpf = set(e['pid'] for e in ebpf_events)
    print(f"   PIDs in eBPF events: {sorted(pids_in_ebpf)}")
    print(f"   Unique PIDs: {len(pids_in_ebpf)}")
    
    # Event type distribution
    print(f"\n7. EBPF EVENT TYPE DISTRIBUTION")
    from collections import Counter
    event_types = Counter(e['event_type'] for e in ebpf_events)
    for event_type, count in event_types.most_common():
        print(f"   {event_type:10s}: {count:4d} events")
    
    # Byte transfer analysis
    print(f"\n8. DATA TRANSFER ANALYSIS")
    total_bytes_sent = sum(e['bytes'] for e in ebpf_events if e['event_type'] == 'send')
    total_bytes_recv = sum(e['bytes'] for e in ebpf_events if e['event_type'] == 'recv')
    print(f"   Total bytes sent: {total_bytes_sent}")
    print(f"   Total bytes recv: {total_bytes_recv}")
    
    send_events = [e for e in ebpf_events if e['event_type'] == 'send']
    recv_events = [e for e in ebpf_events if e['event_type'] == 'recv']
    
    if send_events:
        send_bytes = [e['bytes'] for e in send_events]
        print(f"   Send events with bytes > 0: {sum(1 for b in send_bytes if b > 0)}")
        print(f"   Send events with bytes = 0: {sum(1 for b in send_bytes if b == 0)}")
    
    if recv_events:
        recv_bytes = [e['bytes'] for e in recv_events]
        print(f"   Recv events with bytes > 0: {sum(1 for b in recv_bytes if b > 0)}")
        print(f"   Recv events with bytes = 0: {sum(1 for b in recv_bytes if b == 0)}")
    
    # Correlation simulation for first request
    print(f"\n9. CORRELATION SIMULATION (Request 1)")
    first_req = app_data[0]
    start_ns = int(first_req['start_time'] * 1e9)
    end_ns = int(first_req['end_time'] * 1e9)
    
    # Try different time windows
    for window_ms in [100, 500, 1000, 5000]:
        window_ns = window_ms * 1_000_000
        window_start = start_ns - window_ns
        window_end = end_ns + window_ns
        
        matching = [e for e in ebpf_events if window_start <= e['timestamp_ns'] <= window_end]
        print(f"   Window ±{window_ms}ms: {len(matching)} matching events")
        
        if matching and window_ms == 500:  # Show details for 500ms window
            types = Counter(e['event_type'] for e in matching)
            print(f"      Event types: {dict(types)}")
    
    print(f"\n10. DIAGNOSIS")
    print(f"   Common issues:")
    
    # Check for loopback optimization
    zero_byte_sends = sum(1 for e in send_events if e['bytes'] == 0)
    zero_byte_recvs = sum(1 for e in recv_events if e['bytes'] == 0)
    
    if zero_byte_sends > 0 or zero_byte_recvs > 0:
        print(f"   • Loopback optimization: Many send/recv events show 0 bytes")
        print(f"     This is normal for localhost connections in Linux")
        print(f"     The kernel optimizes by bypassing network layers")
    
    # Check time sync
    if ebpf_first > app_last_ns or ebpf_last < app_first_ns:
        print(f"   • TIME DESYNC: eBPF and app times don't overlap!")
        print(f"     Solution: Ensure eBPF starts before app requests")
    
    # Check PID filtering
    if len(pids_in_ebpf) > 10:
        print(f"   • Many PIDs detected ({len(pids_in_ebpf)})")
        print(f"     eBPF is capturing system-wide traffic")
        print(f"     Consider filtering by specific PIDs")
    
    print(f"\n" + "=" * 70)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <app_metrics.json> <ebpf_events.json>")
        sys.exit(1)
    
    inspect_data(sys.argv[1], sys.argv[2])