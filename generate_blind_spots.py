#!/usr/bin/env python3
"""
Test Scenario Generator - Induces Real Blind Spots

This creates network conditions where app reports success but kernel sees problems.
"""
import time
import subprocess
import random
from http.server import HTTPServer, BaseHTTPRequestHandler


class ProblematicHTTPHandler(BaseHTTPRequestHandler):
    """
    HTTP handler that LOOKS successful from app perspective
    but creates kernel-level issues.
    """
    
    def do_GET(self):
        # Randomly introduce issues that app won't see
        issue = random.choice(['normal', 'slow_response', 'fragmented', 'delayed'])
        
        if issue == 'slow_response':
            # App will report success, but kernel shows lots of events
            time.sleep(0.05)  # Small delay - app still considers it "success"
            for i in range(20):
                # Many small writes - creates excessive kernel events
                self.wfile.write(b"x")
                time.sleep(0.001)
        
        elif issue == 'fragmented':
            # Send response in many tiny fragments
            # App sees one successful response
            # Kernel sees many send/recv events
            self.send_response(200)
            self.end_headers()
            data = b"OK" * 100
            for i in range(0, len(data), 10):
                self.wfile.write(data[i:i+10])
                self.wfile.flush()
                time.sleep(0.002)
        
        elif issue == 'delayed':
            # Delay before sending response
            # App sees success but kernel shows connection held open
            time.sleep(0.03)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        
        else:
            # Normal response
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
    
    def log_message(self, *args):
        pass


def add_network_delays():
    """
    Add network latency and packet loss to induce retransmissions.
    This simulates real-world network issues.
    
    Run this BEFORE starting your test.
    """
    print("Adding network conditions to induce blind spots...")
    
    commands = [
        # Add 50ms delay with 10% jitter
        "sudo tc qdisc add dev lo root netem delay 50ms 10ms",
        
        # Add 2% packet loss (will cause retransmissions)
        # "sudo tc qdisc change dev lo root netem delay 50ms 10ms loss 2%",
        
        # Add packet reordering
        # "sudo tc qdisc change dev lo root netem delay 50ms 10ms reorder 5% 50%",
    ]
    
    for cmd in commands:
        try:
            subprocess.run(cmd.split(), check=True, capture_output=True)
            print(f"  ✓ {cmd}")
        except subprocess.CalledProcessError as e:
            print(f"  ✗ Failed: {e}")
            print("    (If tc not installed: sudo apt-get install iproute2)")


def remove_network_delays():
    """
    Remove network conditions after test.
    """
    print("\nRemoving network conditions...")
    try:
        subprocess.run(["sudo", "tc", "qdisc", "del", "dev", "lo", "root"], 
                      check=True, capture_output=True)
        print("  ✓ Network conditions removed")
    except subprocess.CalledProcessError:
        print("  (No conditions to remove)")


def run_blind_spot_test():
    """
    Complete test that generates REAL blind spots.
    """
    print("="*70)
    print(" BLIND SPOT GENERATION TEST")
    print("="*70)
    
    # Step 1: Add network issues
    add_network_delays()
    
    # Step 2: Start problematic server
    print("\nStarting problematic HTTP server on port 8082...")
    server = HTTPServer(('127.0.0.1', 8082), ProblematicHTTPHandler)
    
    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print("  ✓ Server started")
    
    time.sleep(1)
    
    # Step 3: Run test with eBPF
    print("\nRun this in another terminal:")
    print("  sudo python3 tests/integration/test_cross_layer.py --requests 100")
    print("\n  BUT FIRST modify test_cross_layer.py:")
    print("    Change: LoadGenerator('http://127.0.0.1:8080')")
    print("    To:     LoadGenerator('http://127.0.0.1:8082')")
    
    print("\n  Press Ctrl+C when test completes...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    # Step 4: Cleanup
    server.shutdown()
    remove_network_delays()
    
    print("\n" + "="*70)
    print(" Test complete! Now run correlation and analyzer.")
    print("="*70)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "cleanup":
        remove_network_delays()
    else:
        run_blind_spot_test()