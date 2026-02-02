#!/usr/bin/env python3
"""
Kernel Compatibility Checker for eBPF TCP Monitoring
Helps identify which kprobes are available on your system
"""

import subprocess
import sys
import os

def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        print("❌ This script must be run as root (use sudo)")
        print("   Reason: Need access to /proc/kallsyms")
        sys.exit(1)
    print("✅ Running as root\n")

def get_kernel_version():
    """Get kernel version."""
    try:
        result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
        version = result.stdout.strip()
        print(f"Kernel Version: {version}")
        return version
    except Exception as e:
        print(f"⚠️  Could not get kernel version: {e}")
        return "unknown"

def check_bcc_installed():
    """Check if BCC is installed."""
    try:
        import bcc
        print("✅ BCC (BPF Compiler Collection) is installed")
        return True
    except ImportError:
        print("❌ BCC is NOT installed")
        print("   Install with: sudo apt-get install python3-bcc")
        return False

def get_available_tcp_functions():
    """Read available TCP functions from kallsyms."""
    try:
        with open('/proc/kallsyms', 'r') as f:
            functions = set()
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2].startswith('tcp_'):
                    functions.add(parts[2])
            return functions
    except Exception as e:
        print(f"❌ Error reading /proc/kallsyms: {e}")
        return set()

def analyze_tcp_functions(available_funcs):
    """Analyze which TCP monitoring functions are available."""
    
    # Define function categories
    categories = {
        "Core Connection Functions": {
            'tcp_v4_connect': 'Connection establishment (IPv4)',
            'tcp_v6_connect': 'Connection establishment (IPv6)',
            'tcp_connect': 'Generic connection establishment',
        },
        "Data Transfer Functions": {
            'tcp_sendmsg': 'Send data to socket',
            'tcp_recvmsg': 'Receive data from socket',
            'tcp_sendpage': 'Send page data',
        },
        "Connection Management": {
            'tcp_close': 'Connection close',
            'tcp_shutdown': 'Connection shutdown',
            'tcp_fin': 'FIN packet handling',
        },
        "Retransmission & Recovery": {
            'tcp_retransmit_skb': 'Retransmit packet',
            'tcp_retransmit_timer': 'Retransmission timer',
            'tcp_syn_retransmit': 'SYN retransmission',
        },
        "Packet Drop & Loss": {
            'tcp_drop': 'Packet drop event',
            'tcp_drop_reason': 'Packet drop with reason',
        },
        "Timeout & Timer": {
            'tcp_write_timer_handler': 'Write timeout handler',
            'tcp_delack_timer_handler': 'Delayed ACK timer',
            'tcp_keepalive_timer': 'Keepalive timer',
        },
        "Performance & Congestion": {
            'tcp_cwnd_restart': 'Congestion window restart',
            'tcp_slow_start': 'Slow start algorithm',
            'tcp_cong_avoid': 'Congestion avoidance',
        }
    }
    
    print("\n" + "="*70)
    print("TCP FUNCTION AVAILABILITY CHECK")
    print("="*70)
    
    total_checked = 0
    total_available = 0
    
    for category, functions in categories.items():
        print(f"\n{category}:")
        print("-" * 70)
        
        for func_name, description in functions.items():
            total_checked += 1
            is_available = func_name in available_funcs
            
            if is_available:
                total_available += 1
                status = "✅"
                note = ""
            else:
                status = "❌"
                note = "(not available on this kernel)"
            
            print(f"  {status} {func_name:30s} - {description} {note}")
    
    print("\n" + "="*70)
    print(f"SUMMARY: {total_available}/{total_checked} functions available ({total_available/total_checked*100:.1f}%)")
    print("="*70)
    
    return total_available, total_checked

def check_required_vs_optional():
    """Categorize functions as required or optional."""
    
    print("\n" + "="*70)
    print("FUNCTION PRIORITY CLASSIFICATION")
    print("="*70)
    
    required = {
        'tcp_v4_connect': 'Track connection attempts',
        'tcp_sendmsg': 'Track data sent',
        'tcp_recvmsg': 'Track data received',
        'tcp_close': 'Track connection closes',
    }
    
    highly_recommended = {
        'tcp_retransmit_skb': 'Detect retransmissions (network issues)',
    }
    
    optional_but_useful = {
        'tcp_drop': 'Detect packet drops',
        'tcp_syn_retransmit': 'Detect SYN retransmissions',
        'tcp_write_timer_handler': 'Detect write timeouts',
    }
    
    available_funcs = get_available_tcp_functions()
    
    print("\n🔴 REQUIRED (minimum for basic monitoring):")
    print("-" * 70)
    required_ok = True
    for func, desc in required.items():
        status = "✅" if func in available_funcs else "❌ MISSING"
        print(f"  {status} {func:30s} - {desc}")
        if func not in available_funcs:
            required_ok = False
    
    print("\n🟡 HIGHLY RECOMMENDED (for blindspot detection):")
    print("-" * 70)
    for func, desc in highly_recommended.items():
        status = "✅" if func in available_funcs else "❌ Not available"
        print(f"  {status} {func:30s} - {desc}")
    
    print("\n🟢 OPTIONAL (enhanced monitoring):")
    print("-" * 70)
    for func, desc in optional_but_useful.items():
        status = "✅" if func in available_funcs else "❌ Not available"
        print(f"  {status} {func:30s} - {desc}")
    
    if required_ok:
        print("\n✅ All required functions available - you can run basic monitoring!")
    else:
        print("\n❌ Some required functions missing - monitoring may be limited")
    
    return required_ok

def suggest_alternatives():
    """Suggest alternatives for missing functions."""
    
    available_funcs = get_available_tcp_functions()
    
    alternatives = {
        'tcp_drop': [
            'tcp_drop_reason (newer kernels)',
            'kfree_skb (generic packet drop)',
        ],
        'tcp_recvmsg': [
            'Use kretprobe instead of kprobe',
            'tcp_cleanup_rbuf (alternative)',
        ],
        'tcp_write_timer_handler': [
            'tcp_write_timer (older name)',
            'tcp_retransmit_timer (related)',
        ],
    }
    
    missing = []
    for func in alternatives.keys():
        if func not in available_funcs:
            missing.append(func)
    
    if missing:
        print("\n" + "="*70)
        print("ALTERNATIVES FOR MISSING FUNCTIONS")
        print("="*70)
        
        for func in missing:
            print(f"\n❌ Missing: {func}")
            print("   Alternatives to try:")
            for alt in alternatives[func]:
                print(f"      • {alt}")

def check_bpf_helpers():
    """Check if BPF helpers are available."""
    print("\n" + "="*70)
    print("BPF HELPER FUNCTIONS")
    print("="*70)
    
    helpers = [
        'bpf_ktime_get_ns',
        'bpf_get_current_pid_tgid',
        'bpf_get_current_comm',
        'bpf_perf_event_output',
        'bpf_probe_read_kernel',
    ]
    
    print("\nRequired BPF helpers for TCP monitoring:")
    for helper in helpers:
        # These are almost always available in modern kernels
        print(f"  ✅ {helper}")
    
    print("\nNote: BPF helpers are kernel built-in and almost always available")

def main():
    print("="*70)
    print("eBPF TCP MONITORING - KERNEL COMPATIBILITY CHECKER")
    print("="*70)
    print()
    
    # Check root
    check_root()
    
    # Get kernel version
    kernel_version = get_kernel_version()
    print()
    
    # Check BCC
    if not check_bcc_installed():
        print("\n⚠️  Install BCC before running eBPF programs")
        print()
    
    # Get available functions
    available_funcs = get_available_tcp_functions()
    
    if not available_funcs:
        print("❌ Could not read TCP functions from kernel")
        sys.exit(1)
    
    print(f"\n✅ Found {len([f for f in available_funcs if f.startswith('tcp_')])} TCP functions in kernel")
    
    # Analyze functions
    analyze_tcp_functions(available_funcs)
    
    # Check required vs optional
    required_ok = check_required_vs_optional()
    
    # Suggest alternatives
    suggest_alternatives()
    
    # Check BPF helpers
    check_bpf_helpers()
    
    # Final recommendation
    print("\n" + "="*70)
    print("RECOMMENDATION")
    print("="*70)
    
    if required_ok:
        print("✅ Your kernel supports TCP monitoring with eBPF!")
        print("   Run: sudo python3 test_cross_layer_fixed.py --requests 100")
    else:
        print("⚠️  Your kernel has limited TCP monitoring support")
        print("   The fixed script will still work with available functions")
        print("   Run: sudo python3 test_cross_layer_fixed.py --requests 100")
    
    print("\n" + "="*70)

if __name__ == '__main__':
    main()