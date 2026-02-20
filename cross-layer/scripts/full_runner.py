#!/usr/bin/env python3
"""
full_runner.py - Cross-Layer Observability Full Pipeline Orchestrator

Usage:
    sudo python3 scripts/full_runner.py
    sudo python3 scripts/full_runner.py --requests 100
    sudo python3 scripts/full_runner.py --docker
"""

import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

ROOT    = Path(__file__).parent.parent
SCRIPTS = ROOT / "scripts"
SRC     = ROOT / "src" / "correlation"

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"
C = "\033[96m"; B = "\033[94m"; BOLD = "\033[1m"; RST = "\033[0m"

def banner(msg, color=C):
    w = 70
    print(f"\n{color}{BOLD}{'='*w}\n  {msg}\n{'='*w}{RST}")

def step(n, msg):
    print(f"\n{B}{BOLD}[Step {n}] {msg}{RST}")

def ok(msg):   print(f"  {G}✓{RST} {msg}")
def warn(msg): print(f"  {Y}⚠{RST}  {msg}")
def fail(msg): print(f"  {R}✗{RST} {msg}")
def info(msg): print(f"    {msg}")

def run(cmd, label):
    print(f"\n  {Y}Running:{RST} {' '.join(str(c) for c in cmd)}")
    print(f"  {'-'*66}")
    result = subprocess.run([str(c) for c in cmd], cwd=str(ROOT))
    print(f"  {'-'*66}")
    if result.returncode != 0:
        fail(f"{label} exited with code {result.returncode}")
        return False
    ok(f"{label} complete")
    return True

def run_docker(args):
    compose_file = ROOT / "docker" / "docker-compose.yml"
    # Docker volumes map ../results → ~/cross-layer/results
    output_dir = ROOT / "results"

    banner(f"CROSS-LAYER OBSERVABILITY — DOCKER PIPELINE  ({args.requests} requests)")
    info(f"Results : {output_dir}")
    info(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    t_start = time.time()

    step(1, "Building Docker images")
    if not run(
        ["docker", "compose", "-f", str(compose_file), "build"],
        "Docker build"
    ):
        sys.exit(1)

    step(2, "Running full pipeline via Docker Compose")
    cmd = ["docker", "compose", "-f", str(compose_file), "up"]
    print(f"\n  {Y}Running:{RST} {' '.join(cmd)}")
    print(f"  {'-'*66}")
    result = subprocess.run(cmd, cwd=str(ROOT))
    print(f"  {'-'*66}")

    # Check all containers exited cleanly by inspecting exit codes
    check = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "ps", "-a", "--format", "json"],
        cwd=str(ROOT), capture_output=True, text=True
    )
    failed = False
    for line in check.stdout.strip().splitlines():
        try:
            svc = json.loads(line)
            name = svc.get("Name", "")
            code = svc.get("ExitCode", 0)
            if code != 0:
                fail(f"Container {name} exited with code {code}")
                failed = True
        except Exception:
            pass

    if failed:
        print(f"\n  To inspect logs: docker compose -f {compose_file} logs")
        sys.exit(1)

    ok("Docker pipeline complete")

    step(3, "Unified summary")
    print_summary(output_dir, args.requests, t_start)

    print(f"\n  To clean up: docker compose -f {compose_file} down")

def print_summary(output_dir: Path, num_requests: int, t_start: float):
    banner("FULL PIPELINE — UNIFIED SUMMARY", color=G)

    elapsed = time.time() - t_start
    print(f"\n  {BOLD}Timestamp  :{RST} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {BOLD}Runtime    :{RST} {elapsed:.1f}s")
    print(f"  {BOLD}Requests   :{RST} {num_requests}")

    baseline_file = output_dir / "baseline" / "app_metrics_baseline.json"
    if baseline_file.exists():
        with open(baseline_file) as f:
            baseline = json.load(f)
        lats = [m["latency_ms"] for m in baseline]
        suc  = sum(1 for m in baseline if m.get("result") == "success")
        p95  = sorted(lats)[int(len(lats) * 0.95)]
        print(f"\n  {BOLD}{'─'*66}")
        print(f"  APP-ONLY BASELINE{RST}")
        print(f"  {'─'*66}")
        print(f"  Success rate : {suc}/{len(baseline)} ({suc/len(baseline)*100:.1f}%)")
        print(f"  Avg latency  : {sum(lats)/len(lats):.2f} ms")
        print(f"  P95 latency  : {p95:.2f} ms")
        print(f"  Max latency  : {max(lats):.2f} ms")
    else:
        warn("Baseline metrics not found — skipping")

    cl_file   = output_dir / "app_metrics.json"
    ebpf_file = output_dir / "ebpf_events.json"
    if cl_file.exists() and ebpf_file.exists():
        with open(cl_file)   as f: cl_metrics  = json.load(f)
        with open(ebpf_file) as f: ebpf_events = json.load(f)
        lats = [m["latency_ms"] for m in cl_metrics]
        suc  = sum(1 for m in cl_metrics if m.get("result") == "success")
        event_types = {}
        for e in ebpf_events:
            t = e.get("event_type", "unknown")
            event_types[t] = event_types.get(t, 0) + 1
        print(f"\n  {BOLD}{'─'*66}")
        print(f"  CROSS-LAYER TEST  (app + eBPF){RST}")
        print(f"  {'─'*66}")
        print(f"  Success rate      : {suc}/{len(cl_metrics)} ({suc/len(cl_metrics)*100:.1f}%)")
        print(f"  Avg latency       : {sum(lats)/len(lats):.2f} ms")
        print(f"  Total eBPF events : {len(ebpf_events)}")
        print(f"  Event breakdown   :")
        for etype, count in sorted(event_types.items()):
            print(f"      {etype:<16}: {count}")
    else:
        warn("Cross-layer output files not found — skipping")

    corr_file = output_dir / "correlations.json"
    if corr_file.exists():
        with open(corr_file) as f:
            corr = json.load(f)
        total      = corr.get("total_requests", 0)
        blindspots = corr.get("blind_spots_detected", 0)
        bs_types   = corr.get("blind_spot_types", {})
        bs_pct     = (blindspots / total * 100) if total else 0
        print(f"\n  {BOLD}{'─'*66}")
        print(f"  CORRELATION RESULTS{RST}")
        print(f"  {'─'*66}")
        print(f"  Correlated requests  : {total}")
        if blindspots == 0:
            print(f"  {G}Blind spots detected : 0  — app and kernel layers agree ✓{RST}")
        else:
            print(f"  {Y}Blind spots detected : {blindspots} ({bs_pct:.1f}%){RST}")
            for btype, count in bs_types.items():
                print(f"      {btype}: {count}")
    else:
        warn("Correlations file not found — skipping")

    report_file = output_dir / "comparison_report.json"
    if report_file.exists():
        with open(report_file) as f:
            report = json.load(f)
        recs = report.get("recommendations", [])
        print(f"\n  {BOLD}{'─'*66}")
        print(f"  RECOMMENDATIONS{RST}")
        print(f"  {'─'*66}")
        if recs:
            for i, r in enumerate(recs, 1):
                print(f"  {i}. {r}")
        else:
            print(f"  {G}No issues flagged — system operating normally.{RST}")
    else:
        warn("Comparison report not found — skipping recommendations")

    print(f"\n  {BOLD}{'─'*66}")
    print(f"  OUTPUT FILES{RST}")
    print(f"  {'─'*66}")
    files = [
        output_dir / "baseline" / "app_metrics_baseline.json",
        output_dir / "app_metrics.json",
        output_dir / "ebpf_events.json",
        output_dir / "correlations.json",
        output_dir / "comparison_report.json",
    ]
    for fp in files:
        if fp.exists():
            ok(f"{fp.relative_to(ROOT)}  ({fp.stat().st_size/1024:.1f} KB)")
        else:
            warn(f"{fp.relative_to(ROOT)}  (missing)")

    banner("DONE", color=G)


def main():
    parser = argparse.ArgumentParser(description="Full cross-layer observability pipeline")
    parser.add_argument("--requests",    type=int,   default=100,
                        help="Number of HTTP requests (default: 100)")
    parser.add_argument("--output",      default="./results",
                        help="Output directory (default: ./results)")
    parser.add_argument("--time-window", type=float, default=50.0,
                        help="Correlation time window in ms (default: 50)")
    parser.add_argument("--docker",      action="store_true",
                        help="Run pipeline via Docker Compose")
    args = parser.parse_args()

    if args.docker:
        run_docker(args)
        return

    output_dir   = Path(args.output).resolve()
    baseline_dir = output_dir / "baseline"
    os.makedirs(output_dir,   exist_ok=True)
    os.makedirs(baseline_dir, exist_ok=True)

    t_start = time.time()

    banner(f"CROSS-LAYER OBSERVABILITY — FULL PIPELINE  ({args.requests} requests)")
    info(f"Output : {output_dir}")
    info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if os.geteuid() != 0:
        fail("eBPF requires root. Re-run with:  sudo python3 scripts/full_runner.py")
        sys.exit(1)

    step(1, "App-only baseline test")
    if not run(
        [sys.executable, SCRIPTS / "test_app_only.py",
         "--requests", args.requests,
         "--output",   baseline_dir],
        "App-only baseline"
    ):
        sys.exit(1)

    step(2, "Cross-layer test  (app + eBPF)")
    if not run(
        [sys.executable, SCRIPTS / "test_cross_layer.py",
         "--requests", args.requests,
         "--output",   output_dir],
        "Cross-layer test"
    ):
        sys.exit(1)

    step(3, "Correlating app metrics with eBPF events")
    app_metrics_file  = output_dir / "app_metrics.json"
    ebpf_events_file  = output_dir / "ebpf_events.json"
    correlations_file = output_dir / "correlations.json"

    if not app_metrics_file.exists() or not ebpf_events_file.exists():
        fail("app_metrics.json or ebpf_events.json missing — cross-layer step failed")
        sys.exit(1)

    if not run(
        [sys.executable, SRC / "correlator.py",
         "--app-metrics", app_metrics_file,
         "--ebpf-events", ebpf_events_file,
         "--output",      correlations_file,
         "--time-window", args.time_window],
        "Correlator"
    ):
        sys.exit(1)

    step(4, "Analyzing and comparing against baseline")
    report_file      = output_dir / "comparison_report.json"
    baseline_metrics = baseline_dir / "app_metrics_baseline.json"
    if not baseline_metrics.exists():
        baseline_metrics = baseline_dir / "app_only_baseline.json"

    analyzer_cmd = [
        sys.executable, SRC / "analyzer.py",
        "--correlations", correlations_file,
        "--output",       report_file,
    ]
    if baseline_metrics.exists():
        analyzer_cmd += ["--baseline", baseline_metrics]
    else:
        warn("No baseline file found — running analyzer without baseline comparison")

    if not run(analyzer_cmd, "Analyzer"):
        sys.exit(1)

    step(5, "Generating unified summary")
    print_summary(output_dir, args.requests, t_start)


if __name__ == "__main__":
    main()
