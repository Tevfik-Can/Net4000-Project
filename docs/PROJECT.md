# Cross-Layer Network Observability Framework
## Research Project Documentation

### Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Getting Started](#getting-started)
4. [Running Experiments](#running-experiments)
5. [Data Analysis](#data-analysis)
6. [Deployment Options](#deployment-options)
7. [Research Methodology](#research-methodology)
8. [File Organization](#file-organization)

---

## Project Overview

### Research Objective
Design and evaluate a cross-layer network observability framework that correlates kernel-level telemetry through eBPF with application-level metrics to determine improvements in:
- Diagnostic accuracy
- Fault-detection speed
- Blind spot identification

### Sub-Objectives
1. **Application-Level Metrics**: Track request latency, error rates, and throughput
2. **Kernel-Level Telemetry**: Capture TCP events (connect, send, recv, close)
3. **Cross-Layer Correlation**: Identify issues missed by single-layer monitoring
4. **Comparative Analysis**: Quantify improvements over traditional monitoring

---

## Architecture

### System Layers

```
┌─────────────────────────────────────────────────────────┐
│                   Application Layer                      │
│  ┌──────────────┐              ┌──────────────┐        │
│  │ HTTP Client  │─────────────▶│ HTTP Server  │        │
│  │ (Load Gen)   │              │ (Metrics)    │        │
│  └──────────────┘              └──────────────┘        │
└─────────────────────────────────────────────────────────┘
                          │
                          │ Cross-Layer
                          │ Correlation
                          │
┌─────────────────────────────────────────────────────────┐
│                    Kernel Layer                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  eBPF TCP Monitor (kprobes)                      │  │
│  │  - tcp_v4_connect                                 │  │
│  │  - tcp_sendmsg                                    │  │
│  │  - tcp_recvmsg                                    │  │
│  │  - tcp_close                                      │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Components

1. **Application Layer** (`src/application/`)
   - `server.py`: HTTP server with built-in metrics
   - `client.py`: Load generator with latency tracking

2. **Kernel Layer** (`src/ebpf/`)
   - `tcp_monitor.c`: eBPF program for TCP event capture
   - `runner.py`: eBPF event collector and processor

3. **Correlation Layer** (`src/correlation/`)
   - `correlator.py`: Cross-layer event correlation
   - Detects discrepancies and blind spots

---

## Getting Started

### Prerequisites

**Required:**
- Linux kernel 4.4+ (4.9+ recommended)
- Python 3.8+
- BCC (BPF Compiler Collection)

**Optional:**
- Docker & Docker Compose
- Kubernetes cluster
- Grafana & OpenTelemetry

### Installation

```bash
# 1. Clone repository
git clone <repository-url>
cd cross-layer-observability

# 2. Run setup script
chmod +x scripts/setup_env.sh
./scripts/setup_env.sh

# 3. Activate virtual environment
source venv/bin/activate
```

### Install BCC (if not already installed)

**Ubuntu/Debian:**
```bash
sudo apt-get install bpfcc-tools libbpfcc python3-bpfcc
```

**CentOS/RHEL:**
```bash
sudo yum install bcc-tools python3-bcc
```

---

## Running Experiments

### Option 1: Integrated Test (Quickest)

```bash
# Run the integrated test
sudo python3 tests/integration/test_cross_layer.py --requests 50

# This will:
# 1. Start HTTP server
# 2. Load eBPF program
# 3. Generate HTTP requests
# 4. Capture both app and kernel metrics
# 5. Export data to results/cross_layer/
```

### Option 2: Manual Components (More Control)

```bash
# Terminal 1: Start HTTP server
python3 src/application/server.py --port 8080

# Terminal 2: Start eBPF monitoring (requires sudo)
sudo python3 src/ebpf/runner.py --output results/ebpf_events.json

# Terminal 3: Generate load
python3 src/application/client.py \
  --url http://localhost:8080 \
  --requests 100 \
  --interval 200 \
  --output results/client_metrics.json

# Terminal 4: Correlate data
python3 src/correlation/correlator.py \
  --app-metrics results/client_metrics.json \
  --ebpf-events results/ebpf_events.json \
  --output results/correlations.json
```

### Option 3: Docker (Isolated Environment)

```bash
cd docker
docker-compose up

# Results will be in ./results/
```

### Option 4: Kubernetes (Production Scale)

```bash
# Build and deploy
cd kubernetes
./deploy.sh

# Monitor deployment
kubectl get pods -n cross-layer-observability -w

# View logs
kubectl logs -n cross-layer-observability -l app=ebpf-monitor
```

---

## Data Analysis

### Output Files

Each test run produces:

1. **`client_metrics.json`** - Application-level data
   ```json
   {
     "request_id": 1,
     "latency_ms": 2.45,
     "status_code": 200,
     "result": "success"
   }
   ```

2. **`ebpf_events.json`** - Kernel-level data
   ```json
   {
     "timestamp_ns": 1234567890,
     "event_type": "send",
     "bytes": 512,
     "pid": 1234
   }
   ```

3. **`correlations.json`** - Cross-layer insights
   ```json
   {
     "request_id": 1,
     "app_latency_ms": 2.45,
     "kernel_event_count": 4,
     "discrepancy_detected": false
   }
   ```

### Analyzing Results

```python
import json
import pandas as pd

# Load correlations
with open('results/correlations.json') as f:
    data = json.load(f)

# Find blind spots
blind_spots = [c for c in data['correlations'] 
               if c['discrepancy_detected']]

print(f"Blind spots found: {len(blind_spots)}")
for bs in blind_spots:
    print(f"  Request {bs['request_id']}: {bs['discrepancy_reason']}")
```

---

## Research Methodology

### Phase 1: Baseline Collection
- Run application-only monitoring
- Collect metrics without eBPF
- Establish baseline performance

### Phase 2: Cross-Layer Monitoring
- Enable eBPF monitoring
- Collect both app and kernel data
- Run same test scenarios

### Phase 3: Comparative Analysis
- Compare detection rates
- Measure diagnostic accuracy
- Identify blind spots
- Calculate improvements

### Phase 4: Scenario Testing

**Test Scenarios:**
1. **Normal Operation** - Baseline performance
2. **Network Congestion** - Induced packet loss
3. **Connection Timeouts** - Simulated failures
4. **Silent Failures** - App thinks success, kernel shows failure
5. **Retransmissions** - TCP retransmit events

---

## Deployment Options

### Local Development
- **Best for**: Initial testing, debugging
- **Setup**: Python + BCC on Linux
- **Command**: `python3 tests/integration/test_cross_layer.py`

### Docker
- **Best for**: Isolated testing, reproducibility
- **Setup**: Docker + Docker Compose
- **Command**: `docker-compose up`

### Kubernetes
- **Best for**: Production-scale testing, multi-node
- **Setup**: K8s cluster with eBPF support
- **Command**: `./kubernetes/deploy.sh`

---

## File Organization

```
cross-layer-observability/
├── src/                      # Source code
│   ├── ebpf/                # Kernel telemetry
│   │   ├── tcp_monitor.c    # eBPF program
│   │   └── runner.py        # Event collector
│   ├── application/         # App metrics
│   │   ├── server.py        # HTTP server
│   │   └── client.py        # Load generator
│   └── correlation/         # Cross-layer
│       ├── correlator.py    # Event correlation
│       └── analyzer.py      # Statistical analysis
│
├── tests/                   # Test suite
│   ├── integration/         # End-to-end tests
│   └── benchmarks/          # Performance tests
│
├── docker/                  # Containerization
│   ├── Dockerfile.ebpf      # eBPF container
│   ├── Dockerfile.app       # App container
│   └── docker-compose.yml   # Orchestration
│
├── kubernetes/              # K8s deployment
│   ├── namespace.yaml
│   ├── app-deployment.yaml
│   ├── ebpf-daemonset.yaml
│   └── deploy.sh
│
├── scripts/                 # Utility scripts
│   └── setup_env.sh         # Environment setup
│
├── results/                 # Data output
│   ├── baseline/            # Single-layer data
│   ├── cross_layer/         # Combined data
│   └── analysis/            # Analysis results
│
├── requirements.txt         # Python dependencies
└── README.md               # Project overview
```

---

## Key Metrics

### Application Layer
- Request latency (p50, p95, p99)
- Error rate (%)
- Throughput (req/s)
- Success rate (%)

### Kernel Layer
- TCP connections
- Bytes sent/received
- Connection duration
- Event counts per request

### Cross-Layer Insights
- Discrepancy detection rate
- False positive/negative rates
- Blind spot identification
- Diagnostic accuracy improvement

---

## Troubleshooting

### eBPF Won't Load
```bash
# Check kernel version
uname -r  # Should be 4.4+

# Check if debugfs is mounted
mount | grep debugfs

# Mount if needed
sudo mount -t debugfs none /sys/kernel/debug
```

### Permission Denied
```bash
# eBPF requires root/sudo
sudo python3 src/ebpf/runner.py
```

### No Events Captured
```bash
# Check if PIDs are correct
ps aux | grep server

# Verify eBPF is attached
sudo bpftool prog list
```

---

## Contributing

This is a research project. For questions or contributions:
1. Open an issue
2. Provide detailed description
3. Include test results if applicable

---

## References

- [eBPF Documentation](https://ebpf.io/)
- [BCC Tools](https://github.com/iovisor/bcc)
- [Linux Kernel Networking](https://www.kernel.org/doc/html/latest/networking/)
