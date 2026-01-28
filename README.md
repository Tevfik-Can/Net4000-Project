# Cross-Layer Network Observability Framework

## Research Objective
Design and evaluate a cross-layer network observability framework that correlates kernel-level telemetry through eBPF with application-level metrics to determine how much diagnostic accuracy and fault-detection speed improve compared to traditional single-layer monitoring.

## Project Structure

```
cross-layer-observability/
├── src/               # Source code
│   ├── ebpf/         # Kernel-level telemetry via eBPF
│   ├── application/  # Application-level metrics collection
│   └── correlation/  # Cross-layer correlation engine
├── tests/            # Test suite and benchmarks
├── docker/           # Container configurations
├── kubernetes/       # K8s deployment manifests
├── config/           # Configuration files
├── scripts/          # Utility scripts
└── results/          # Experimental data (gitignored)
```

## Key Components

### 1. eBPF Telemetry (`src/ebpf/`)
- **tcp_monitor.c**: Kernel-level TCP event monitoring
- **runner.py**: eBPF event collector and processor

### 2. Application Metrics (`src/application/`)
- **server.py**: HTTP server with instrumentation
- **client.py**: Load generator with latency tracking

### 3. Cross-Layer Correlation (`src/correlation/`)
- **correlator.py**: Correlates kernel + app events
- **analyzer.py**: Statistical analysis and blind spot detection

## Quick Start

### Prerequisites
- Python 3.8+
- BCC (BPF Compiler Collection)
- Docker & Docker Compose
- Kubernetes cluster (for production deployment)

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run baseline (single-layer) test
./scripts/run_baseline.sh

# Run cross-layer monitoring test
./scripts/run_cross_layer.sh

# Analyze results
python src/correlation/analyzer.py --baseline results/baseline/ --cross-layer results/cross_layer/
```

### Docker Deployment

```bash
cd docker
docker-compose up
```

### Kubernetes Deployment

```bash
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/
```

## Research Methodology

1. **Baseline Collection**: Traditional application-only monitoring
2. **eBPF Telemetry**: Kernel-level network event capture
3. **Cross-Layer Correlation**: Combine both data sources
4. **Comparative Analysis**: Measure improvements in:
   - Diagnostic accuracy
   - Fault detection speed
   - Blind spot identification

## Metrics Tracked

### Application Layer
- Request latency (p50, p95, p99)
- Error rates
- Throughput (requests/sec)

### Kernel Layer (eBPF)
- TCP connection events
- Packet send/receive events
- Connection close events
- Retransmission events

### Cross-Layer Insights
- Kernel delays not visible at app layer
- Silent failures detected only by eBPF
- Correlation between kernel congestion and app latency

## Results & Analysis

Results are stored in `results/` directory:
- `baseline/`: Single-layer monitoring data
- `cross_layer/`: Combined eBPF + app metrics
- `analysis/`: Comparative analysis and visualizations

## Contributing

This is a research project. For questions or contributions, please open an issue.

## License

MIT License
