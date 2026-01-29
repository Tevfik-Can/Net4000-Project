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

## Quick Start (vscode WSL terminal + docker desktop)

1. cd to project root after download  

# 2. Setup Python environment  
chmod +x scripts/setup_env.sh  
./scripts/setup_env.sh  
source venv/bin/activate  

# 3. Install BCC tools  
sudo apt-get install -y bpfcc-tools libbpfcc python3-bpfcc  

# Build (from project root)  
docker build -t cross-layer-observability/ebpf:latest -f docker/Dockerfile.ebpf .  
docker build -t cross-layer-observability/app:latest -f docker/Dockerfile.app .  

# Run  
cd docker  
docker-compose up  

Cross Layer commands:  

sudo python3 tests/integration/test_cross_layer.py --requests 100  

python3 src/correlation/correlator.py \  
    --app-metrics ./results/cross_layer/app_metrics.json \  
    --ebpf-events ./results/cross_layer/ebpf_events.json \  
    --output ./results/cross_layer/correlations.json  

python3 analyzer.py \  
    --correlations ./results/cross_layer/correlations.json \  
    --output ./results/cross_layer/performance_report.json  


Compare to baseline:   
python3 src/application/client.py \  
    --url http://localhost:8080 \  
    --requests 100 \  
    --output ./results/baseline/app_only.json  


python3 analyzer.py \  
    --correlations ./results/cross_layer/correlations.json \  
    --baseline ./results/baseline/app_only.json \  
    --output ./results/comparison_report.json  



