## Quick Start (vscode WSL terminal + docker desktop)

1. cd to project root after download  

2. Setup Python environment  
chmod +x scripts/setup_env.sh  
./scripts/setup_env.sh  
source venv/bin/activate  

3. Install BCC tools    
sudo apt-get install -y bpfcc-tools libbpfcc python3-bpfcc    

# Run Commands:   
1. Baseline (app-only)  
python3 tests/integration/test_app_only.py \  
  --requests 100 \  
  --output ./results/baseline  

2. Cross-layer (app + kernel)   
sudo python3 tests/integration/test_cross_layer.py \  
  --requests 100 \  
  --output ./results/cross_layer  

3. Correlate events  
python3 src/correlation/correlator.py \  
  --app-metrics ./results/cross_layer/app_metrics.json \  
  --ebpf-events ./results/cross_layer/ebpf_events.json \  
  --output ./results/cross_layer/correlations.json  

4. Analyze and compare  
python3 src/correlation/analyzer.py \  
  --correlations ./results/cross_layer/correlations.json \  
  --baseline ./results/baseline/app_metrics_baseline.json \  
  --output ./results/comparison_report.json  




# docker  
Build (from project root)   
docker build -t cross-layer-observability/ebpf:latest -f docker/Dockerfile.ebpf .  
docker build -t cross-layer-observability/app:latest -f docker/Dockerfile.app .  

cd docker   
docker-compose up  
