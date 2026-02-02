# Files 
cross-layer-observability/  
├── .gitignore  
├── requirements.txt  
├── docker/  
│ ├── docker-compose.yml  
│ ├── Dockerfile.app  
│ └── Dockerfile.ebpf  
├── results/ # json files  
│  
├── scripts/ # Main scripts and testing utilities  
│ ├── generate_blind_spots.py  
│ ├── inspect_data.py  
│ ├── setup_env.sh  
│ ├── test_app_only.py  
│ └── test_cross_layer.py # Main integration test  
├── src/  
├── application/ # Application layer monitoring  
│ ├── client.py  
│ └── server.py  
├── correlation/ # Cross-layer correlation logic  
│ ├── analyzer.py  
│ └── correlator.py  
└── ebpf/ # eBPF kernel monitoring  
├── runner.py  
└── tcp_monitor.c  



## Quick Start (vscode WSL terminal venv)

1. cd to project root after download  

2. Setup Python environment  
chmod +x scripts/setup_env.sh  
./scripts/setup_env.sh  
source venv/bin/activate  

3. Install BCC tools      
sudo apt-get install -y bpfcc-tools libbpfcc python3-bpfcc      

Baseline (app-only)  
python3 tests/integration/test_app_only.py \  
--requests 100 \  
--output ./results  

Cross-layer (app + kernel)  
sudo python3 tests/integration/test_cross_layer.py \  
--requests 100 \  
--output ./results  

Correlate events
python3 src/correlation/correlator.py \  
--app-metrics ./results/app_metrics.json \  
--ebpf-events ./results/ebpf_events.json \  
--output ./results/correlations.json  

Analyze and compare  
python3 src/correlation/analyzer.py \  
--correlations ./results/correlations.json \  
--baseline ./results/app_metrics_baseline.json \  
--output ./results/comparison_report.json  



# Run in Docker    
cd docker  

docker compose build  

docker compose up -d; docker compose logs -f  

or run 1 at a time:   
docker compose run --rm correlator python3 src/correlation/correlator.py \  
  --app-metrics ./results/app_metrics.json \  
  --ebpf-events ./results/ebpf_events.json \  
  --output ./results/correlations.json  

docker compose run --rm analyzer python3 src/correlation/analyzer.py \  
  --correlations ./results/correlations.json \  
  --output ./results/comparison_report.json  
