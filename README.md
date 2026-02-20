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
│ └── full_runner.py (main orchestrator calls all other files)  
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



# How to run (i put all these files on vm, then ran with docker)  
sudo apt update  
sudo apt install -y ca-certificates curl gnupg  
sudo install -m 0755 -d /etc/apt/keyrings  
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg  
sudo chmod a+r /etc/apt/keyrings/docker.gpg  
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null  
sudo apt update  
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin  
sudo usermod -aG docker $USER  
sudo systemctl enable --now docker  

sudo apt install -y linux-headers-$(uname -r) bpfcc-tools python3-bpfcc libbpfcc  

Log out and back in (applies docker group), then build and run   
cd ~/cross-layer  
docker compose -f docker/docker-compose.yml build  
sudo python3 scripts/full_runner.py --docker --requests 100  
