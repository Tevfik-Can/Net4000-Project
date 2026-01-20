# Net4000 Project - Cross-Layer Network Observability using eBPF

# Clone and setup
git clone https://github.com/Tevfik-Can/Net4000-Project.git
cd Net4000-Project
pip install -r requirements.txt

# Run cross-layer test
cd analysis
python3 simple_test.py


# Project Structure
data_collection/     # HTTP client/server for application metrics
analysis/           # Test scripts and data analysis
ebpf_programs/      # eBPF headers and programs
docs/              # Documentation
results/           # Output data (gitignored)

# Initial VM Setup
mkdir project
cd project/
sudo apt update
sudo apt install -y git python3 python3-pip

git init
git remote add origin git@github.com:Tevfik-Can/Net4000-Project.git
git config --global user.email "your-email@example.com"
git config --global user.name "Your Name"

# SSH Key Setup
ssh-keygen -t ed25519 -C "your-email@example.com"
cat ~/.ssh/id_ed25519.pub
# Add to GitHub: https://github.com/settings/keys

ssh -T git@github.com
git push -u origin main

# eBPF Setup
sudo apt install -y clang llvm libelf-dev libbpf-dev \
  bpfcc-tools linux-headers-$(uname -r) bpftool
