#!/bin/bash
# setup_env.sh - Set up the development environment

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Environment Setup${NC}"
echo -e "${GREEN}========================================${NC}"

# Check OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "${GREEN}✓${NC} Running on Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${YELLOW}⚠${NC} Running on macOS - eBPF support limited"
    echo "  Consider using Docker or a Linux VM for full functionality"
else
    echo -e "${RED}✗${NC} Unsupported OS: $OSTYPE"
    exit 1
fi

# Check Python
echo -e "\n${YELLOW}Checking Python...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
else
    echo -e "${RED}✗${NC} Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Check kernel version (for eBPF)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "\n${YELLOW}Checking kernel version...${NC}"
    KERNEL_VERSION=$(uname -r)
    echo -e "${GREEN}✓${NC} Kernel version: $KERNEL_VERSION"
    
    # eBPF requires kernel 4.4+ (preferably 4.9+)
    MAJOR=$(echo $KERNEL_VERSION | cut -d'.' -f1)
    MINOR=$(echo $KERNEL_VERSION | cut -d'.' -f2)
    if [ "$MAJOR" -lt 4 ] || ([ "$MAJOR" -eq 4 ] && [ "$MINOR" -lt 4 ]); then
        echo -e "${RED}✗${NC} Kernel too old for eBPF (requires 4.4+)"
        exit 1
    fi
fi

# Check for BCC (BPF Compiler Collection)
echo -e "\n${YELLOW}Checking BCC...${NC}"
if python3 -c "import bcc" &> /dev/null; then
    echo -e "${GREEN}✓${NC} BCC installed"
else
    echo -e "${YELLOW}⚠${NC} BCC not found"
    echo "  To install BCC:"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            echo "    sudo apt-get install bpfcc-tools libbpfcc python3-bpfcc"
        elif command -v yum &> /dev/null; then
            echo "    sudo yum install bcc-tools python3-bcc"
        fi
    fi
fi

# Create virtual environment
echo -e "\n${YELLOW}Creating Python virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓${NC} Virtual environment created"
else
    echo -e "${GREEN}✓${NC} Virtual environment already exists"
fi

# Activate and install dependencies
echo -e "\n${YELLOW}Installing Python dependencies...${NC}"
source venv/bin/activate
pip install --upgrade pip > /dev/null
pip install -r requirements.txt
echo -e "${GREEN}✓${NC} Dependencies installed"

# Create results directory
echo -e "\n${YELLOW}Creating directories...${NC}"
mkdir -p results/{baseline,cross_layer,analysis}
echo -e "${GREEN}✓${NC} Result directories created"

# Check Docker (optional)
echo -e "\n${YELLOW}Checking Docker (optional)...${NC}"
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | tr -d ',')
    echo -e "${GREEN}✓${NC} Docker $DOCKER_VERSION found"
else
    echo -e "${YELLOW}⚠${NC} Docker not found (optional for containerized deployment)"
fi

# Check kubectl (optional)
echo -e "\n${YELLOW}Checking kubectl (optional)...${NC}"
if command -v kubectl &> /dev/null; then
    KUBECTL_VERSION=$(kubectl version --client --short 2>/dev/null | cut -d' ' -f3)
    echo -e "${GREEN}✓${NC} kubectl $KUBECTL_VERSION found"
else
    echo -e "${YELLOW}⚠${NC} kubectl not found (optional for Kubernetes deployment)"
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "\n${YELLOW}Next steps:${NC}"
echo "1. Activate virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Run integration test:"
echo "   python3 tests/integration/test_cross_layer.py"
echo ""
echo "3. Or use Docker:"
echo "   cd docker && docker-compose up"

echo -e "\n${YELLOW}Documentation:${NC}"
echo "  README.md - Project overview"
echo "  docs/ - Additional documentation"
