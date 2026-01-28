#!/bin/bash
# deploy.sh - Deploy the cross-layer observability stack to Kubernetes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="cross-layer-observability"
IMAGE_TAG="${IMAGE_TAG:-latest}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Cross-Layer Observability Deployment${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Error: kubectl not found. Please install kubectl.${NC}"
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}Error: Cannot connect to Kubernetes cluster.${NC}"
    exit 1
fi

echo -e "${YELLOW}Connected to cluster:${NC}"
kubectl cluster-info | head -1

# Build Docker images
echo -e "\n${YELLOW}Building Docker images...${NC}"
cd ..
docker build -t cross-layer-observability/app:${IMAGE_TAG} -f docker/Dockerfile.app .
docker build -t cross-layer-observability/ebpf:${IMAGE_TAG} -f docker/Dockerfile.ebpf .

# If using a registry, push images
if [ ! -z "$DOCKER_REGISTRY" ]; then
    echo -e "\n${YELLOW}Pushing images to ${DOCKER_REGISTRY}...${NC}"
    docker tag cross-layer-observability/app:${IMAGE_TAG} ${DOCKER_REGISTRY}/cross-layer-observability/app:${IMAGE_TAG}
    docker tag cross-layer-observability/ebpf:${IMAGE_TAG} ${DOCKER_REGISTRY}/cross-layer-observability/ebpf:${IMAGE_TAG}
    docker push ${DOCKER_REGISTRY}/cross-layer-observability/app:${IMAGE_TAG}
    docker push ${DOCKER_REGISTRY}/cross-layer-observability/ebpf:${IMAGE_TAG}
fi

# Create namespace
echo -e "\n${YELLOW}Creating namespace...${NC}"
kubectl apply -f kubernetes/namespace.yaml

# Deploy application layer
echo -e "\n${YELLOW}Deploying application layer...${NC}"
kubectl apply -f kubernetes/app-deployment.yaml

# Wait for application to be ready
echo -e "\n${YELLOW}Waiting for application to be ready...${NC}"
kubectl wait --for=condition=available --timeout=60s \
    deployment/http-server -n ${NAMESPACE}

# Deploy eBPF monitoring layer
echo -e "\n${YELLOW}Deploying eBPF monitoring layer...${NC}"
kubectl apply -f kubernetes/ebpf-daemonset.yaml

# Wait for DaemonSet to be ready
echo -e "\n${YELLOW}Waiting for eBPF monitors to be ready...${NC}"
kubectl rollout status daemonset/ebpf-monitor -n ${NAMESPACE} --timeout=60s

# Display status
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "\n${YELLOW}Deployment Status:${NC}"
kubectl get all -n ${NAMESPACE}

echo -e "\n${YELLOW}eBPF Monitor Pods:${NC}"
kubectl get pods -n ${NAMESPACE} -l app=ebpf-monitor -o wide

echo -e "\n${YELLOW}Useful commands:${NC}"
echo "  View logs:"
echo "    kubectl logs -n ${NAMESPACE} -l app=http-server"
echo "    kubectl logs -n ${NAMESPACE} -l app=ebpf-monitor"
echo ""
echo "  Port forward to access server:"
echo "    kubectl port-forward -n ${NAMESPACE} svc/http-server 8080:8080"
echo ""
echo "  Exec into pod:"
echo "    kubectl exec -it -n ${NAMESPACE} <pod-name> -- bash"
echo ""
echo "  Delete deployment:"
echo "    kubectl delete namespace ${NAMESPACE}"

echo -e "\n${GREEN}Deployment successful!${NC}"
