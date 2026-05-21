#!/usr/bin/env bash
# ============================================================
# IronStack - BunkerWeb Installation Script
# ============================================================
# This script installs Docker (if not present) and pulls the
# BunkerWeb Docker image required for the BunkerWeb WAF engine.
#
# Usage:
#   chmod +x install_bunkerweb.sh
#   ./install_bunkerweb.sh
#
# After installation, you can use BunkerWeb via IronStack:
#   from ironstack.defense import WAF
#   waf = WAF(engine="bunkerweb")
#   waf.start()
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BUNKERWEB_IMAGE="bunkerity/bunkerweb:latest"
MIN_DOCKER_VERSION="20.10.0"

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}    IronStack - BunkerWeb WAF Installation                  ${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

# -----------------------------------------------------------
# 1. Check if Docker is installed
# -----------------------------------------------------------
check_docker() {
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
        echo -e "${GREEN}[✓] Docker is installed (version: $DOCKER_VERSION)${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Docker is not installed.${NC}"
        return 1
    fi
}

# -----------------------------------------------------------
# 2. Install Docker (Linux only, recommended method)
# -----------------------------------------------------------
install_docker() {
    echo -e "${YELLOW}[*] Attempting to install Docker...${NC}"
    OS="$(uname -s)"
    case "$OS" in
        Linux)
            if [ -f /etc/debian_version ]; then
                echo -e "${BLUE}[*] Debian/Ubuntu detected.${NC}"
                sudo apt-get update
                sudo apt-get install -y ca-certificates curl
                sudo install -m 0755 -d /etc/apt/keyrings
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
                sudo apt-get update
                sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            elif [ -f /etc/redhat-release ]; then
                echo -e "${BLUE}[*] RHEL/CentOS/Fedora detected.${NC}"
                sudo yum install -y yum-utils
                sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
                sudo systemctl start docker
                sudo systemctl enable docker
            else
                echo -e "${RED}[✗] Unsupported Linux distribution. Please install Docker manually:${NC}"
                echo -e "    https://docs.docker.com/engine/install/"
                exit 1
            fi
            # Add user to docker group
            if [ -n "$USER" ] && [ "$USER" != "root" ]; then
                sudo usermod -aG docker "$USER"
                echo -e "${YELLOW}[!] You may need to log out and back in for docker group to take effect.${NC}"
            fi
            # Start docker if not running
            if ! pgrep -x dockerd > /dev/null; then
                sudo systemctl start docker
            fi
            ;;
        Darwin)
            echo -e "${RED}[✗] Docker Desktop is required on macOS. Please install manually:${NC}"
            echo -e "    https://docs.docker.com/desktop/install/mac/"
            exit 1
            ;;
        *)
            echo -e "${RED}[✗] Unsupported OS. Please install Docker manually.${NC}"
            exit 1
            ;;
    esac
    echo -e "${GREEN}[✓] Docker installation completed.${NC}"
}

# -----------------------------------------------------------
# 3. Pull BunkerWeb Docker image
# -----------------------------------------------------------
pull_image() {
    echo -e "${BLUE}[*] Pulling BunkerWeb Docker image (${BUNKERWEB_IMAGE})...${NC}"
    docker pull "${BUNKERWEB_IMAGE}"
    echo -e "${GREEN}[✓] BunkerWeb image pulled successfully.${NC}"
}

# -----------------------------------------------------------
# 4. Verify installation (quick test)
# -----------------------------------------------------------
verify_installation() {
    echo -e "${BLUE}[*] Verifying BunkerWeb image...${NC}"
    if docker image inspect "${BUNKERWEB_IMAGE}" &> /dev/null; then
        echo -e "${GREEN}[✓] BunkerWeb image is ready.${NC}"
    else
        echo -e "${RED}[✗] Failed to find