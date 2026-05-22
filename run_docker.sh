#!/bin/bash

# --- Color Scheme for Premium UX ---
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0;37m' # No Color

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}       🚀 ReconLens Containerizer Helper 🚀         ${NC}"
echo -e "${CYAN}====================================================${NC}"

# Check if Docker is installed
if ! [ -x "$(command -v docker)" ]; then
  echo -e "${RED}Error: Docker is not installed on this system.${NC}" >&2
  exit 1
fi

# Check if Docker Daemon is running
if ! docker info >/dev/null 2>&1; then
  echo -e "${RED}Error: Docker daemon is not running. Please start Docker Desktop first.${NC}" >&2
  exit 1
fi

# Clean up legacy running container if exists
if [ "$(docker ps -aq -f name=reconlens)" ]; then
  echo -e "${YELLOW}Stopping and removing existing legacy ReconLens container...${NC}"
  docker rm -f reconlens >/dev/null 2>&1
fi

echo -e "${GREEN}Building and launching ReconLens in Docker Sandbox...${NC}"
docker-compose up --build -d

if [ $? -eq 0 ]; then
  echo -e "${GREEN}====================================================${NC}"
  echo -e "${GREEN} 🎉 ReconLens is now running completely in a Secure Container!${NC}"
  echo -e "${CYAN}  • URL        : ${YELLOW}http://localhost:8003${NC}"
  echo -e "${CYAN}  • Logs Command: ${NC}docker logs -f reconlens"
  echo -e "${CYAN}  • Stop Command: ${NC}docker-compose down"
  echo -e "${GREEN}====================================================${NC}"
  echo -e "${YELLOW}Semua tool recon & scripting berjalan di dalam Docker Sandbox.${NC}"
  echo -e "${YELLOW}Sistem host drive Anda 100% AMAN dari resiko kerusakan file! 🛡️${NC}"
  echo -e "${GREEN}====================================================${NC}"
else
  echo -e "${RED}Error: Failed to build and launch containers.${NC}"
  exit 1
fi
