#!/bin/bash
# Infernox Launcher Script for Kali Linux

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${RED}"
echo "██╗███╗   ██╗███████╗███████╗██████╗ ███╗   ██╗ ██████╗ ██╗  ██╗"
echo "██║████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║██╔═══██╗╚██╗██╔╝"
echo "██║██╔██╗ ██║█████╗  █████╗  ██████╔╝██╔██╗ ██║██║   ██║ ╚███╔╝ "
echo "██║██║╚██╗██║██╔══╝  ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║ ██╔██╗ "
echo "██║██║ ╚████║██║     ███████╗██║  ██║██║ ╚████║╚██████╔╝██╔╝ ██╗"
echo "╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${YELLOW}          Advanced SMS Spoofing Framework${NC}"
echo -e "${GREEN}        Optimized for Kali Linux & Pen Testing${NC}"
echo -e "${RED}              ⚠️  AUTHORIZED USE ONLY ⚠️${NC}"
echo ""

# Check if running on Kali
if [[ -f /etc/os-release ]] && grep -q "kali" /etc/os-release; then
    echo -e "${GREEN}✅ Kali Linux detected${NC}"
else
    echo -e "${YELLOW}⚠️  Not running on Kali (but continuing)${NC}"
fi

# Check Python
if command -v python3 &> /dev/null; then
    echo -e "${GREEN}✅ Python3 found${NC}"
else
    echo -e "${RED}❌ Python3 not found${NC}"
    echo -e "${BLUE}💡 Install with: sudo apt install python3 python3-pip${NC}"
    exit 1
fi

# Make scripts executable
chmod +x infernox.py 2>/dev/null

# Check for .env file
if [[ ! -f .env ]]; then
    if [[ -f .env.kali ]]; then
        echo -e "${YELLOW}📝 Creating .env from Kali template${NC}"
        cp .env.kali .env
    else
        echo -e "${YELLOW}⚠️  No .env file found - using defaults${NC}"
    fi
fi

echo -e "${BLUE}🚀 Starting Infernox...${NC}"
echo ""

# Start Infernox
python3 infernox.py
