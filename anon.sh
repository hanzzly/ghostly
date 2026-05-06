#!/bin/bash
# anon.sh - Simple Anonymous Toggle

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

case "$1" in
    "on")
        echo -e "${GREEN}[+] Enabling anonymous mode...${NC}"

        # Start Tor
        sudo systemctl start tor
        sleep 2

        # Change MAC
        sudo macchanger -r eth0 2>/dev/null

        # Set proxy
        export http_proxy="socks5://127.0.0.1:9050"
        export https_proxy="socks5://127.0.0.1:9050"

        echo -e "${GREEN}[+] Anonymous mode ON${NC}"
        echo "IP: $(curl --socks5 127.0.0.1:9050 -s https://ipinfo.io/ip)"
        ;;

    "off")
        echo -e "${RED}[+] Disabling anonymous mode...${NC}"

        # Stop Tor
        sudo systemctl stop tor

        # Reset MAC
        sudo macchanger -p eth0 2>/dev/null

        # Unset proxy
        unset http_proxy https_proxy

        echo -e "${RED}[+] Anonymous mode OFF${NC}"
        ;;

    "ip")
        echo -e "${GREEN}[+] Current IP:${NC}"
        curl --socks5 127.0.0.1:9050 -s https://ipinfo.io/ip || curl -s https://ipinfo.io/ip
        ;;

    *)
        echo "Usage: $0 [on|off|ip]"
        echo "  on   - Enable anonymity"
        echo "  off  - Disable anonymity"
        echo "  ip   - Check current IP"
        exit 1
        ;;
esac
