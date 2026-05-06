#!/bin/bash
# ghost.sh - Anonymous Mode Switcher
# Usage: sudo ./ghost.sh [on|off|status|check]

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Config
TOR_PORT="9050"
PRIVOXY_PORT="8118"
LOG_FILE="/tmp/ghost.log"

# Functions
log() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[!]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[*]${NC} $1" | tee -a "$LOG_FILE"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root: sudo ./ghost.sh"
        exit 1
    fi
}

install_deps() {
    log "Checking dependencies..."

    deps=("tor" "proxychains" "macchanger" "privoxy" "curl" "openvpn")
    missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        warning "Missing dependencies: ${missing[*]}"
        read -p "Install? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            apt update
            apt install -y tor proxychains macchanger privoxy curl openvpn
            log "Dependencies installed"
        fi
    fi
}

configure_proxychains() {
    log "Configuring proxychains..."

    cat > /etc/proxychains.conf << EOF
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0

[ProxyList]
socks5 127.0.0.1 $TOR_PORT
socks4 127.0.0.1 $TOR_PORT
http 127.0.0.1 $PRIVOXY_PORT
EOF

    log "Proxychains configured"
}

start_services() {
    log "Starting anonymous services..."

    # Stop networking temporarily
    systemctl stop NetworkManager 2>/dev/null

    # Change MAC address
    log "Changing MAC address..."
    for iface in $(ls /sys/class/net/ | grep -v lo); do
        macchanger -r "$iface" 2>/dev/null && log "MAC changed on $iface"
    done

    # Start Tor
    log "Starting Tor..."
    systemctl start tor
    sleep 3

    # Start Privoxy
    log "Starting Privoxy..."
    systemctl start privoxy

    # Configure DNS
    log "Configuring DNS..."
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null

    # Start networking
    systemctl start NetworkManager 2>/dev/null
    sleep 2

    # Set proxy environment
    export http_proxy="http://127.0.0.1:$PRIVOXY_PORT"
    export https_proxy="http://127.0.0.1:$PRIVOXY_PORT"
    export HTTP_PROXY="http://127.0.0.1:$PRIVOXY_PORT"
    export HTTPS_PROXY="http://127.0.0.1:$PRIVOXY_PORT"

    log "Anonymous mode activated!"
}

stop_services() {
    log "Stopping anonymous services..."

    # Unlock DNS
    chattr -i /etc/resolv.conf 2>/dev/null

    # Stop services
    systemctl stop tor
    systemctl stop privoxy

    # Reset MAC address
    log "Resetting MAC address..."
    for iface in $(ls /sys/class/net/ | grep -v lo); do
        macchanger -p "$iface" 2>/dev/null && log "MAC reset on $iface"
    done

    # Reset proxy environment
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY

    # Reset DNS
    systemctl restart systemd-resolved

    log "Anonymous mode deactivated!"
}

check_status() {
    log "Checking anonymous status..."

    echo -e "\n${BLUE}=== SYSTEM STATUS ===${NC}"

    # Check Tor
    if systemctl is-active --quiet tor; then
        echo -e "Tor: ${GREEN}Running${NC}"
    else
        echo -e "Tor: ${RED}Stopped${NC}"
    fi

    # Check Privoxy
    if systemctl is-active --quiet privoxy; then
        echo -e "Privoxy: ${GREEN}Running${NC}"
    else
        echo -e "Privoxy: ${RED}Stopped${NC}"
    fi

    # Check MAC
    echo -e "\n${BLUE}=== MAC ADDRESSES ===${NC}"
    for iface in $(ls /sys/class/net/ | grep -v lo); do
        mac=$(cat /sys/class/net/"$iface"/address 2>/dev/null)
        echo -e "$iface: $mac"
    done

    # Check IP
    echo -e "\n${BLUE}=== PUBLIC IP ===${NC}"
    timeout 10 curl --socks5-hostname 127.0.0.1:$TOR_PORT -s https://ipinfo.io/ip || echo "Cannot determine IP"

    # Check DNS
    echo -e "\n${BLUE}=== DNS LEAK TEST ===${NC}"
    timeout 10 curl --socks5-hostname 127.0.0.1:$TOR_PORT -s https://dnsleaktest.com | grep -oP 'Your IP address:[^<]*' || echo "Test failed"
}

test_anonymity() {
    log "Testing anonymity..."

    echo -e "\n${BLUE}=== TOR CHECK ===${NC}"
    curl --socks5-hostname 127.0.0.1:$TOR_PORT -s https://check.torproject.org | grep -oP 'Congratulations.[^<]*' || echo "Not using Tor"

    echo -e "\n${BLUE}=== IP INFO ===${NC}"
    curl --socks5-hostname 127.0.0.1:$TOR_PORT -s https://ipinfo.io | grep -E 'ip|city|country|org' | head -5

    echo -e "\n${BLUE}=== PROXY TEST ===${NC}"
    proxychains curl -s https://httpbin.org/ip | grep origin
}

enable_persistent() {
    log "Enabling persistent anonymous mode..."

    # Add to bashrc
    echo '
# Ghost Mode Aliases
alias ghost-on="sudo systemctl start tor && sudo systemctl start privoxy && export http_proxy=http://127.0.0.1:8118 && export https_proxy=http://127.0.0.1:8118"
alias ghost-off="sudo systemctl stop tor && sudo systemctl stop privoxy && unset http_proxy https_proxy"
alias ghost-status="systemctl status tor; systemctl status privoxy; curl --socks5 127.0.0.1:9050 https://ipinfo.io/ip"
' >> ~/.bashrc

    # Create systemd service
    cat > /etc/systemd/system/ghost-mode.service << EOF
[Unit]
Description=Ghost Anonymous Mode
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/ghost.sh on
ExecStop=/usr/local/bin/ghost.sh off

[Install]
WantedBy=multi-user.target
EOF

    log "Persistent mode enabled. Run: sudo systemctl enable ghost-mode"
}

# Main execution
case "$1" in
    "on"|"start"|"enable")
        check_root
        install_deps
        configure_proxychains
        start_services
        check_status
        ;;

    "off"|"stop"|"disable")
        check_root
        stop_services
        check_status
        ;;

    "status"|"check")
        check_status
        ;;

    "test")
        test_anonymity
        ;;

    "persistent"|"auto")
        enable_persistent
        ;;

    "install")
        check_root
        install_deps
        configure_proxychains
        cp "$0" /usr/local/bin/ghost
        chmod +x /usr/local/bin/ghost
        log "Installed to /usr/local/bin/ghost"
        ;;

    *)
        echo -e "${BLUE}Ghost Anonymous Mode Switcher${NC}"
        echo -e "${GREEN}Usage:${NC} sudo ./ghost.sh [command]"
        echo
        echo "Commands:"
        echo "  on/start     - Enable anonymous mode"
        echo "  off/stop     - Disable anonymous mode"
        echo "  status       - Check current status"
        echo "  test         - Test anonymity"
        echo "  install      - Install to system"
        echo "  persistent   - Enable auto-start"
        echo
        echo "Examples:"
        echo "  sudo ./ghost.sh on"
        echo "  sudo ./ghost.sh status"
        echo "  sudo ./ghost.sh test"
        exit 1
        ;;
esac

log "Operation completed. Log: $LOG_FILE"
