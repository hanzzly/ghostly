#!/usr/bin/env bash
#
# ghostly.sh - Hardened Anonymous Networking Toolkit
#

set -Eeuo pipefail

############################
# CONFIG
############################

VERSION="2.0"

TOR_PORT="9050"
TOR_DNS_PORT="5353"
TOR_TRANS_PORT="9040"
TOR_CONTROL_PORT="9051"

CONFIG_DIR="/etc/ghostly"
BACKUP_DIR="/var/lib/ghostly"
LOG_FILE="/var/log/ghostly.log"

TOR_USER="debian-tor"

BOOTSTRAP_TIMEOUT=60
MAC_RETRY=3

############################
# COLORS
############################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

############################
# LOGGING
############################

log() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$ts] [+] $1" >> "$LOG_FILE"
}

warn() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${YELLOW}[*]${NC} $1"
    echo "[$ts] [*] $1" >> "$LOG_FILE"
}

err() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${RED}[!]${NC} $1" >&2
    echo "[$ts] [!] $1" >> "$LOG_FILE"
}

die() {
    err "$1"
    exit 1
}

############################
# ROOT CHECK
############################

require_root() {
    [[ $EUID -eq 0 ]] || die "Run as root"
}

############################
# UTIL
############################

default_iface() {
    ip route | awk '/default/ {print $5}' | head -n1
}

check_binary() {
    command -v "$1" >/dev/null 2>&1 || die "Required binary not found: $1"
}

check_deps() {
    for bin in tor nc ip iptables macchanger curl sysctl; do
        check_binary "$bin"
    done
}

############################
# INSTALL
############################

install_deps() {
    log "Installing dependencies..."
    apt-get update -qq
    apt-get install -y \
        tor \
        torsocks \
        proxychains4 \
        macchanger \
        curl \
        iptables \
        iproute2 \
        netcat-openbsd \
        dnsutils
    log "Dependencies installed."
}

############################
# TOR CONFIG
############################

configure_tor() {
    log "Configuring Tor..."

    mkdir -p "$BACKUP_DIR" "$CONFIG_DIR"

    [[ -f /etc/tor/torrc ]] && \
        cp /etc/tor/torrc "$BACKUP_DIR/torrc.bak"

    local hashed_pass
    hashed_pass="$(tor --hash-password "ghostly_ctrl_$(hostname)" 2>/dev/null | tail -1)"

    cat > /etc/tor/torrc <<EOF
SocksPort $TOR_PORT
ControlPort $TOR_CONTROL_PORT

## Auth
HashedControlPassword $hashed_pass
CookieAuthentication 0

## Performance & safety
AvoidDiskWrites 1
HardwareAccel 1
SafeLogging 1
ClientOnly 1
StrictNodes 0

## Transparent proxy setup
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort $TOR_TRANS_PORT IsolateClientAddr IsolateClientProtocol
DNSPort $TOR_DNS_PORT

## Prevent DNS leak
AutomapHostsSuffixes .onion,.exit
EOF

    echo "ghostly_ctrl_$(hostname)" > "$CONFIG_DIR/.ctrl_pass"
    chmod 600 "$CONFIG_DIR/.ctrl_pass"

    systemctl restart tor
    log "Tor configured."
}

############################
# WAIT FOR TOR BOOTSTRAP
############################

wait_for_tor() {
    log "Waiting for Tor to bootstrap (timeout: ${BOOTSTRAP_TIMEOUT}s)..."

    local elapsed=0

    while (( elapsed < BOOTSTRAP_TIMEOUT )); do
        if journalctl -u tor --since "5 minutes ago" --no-pager -q 2>/dev/null \
            | grep -q "Bootstrapped 100%"; then
            log "Tor bootstrapped successfully."
            return 0
        fi
        sleep 2
        (( elapsed += 2 ))
    done

    if nc -z 127.0.0.1 "$TOR_PORT" 2>/dev/null; then
        warn "Bootstrap log not found, but SOCKS port is open. Proceeding."
        return 0
    fi

    die "Tor failed to bootstrap within ${BOOTSTRAP_TIMEOUT}s. Aborting."
}

############################
# DNS
############################

configure_dns() {
    log "Configuring DNS over Tor..."

    mkdir -p "$BACKUP_DIR"

    [[ -f /etc/resolv.conf ]] && \
        cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf.bak"

    chattr -i /etc/resolv.conf 2>/dev/null || true

    cat > /etc/resolv.conf <<EOF
# Ghostly - DNS via Tor
nameserver 127.0.0.1
options timeout:1 attempts:1
EOF

    chattr +i /etc/resolv.conf 2>/dev/null || true
    log "DNS locked to 127.0.0.1."
}

restore_dns() {
    log "Restoring DNS..."

    chattr -i /etc/resolv.conf 2>/dev/null || true

    if [[ -f "$BACKUP_DIR/resolv.conf.bak" ]]; then
        cp "$BACKUP_DIR/resolv.conf.bak" /etc/resolv.conf
        log "DNS restored."
    else
        warn "No DNS backup found. Falling back to 8.8.8.8."
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
    fi
}

############################
# IPV6
############################

disable_ipv6() {
    log "Disabling IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=1     >/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1       >/dev/null

    cat > /etc/sysctl.d/99-ghostly-no-ipv6.conf <<EOF
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
    log "IPv6 disabled."
}

enable_ipv6() {
    log "Re-enabling IPv6..."
    rm -f /etc/sysctl.d/99-ghostly-no-ipv6.conf
    sysctl -w net.ipv6.conf.all.disable_ipv6=0     >/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0       >/dev/null
    log "IPv6 re-enabled."
}

############################
# MAC SPOOF
############################

spoof_mac() {
    local iface
    iface="$(default_iface)"

    [[ -z "$iface" ]] && { err "No network interface found"; return 1; }

    log "Spoofing MAC on $iface..."

    local attempt=0
    while (( attempt < MAC_RETRY )); do
        ip link set "$iface" down
        sleep 1
        if macchanger -r "$iface" 2>/dev/null; then
            ip link set "$iface" up
            local new_mac
            new_mac="$(cat /sys/class/net/"$iface"/address)"
            log "MAC spoofed → $new_mac"
            return 0
        fi
        ip link set "$iface" up
        (( attempt++ ))
        warn "MAC spoof attempt $attempt failed, retrying..."
        sleep 2
    done

    err "MAC spoofing failed after $MAC_RETRY attempts."
}

restore_mac() {
    local iface
    iface="$(default_iface)"
    [[ -z "$iface" ]] && return

    log "Restoring original MAC on $iface..."
    ip link set "$iface" down
    sleep 1
    macchanger -p "$iface" 2>/dev/null || true
    ip link set "$iface" up
    log "MAC restored."
}

############################
# FIREWALL
############################

backup_iptables() {
    mkdir -p "$BACKUP_DIR"
    iptables-save > "$BACKUP_DIR/iptables.bak"
}

restore_iptables() {
    if [[ -f "$BACKUP_DIR/iptables.bak" ]]; then
        iptables-restore < "$BACKUP_DIR/iptables.bak"
        log "iptables restored."
    else
        warn "No iptables backup found. Flushing to ACCEPT all."
        iptables -F
        iptables -t nat -F
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
    fi
}

configure_firewall() {
    log "Applying kill-switch firewall..."

    backup_iptables

    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    iptables -X 2>/dev/null || true

    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  DROP

    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    iptables -A OUTPUT \
        -m owner --uid-owner "$TOR_USER" \
        -j ACCEPT

    # Skip loopback — nf_tables requires negation immediately after the flag,
    # so we use RETURN rules instead of ! -d / ! -m owner
    iptables -t nat -A OUTPUT \
        -p tcp --syn \
        -d 127.0.0.0/8 \
        -j RETURN

    # Skip Tor daemon's own traffic
    iptables -t nat -A OUTPUT \
        -p tcp --syn \
        -m owner --uid-owner "$TOR_USER" \
        -j RETURN

    # Redirect everything else through TransPort
    iptables -t nat -A OUTPUT \
        -p tcp --syn \
        -j REDIRECT --to-ports "$TOR_TRANS_PORT"

    iptables -t nat -A OUTPUT \
        -p udp --dport 53 \
        -j REDIRECT --to-ports "$TOR_DNS_PORT"

    iptables -t nat -A OUTPUT \
        -p tcp --dport 53 \
        -j REDIRECT --to-ports "$TOR_DNS_PORT"

    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP

    iptables -A OUTPUT -j DROP

    log "Kill-switch firewall applied."
}

############################
# VERIFY IP IS TOR
############################

verify_tor_ip() {
    log "Verifying public IP is via Tor..."

    local ip
    ip="$(torsocks curl -s --max-time 10 https://ipinfo.io/ip 2>/dev/null || true)"

    if [[ -z "$ip" ]]; then
        warn "Could not fetch public IP. Check Tor connectivity."
        return 1
    fi

    local tor_check
    tor_check="$(torsocks curl -s --max-time 10 https://check.torproject.org/api/ip 2>/dev/null || true)"

    if echo "$tor_check" | grep -q '"IsTor":true'; then
        log "Confirmed: traffic is routed through Tor. IP: $ip"
    else
        warn "WARNING: Tor check inconclusive. IP: $ip"
    fi
}

############################
# START
############################

start_ghostly() {
    require_root
    check_deps

    log "==============================="
    log "  Starting Ghostly"
    log "==============================="

    configure_tor
    spoof_mac
    disable_ipv6
    configure_dns
    configure_firewall

    systemctl restart tor
    wait_for_tor
    verify_tor_ip

    log "Ghostly ACTIVE."
    log "All traffic is routed through Tor."
}

############################
# STOP
############################

stop_ghostly() {
    require_root

    log "==============================="
    log "  Stopping Ghostly"
    log "==============================="

    restore_iptables
    restore_dns
    restore_mac
    enable_ipv6

    systemctl stop tor

    rm -f "$CONFIG_DIR/.ctrl_pass"

    log "Ghostly DISABLED."
    warn "Your real IP is now exposed."
}

############################
# ROTATE CIRCUIT
############################

rotate_tor() {
    require_root

    log "Requesting new Tor circuit..."

    local ctrl_pass=""
    [[ -f "$CONFIG_DIR/.ctrl_pass" ]] && \
        ctrl_pass="$(cat "$CONFIG_DIR/.ctrl_pass")"

    if [[ -z "$ctrl_pass" ]]; then
        err "No control password found. Is Ghostly active?"
        return 1
    fi

    printf "AUTHENTICATE \"%s\"\r\nSIGNAL NEWNYM\r\nQUIT\r\n" "$ctrl_pass" \
        | nc 127.0.0.1 "$TOR_CONTROL_PORT" >/dev/null 2>&1

    log "Waiting 10s for new circuit to establish..."
    sleep 10

    verify_tor_ip
    log "Circuit rotated."
}

############################
# STATUS
############################

status_ghostly() {
    echo
    echo -e "${BLUE}=================================${NC}"
    echo -e "${BLUE}          GHOSTLY STATUS         ${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo

    echo -n "  Tor service  : "
    systemctl is-active tor 2>/dev/null || echo "inactive"

    echo -n "  SOCKS port   : "
    nc -z 127.0.0.1 "$TOR_PORT" 2>/dev/null \
        && echo "open ($TOR_PORT)" || echo "CLOSED"

    echo -n "  Public IP    : "
    torsocks curl -s --max-time 8 https://ipinfo.io/ip 2>/dev/null \
        || echo "unavailable"
    echo

    echo -n "  Interface    : "
    default_iface

    echo -n "  MAC address  : "
    cat /sys/class/net/"$(default_iface)"/address 2>/dev/null || echo "unknown"

    echo -n "  IPv6 disabled: "
    sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown"

    echo -n "  DNS server   : "
    grep "nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -1

    echo -n "  iptables     : "
    local rules
    rules="$(iptables -L OUTPUT --line-numbers 2>/dev/null | wc -l)"
    echo "$rules rules active"

    echo
}

############################
# LEAK TEST
############################

leak_test() {
    log "Running comprehensive leak test..."

    echo
    echo -e "${BLUE}===== TOR CHECK =====${NC}"
    torsocks curl -s --max-time 10 https://check.torproject.org/api/ip 2>/dev/null \
        | python3 -m json.tool 2>/dev/null || echo "unavailable"

    echo
    echo -e "${BLUE}===== PUBLIC IP =====${NC}"
    torsocks curl -s --max-time 10 https://ipinfo.io 2>/dev/null \
        | python3 -m json.tool 2>/dev/null || echo "unavailable"

    echo
    echo -e "${BLUE}===== DNS LEAK =====${NC}"
    torsocks curl -s --max-time 10 "https://bash.ws/dnsleak/test/$RANDOM" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null || \
        torsocks dig +short TXT whoami.cloudflare @1.1.1.1 2>/dev/null || \
        echo "DNS test unavailable"

    echo
    echo -e "${BLUE}===== WEBRTC =====${NC}"
    echo "  WebRTC cannot be tested from CLI."
    echo "  Open: https://browserleaks.com/webrtc"

    echo
    echo -e "${BLUE}===== IPV6 LEAK =====${NC}"
    if sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "1"; then
        echo "  IPv6 is disabled. No IPv6 leak possible."
    else
        warn "  IPv6 is ENABLED. Risk of IPv6 leak!"
    fi

    echo
}

############################
# MENU
############################

menu() {
    while true; do
        clear
        echo -e "${BLUE}=================================${NC}"
        echo -e "${BLUE}            GHOSTLY              ${NC}"
        echo -e "${BLUE}=================================${NC}"
        echo
        echo "  1. Enable Ghostly"
        echo "  2. Disable Ghostly"
        echo "  3. Rotate Tor Circuit"
        echo "  4. Status"
        echo "  5. Leak Test"
        echo "  6. Exit"
        echo

        read -rp "Select [1-6]: " choice

        case "$choice" in
            1) start_ghostly  ;;
            2) stop_ghostly   ;;
            3) rotate_tor     ;;
            4) status_ghostly ;;
            5) leak_test      ;;
            6) exit 0         ;;
            *) warn "Invalid option" ;;
        esac

        echo
        read -rp "Press Enter to continue..."
    done
}

############################
# MAIN
############################

mkdir -p "$(dirname "$LOG_FILE")" "$CONFIG_DIR"

case "${1:-}" in
    install)
        require_root
        install_deps
        ;;
    on|start)
        start_ghostly
        ;;
    off|stop)
        stop_ghostly
        ;;
    rotate)
        rotate_tor
        ;;
    status)
        status_ghostly
        ;;
    leak-test)
        leak_test
        ;;
    menu)
        menu
        ;;
    -v|--version|version)
        echo "Ghostly v${VERSION}"
        ;;
    *)
        echo
        echo "Ghostly - Hardened Anonymous Networking Toolkit"
        echo
        echo "Usage:"
        echo "  sudo ghostly install       Install dependencies"
        echo "  sudo ghostly on            Enable Ghostly"
        echo "  sudo ghostly off           Disable Ghostly"
        echo "  sudo ghostly rotate        Rotate Tor circuit"
        echo "  sudo ghostly status        Show current status"
        echo "  sudo ghostly leak-test     Run leak tests"
        echo "  sudo ghostly menu          Interactive menu"
        echo "  ghostly --version          Show version"
        echo
        ;;
esac
