#!/usr/bin/env bash
#
# ghostly.sh - Production-Grade Hardened Anonymity Toolkit
# https://github.com/hanzzly/ghostly
#

set -Eeuo pipefail

############################
# VERSION
############################

VERSION="3.0"

############################
# PORTS
############################

TOR_PORT="9050"
TOR_DNS_PORT="5353"
TOR_TRANS_PORT="9040"
TOR_CONTROL_PORT="9051"

############################
# PATHS
############################

CONFIG_DIR="/etc/ghostly"
BACKUP_DIR="/var/lib/ghostly"
LOG_FILE="/var/log/ghostly.log"
TORRC_SNIPPET="/etc/tor/torrc.d/ghostly.conf"
COOKIE_FILE="/run/tor/control.authcookie"
STATE_FILE="/var/lib/ghostly/state"

############################
# DEFAULTS
############################

TOR_USER="debian-tor"
BOOTSTRAP_TIMEOUT=90
MAC_RETRY=3
MODE="${GHOSTLY_MODE:-balanced}"   # strict | balanced | safe

# LAN ranges excluded from Tor redirect
LAN_RANGES=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "169.254.0.0/16"   # link-local
    "100.64.0.0/10"    # CGNAT
)

############################
# COLORS
############################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

############################
# LOGGING
############################

log() {
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$ts] [+] $1" >> "$LOG_FILE"
}

warn() {
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${YELLOW}[*]${NC} $1"
    echo "[$ts] [*] $1" >> "$LOG_FILE"
}

err() {
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${RED}[!]${NC} $1" >&2
    echo "[$ts] [!] $1" >> "$LOG_FILE"
}

info() {
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${CYAN}[i]${NC} $1"
    echo "[$ts] [i] $1" >> "$LOG_FILE"
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
# DEPENDENCY CHECK
############################

check_deps() {
    local missing=()
    for bin in tor nc ip sysctl curl; do
        command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required binaries: ${missing[*]}. Run: sudo ghostly install"
    fi
}

############################
# FIREWALL BACKEND DETECT
############################

# Returns: iptables-legacy | iptables-nft | nftables
detect_fw_backend() {
    if command -v nft >/dev/null 2>&1 && nft list tables &>/dev/null; then
        # Check if iptables is actually nft wrapper
        if iptables --version 2>/dev/null | grep -q "nf_tables"; then
            echo "iptables-nft"
        else
            echo "nftables"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        if iptables --version 2>/dev/null | grep -q "legacy"; then
            echo "iptables-legacy"
        else
            echo "iptables-nft"
        fi
    else
        echo "unknown"
    fi
}

# Wrapper: use iptables-legacy if available to avoid nf_tables quirks
ipt() {
    if command -v iptables-legacy >/dev/null 2>&1; then
        iptables-legacy "$@"
    else
        iptables "$@"
    fi
}

ipt_save() {
    if command -v iptables-legacy-save >/dev/null 2>&1; then
        iptables-legacy-save "$@"
    else
        iptables-save "$@"
    fi
}

ipt_restore() {
    if command -v iptables-legacy-restore >/dev/null 2>&1; then
        iptables-legacy-restore "$@"
    else
        iptables-restore "$@"
    fi
}

############################
# VIRTUALIZATION DETECT
############################

VIRT_TYPE="none"
SKIP_MAC=0

detect_virt() {
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        VIRT_TYPE="$(systemd-detect-virt 2>/dev/null || echo 'none')"
    elif [[ -f /proc/1/environ ]] && grep -q "container=lxc" /proc/1/environ 2>/dev/null; then
        VIRT_TYPE="lxc"
    elif [[ -f /.dockerenv ]]; then
        VIRT_TYPE="docker"
    elif grep -qi "microsoft" /proc/version 2>/dev/null; then
        VIRT_TYPE="wsl"
    else
        VIRT_TYPE="none"
    fi

    case "$VIRT_TYPE" in
        wsl|wsl2|microsoft|docker|lxc|lxc-libvirt|openvz|podman)
            SKIP_MAC=1
            warn "Virtualization detected: $VIRT_TYPE — MAC spoofing will be skipped."
            ;;
        kvm|qemu|vmware|hyperv|xen|amazon|azure|gce|oracle)
            SKIP_MAC=1
            warn "VM/cloud environment: $VIRT_TYPE — MAC spoofing will be skipped."
            ;;
        none|bare-metal|*)
            SKIP_MAC=0
            ;;
    esac
}

############################
# NETWORK MANAGER DETECT
############################

detect_netman() {
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        echo "NetworkManager"
    elif systemctl is-active --quiet systemd-networkd 2>/dev/null; then
        echo "systemd-networkd"
    elif systemctl is-active --quiet networking 2>/dev/null; then
        echo "ifupdown"
    else
        echo "unknown"
    fi
}

############################
# UTIL
############################

default_iface() {
    ip route | awk '/default/ {print $5}' | head -n1
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
        iptables-persistent \
        iproute2 \
        netcat-openbsd \
        dnsutils \
        nftables
    log "Dependencies installed."
}

############################
# ROUTE BACKUP & RESTORE
############################

backup_routes() {
    mkdir -p "$BACKUP_DIR"
    ip route show > "$BACKUP_DIR/routes.bak"
    ip rule show  > "$BACKUP_DIR/rules.bak"
    log "Routing table backed up."
}

restore_routes() {
    if [[ -f "$BACKUP_DIR/routes.bak" ]]; then
        log "Restoring routing table..."
        # Only restore default route to avoid conflicts
        local default_gw
        default_gw="$(grep '^default' "$BACKUP_DIR/routes.bak" | head -1 || true)"
        if [[ -n "$default_gw" ]]; then
            ip route replace $default_gw 2>/dev/null || true
        fi
        log "Routes restored."
    fi
}

############################
# TOR CONFIG (torrc.d)
############################

configure_tor() {
    log "Configuring Tor..."

    mkdir -p "$BACKUP_DIR" "$CONFIG_DIR"

    # Ensure torrc.d includes are enabled
    if [[ -f /etc/tor/torrc ]] && ! grep -q "torrc.d" /etc/tor/torrc; then
        echo "" >> /etc/tor/torrc
        echo "# Ghostly includes" >> /etc/tor/torrc
        echo "%include /etc/tor/torrc.d/*.conf" >> /etc/tor/torrc
    fi
    mkdir -p /etc/tor/torrc.d

    # Mode-specific circuit options
    local entry_nodes="" exit_nodes="" strict_nodes="0" max_circuits="32"
    case "$MODE" in
        strict)
            strict_nodes="1"
            max_circuits="8"
            warn "Mode: STRICT — reduced circuit count, StrictNodes enabled."
            ;;
        safe)
            max_circuits="64"
            info "Mode: SAFE — more circuits, more permissive."
            ;;
        balanced|*)
            max_circuits="32"
            info "Mode: BALANCED"
            ;;
    esac

    # Write snippet — CookieAuthentication, no plaintext password
    cat > "$TORRC_SNIPPET" <<EOF
## Ghostly v${VERSION} — auto-generated, do not edit manually
## Mode: ${MODE}

SocksPort ${TOR_PORT}
ControlPort ${TOR_CONTROL_PORT}

## Auth via cookie (no plaintext password)
CookieAuthentication 1
CookieAuthFile ${COOKIE_FILE}
CookieAuthFileGroupReadable 1

## Performance & safety
AvoidDiskWrites 1
HardwareAccel 1
SafeLogging 1
ClientOnly 1
StrictNodes ${strict_nodes}
MaxCircuitDirtiness 600
NewCircuitPeriod 30
MaxClientCircuitsPending ${max_circuits}

## Transparent proxy
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit
TransPort ${TOR_TRANS_PORT} IsolateClientAddr IsolateClientProtocol
DNSPort ${TOR_DNS_PORT}
EOF

    chmod 644 "$TORRC_SNIPPET"

    # Validate config before restarting
    if ! tor --verify-config --torrc-file /etc/tor/torrc &>/dev/null; then
        err "Tor config validation failed. Check $TORRC_SNIPPET"
        return 1
    fi

    systemctl restart tor
    log "Tor configured (mode: $MODE, cookie auth)."
}

############################
# WAIT FOR TOR BOOTSTRAP
############################

wait_for_tor() {
    log "Waiting for Tor bootstrap (timeout: ${BOOTSTRAP_TIMEOUT}s)..."

    local elapsed=0
    while (( elapsed < BOOTSTRAP_TIMEOUT )); do
        # Primary: journalctl bootstrap check
        if journalctl -u tor --since "2 minutes ago" --no-pager -q 2>/dev/null \
            | grep -q "Bootstrapped 100%"; then
            log "Tor bootstrapped (journal confirmed)."
            return 0
        fi

        # Secondary: Tor control port GETINFO
        if [[ -r "$COOKIE_FILE" ]] && nc -z 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null; then
            local status
            status="$(echo -e "AUTHENTICATE\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n" \
                | nc -q1 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null \
                | grep "PROGRESS=100" || true)"
            if [[ -n "$status" ]]; then
                log "Tor bootstrapped (control port confirmed)."
                return 0
            fi
        fi

        sleep 2
        (( elapsed += 2 ))
        echo -ne "\r${YELLOW}[*]${NC} Bootstrapping... ${elapsed}s / ${BOOTSTRAP_TIMEOUT}s"
    done
    echo

    # Fallback: SOCKS port open
    if nc -z 127.0.0.1 "$TOR_PORT" 2>/dev/null; then
        warn "Bootstrap log not confirmed, but SOCKS port is open. Proceeding with caution."
        return 0
    fi

    return 1  # Caller handles this — do NOT die here (rollback needed)
}

############################
# VERIFY IP VIA TOR
############################

verify_tor_ip() {
    log "Verifying traffic exits via Tor..."

    local ip tor_check
    ip="$(torsocks curl -s --max-time 10 https://ipinfo.io/ip 2>/dev/null || true)"
    tor_check="$(torsocks curl -s --max-time 10 https://check.torproject.org/api/ip 2>/dev/null || true)"

    if [[ -z "$ip" ]]; then
        warn "Could not fetch public IP. Tor may not be fully up yet."
        return 1
    fi

    if echo "$tor_check" | grep -q '"IsTor":true'; then
        log "Verified: Tor exit confirmed. IP: $ip"
    else
        warn "Tor check inconclusive. IP: $ip — traffic may not be anonymized."
    fi
}

############################
# DNS
############################

configure_dns() {
    log "Locking DNS to Tor (127.0.0.1)..."

    [[ -f /etc/resolv.conf ]] && \
        cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf.bak"

    chattr -i /etc/resolv.conf 2>/dev/null || true
    cat > /etc/resolv.conf <<EOF
# Ghostly - DNS via Tor DNSPort
nameserver 127.0.0.1
options timeout:1 attempts:1
EOF
    chattr +i /etc/resolv.conf 2>/dev/null || true
    log "DNS locked."
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
    if [[ "$SKIP_MAC" -eq 1 ]]; then
        warn "Skipping MAC spoof (virt: $VIRT_TYPE)."
        return 0
    fi

    local iface; iface="$(default_iface)"
    [[ -z "$iface" ]] && { err "No network interface found"; return 1; }

    if ! command -v macchanger >/dev/null 2>&1; then
        warn "macchanger not found, skipping MAC spoof."
        return 0
    fi

    log "Spoofing MAC on $iface..."
    local attempt=0
    while (( attempt < MAC_RETRY )); do
        ip link set "$iface" down
        sleep 1
        if macchanger -r "$iface" 2>/dev/null; then
            ip link set "$iface" up
            local new_mac; new_mac="$(cat /sys/class/net/"$iface"/address)"
            log "MAC spoofed → $new_mac"
            return 0
        fi
        ip link set "$iface" up
        (( attempt++ ))
        warn "MAC spoof attempt $attempt failed, retrying..."
        sleep 2
    done
    warn "MAC spoofing failed after $MAC_RETRY attempts. Continuing anyway."
}

restore_mac() {
    if [[ "$SKIP_MAC" -eq 1 ]]; then return 0; fi
    local iface; iface="$(default_iface)"
    [[ -z "$iface" ]] && return
    command -v macchanger >/dev/null 2>&1 || return

    log "Restoring original MAC on $iface..."
    ip link set "$iface" down
    sleep 1
    macchanger -p "$iface" 2>/dev/null || true
    ip link set "$iface" up
    log "MAC restored."
}

############################
# FIREWALL (iptables-safe)
# Uses RETURN-based exclusions (nf_tables compat)
# OUTPUT DROP applied ONLY after Tor verified
############################

backup_firewall() {
    mkdir -p "$BACKUP_DIR"
    ipt_save > "$BACKUP_DIR/iptables.bak"
}

restore_firewall() {
    if [[ -f "$BACKUP_DIR/iptables.bak" ]]; then
        ipt_restore < "$BACKUP_DIR/iptables.bak" 2>/dev/null || true
        log "Firewall restored."
    else
        warn "No firewall backup. Resetting to ACCEPT-all."
        ipt -F; ipt -t nat -F; ipt -t mangle -F
        ipt -P INPUT ACCEPT
        ipt -P FORWARD ACCEPT
        ipt -P OUTPUT ACCEPT
    fi
}

configure_firewall() {
    log "Applying kill-switch firewall (mode: $MODE)..."
    backup_firewall

    # Flush
    ipt -F
    ipt -t nat -F
    ipt -t mangle -F
    ipt -X 2>/dev/null || true

    # Policies — start PERMISSIVE, tighten after Tor verified
    ipt -P INPUT   DROP
    ipt -P FORWARD DROP
    ipt -P OUTPUT  ACCEPT   # ← stays ACCEPT until Tor confirmed

    # Loopback
    ipt -A INPUT  -i lo -j ACCEPT
    ipt -A OUTPUT -o lo -j ACCEPT

    # Established
    ipt -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Tor daemon always allowed
    ipt -A OUTPUT -m owner --uid-owner "$TOR_USER" -j ACCEPT

    # NAT: skip loopback
    ipt -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN
    ipt -t nat -A OUTPUT -p tcp -m owner --uid-owner "$TOR_USER" -j RETURN

    # NAT: LAN exclusions (mode-aware)
    if [[ "$MODE" != "strict" ]]; then
        for lan in "${LAN_RANGES[@]}"; do
            ipt -t nat -A OUTPUT -p tcp -d "$lan" -j RETURN
            ipt -t nat -A OUTPUT -p udp -d "$lan" -j RETURN
        done
        log "LAN ranges excluded from Tor redirect."
    else
        warn "Strict mode: LAN traffic also redirected through Tor."
    fi

    # NAT: redirect TCP through Tor TransPort
    ipt -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports "$TOR_TRANS_PORT"

    # NAT: redirect DNS through Tor DNSPort
    ipt -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "$TOR_DNS_PORT"
    ipt -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "$TOR_DNS_PORT"

    # Explicit DNS leak prevention
    ipt -A OUTPUT -p udp --dport 53 -m owner --uid-owner "$TOR_USER" -j ACCEPT
    ipt -A OUTPUT -p tcp --dport 53 -m owner --uid-owner "$TOR_USER" -j ACCEPT

    log "Firewall applied (OUTPUT still ACCEPT — awaiting Tor verification)."
}

# Called after Tor is verified — tightens OUTPUT to DROP
apply_killswitch() {
    log "Activating kill-switch (OUTPUT → DROP)..."
    ipt -P OUTPUT DROP

    # Ensure Tor owner rule is in place as safety net
    ipt -A OUTPUT -m owner --uid-owner "$TOR_USER" -j ACCEPT 2>/dev/null || true

    log "Kill-switch active. All non-Tor traffic blocked."
}

############################
# ERROR TRAP & ROLLBACK
############################

_ROLLBACK_DONE=0

cleanup_on_error() {
    local exit_code=$?
    [[ "$_ROLLBACK_DONE" -eq 1 ]] && return
    _ROLLBACK_DONE=1

    echo
    err "Error occurred (exit $exit_code). Rolling back all changes..."

    # Always restore OUTPUT to ACCEPT first — prevent network lockout
    ipt -P OUTPUT ACCEPT 2>/dev/null || true
    ipt -P INPUT  ACCEPT 2>/dev/null || true

    restore_firewall
    restore_dns
    restore_mac
    enable_ipv6
    restore_routes

    systemctl stop tor 2>/dev/null || true
    rm -f "$TORRC_SNIPPET" 2>/dev/null || true

    echo
    warn "Rollback complete. Your original network config has been restored."
    warn "Check $LOG_FILE for details."
}

############################
# STATE TRACKING
############################

save_state() {
    echo "active" > "$STATE_FILE"
    echo "MODE=$MODE" >> "$STATE_FILE"
    echo "VIRT=$VIRT_TYPE" >> "$STATE_FILE"
    echo "STARTED=$(date '+%Y-%m-%d %H:%M:%S')" >> "$STATE_FILE"
}

clear_state() {
    rm -f "$STATE_FILE"
}

is_active() {
    [[ -f "$STATE_FILE" ]] && grep -q "^active" "$STATE_FILE" 2>/dev/null
}

############################
# START
############################

start_ghostly() {
    require_root
    check_deps
    detect_virt

    if is_active; then
        warn "Ghostly appears to already be active. Run 'ghostly off' first."
        return 1
    fi

    # Register rollback trap
    trap cleanup_on_error ERR

    log "==============================="
    log "  Starting Ghostly v${VERSION}"
    log "  Mode: ${MODE}"
    log "==============================="

    # 1. Backup current state
    backup_routes

    # 2. Configure Tor (write torrc.d snippet, restart)
    configure_tor

    # 3. Spoof MAC before network changes
    spoof_mac

    # 4. Disable IPv6
    disable_ipv6

    # 5. Apply firewall in permissive mode (OUTPUT still ACCEPT)
    configure_firewall

    # 6. Wait for Tor to fully bootstrap
    if ! wait_for_tor; then
        err "Tor failed to bootstrap within ${BOOTSTRAP_TIMEOUT}s."
        err "Rolling back to prevent network lockout..."
        cleanup_on_error
        exit 1
    fi

    # 7. Verify exit IP is Tor
    verify_tor_ip

    # 8. Lock DNS now that Tor is confirmed up
    configure_dns

    # 9. Activate kill-switch (OUTPUT → DROP)
    apply_killswitch

    # 10. Save state
    save_state

    # Remove trap (clean start)
    trap - ERR

    echo
    log "==============================="
    log "  Ghostly ACTIVE"
    log "==============================="
}

############################
# STOP
############################

stop_ghostly() {
    require_root

    log "==============================="
    log "  Stopping Ghostly"
    log "==============================="

    # Always restore OUTPUT first
    ipt -P OUTPUT ACCEPT 2>/dev/null || true
    ipt -P INPUT  ACCEPT 2>/dev/null || true

    restore_firewall
    restore_dns
    restore_mac
    enable_ipv6
    restore_routes

    systemctl stop tor 2>/dev/null || true
    rm -f "$TORRC_SNIPPET" 2>/dev/null || true
    clear_state

    log "Ghostly DISABLED."
    warn "Your real IP is now exposed."
}

############################
# ROTATE CIRCUIT
############################

rotate_tor() {
    require_root

    log "Requesting new Tor circuit..."

    if ! nc -z 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null; then
        err "Tor control port not reachable. Is Ghostly active?"
        return 1
    fi

    # Cookie auth — read binary cookie and hex-encode it
    if [[ ! -r "$COOKIE_FILE" ]]; then
        err "Tor cookie not readable: $COOKIE_FILE"
        err "Ensure you are root and Tor is running."
        return 1
    fi

    local cookie_hex
    cookie_hex="$(xxd -p "$COOKIE_FILE" | tr -d '\n')"

    printf "AUTHENTICATE %s\r\nSIGNAL NEWNYM\r\nQUIT\r\n" "$cookie_hex" \
        | nc -q1 127.0.0.1 "$TOR_CONTROL_PORT" >/dev/null 2>&1

    # Tor enforces 10s minimum between NEWNYM
    log "Waiting 10s for new circuit..."
    sleep 10

    verify_tor_ip
    log "Circuit rotated."
}

############################
# STATUS
############################

status_ghostly() {
    echo
    echo -e "${BLUE}${BOLD}=================================${NC}"
    echo -e "${BLUE}${BOLD}          GHOSTLY STATUS         ${NC}"
    echo -e "${BLUE}${BOLD}=================================${NC}"
    echo

    echo -n "  Active       : "
    if is_active; then
        echo -e "${GREEN}YES${NC}"
    else
        echo -e "${RED}NO${NC}"
    fi

    echo -n "  Mode         : "
    if [[ -f "$STATE_FILE" ]]; then
        grep "^MODE=" "$STATE_FILE" | cut -d= -f2
    else
        echo "$MODE"
    fi

    echo -n "  Virt type    : "
    detect_virt 2>/dev/null; echo "$VIRT_TYPE"

    echo -n "  Network mgr  : "; detect_netman
    echo -n "  FW backend   : "; detect_fw_backend

    echo
    echo -n "  Tor service  : "
    systemctl is-active tor 2>/dev/null || echo "inactive"

    echo -n "  SOCKS port   : "
    nc -z 127.0.0.1 "$TOR_PORT" 2>/dev/null \
        && echo "open ($TOR_PORT)" || echo -e "${RED}CLOSED${NC}"

    echo -n "  Control port : "
    nc -z 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null \
        && echo "open ($TOR_CONTROL_PORT)" || echo -e "${RED}CLOSED${NC}"

    echo -n "  Public IP    : "
    torsocks curl -s --max-time 8 https://ipinfo.io/ip 2>/dev/null \
        || echo "unavailable"
    echo

    echo -n "  Interface    : "; default_iface
    echo -n "  MAC address  : "
    local iface; iface="$(default_iface)"
    cat /sys/class/net/"$iface"/address 2>/dev/null || echo "unknown"

    echo -n "  IPv6 disabled: "
    sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown"

    echo -n "  DNS server   : "
    grep "^nameserver" /etc/resolv.conf 2>/dev/null \
        | awk '{print $2}' | head -1 || echo "unknown"

    echo -n "  Kill-switch  : "
    ipt -L OUTPUT -n 2>/dev/null | grep -q "DROP" \
        && echo -e "${GREEN}ACTIVE${NC}" || echo -e "${YELLOW}inactive${NC}"

    echo
}

############################
# DIAGNOSTICS
############################

diagnostics() {
    echo
    echo -e "${BLUE}${BOLD}=================================${NC}"
    echo -e "${BLUE}${BOLD}      GHOSTLY DIAGNOSTICS        ${NC}"
    echo -e "${BLUE}${BOLD}=================================${NC}"
    echo

    echo -e "${BOLD}Environment:${NC}"
    detect_virt 2>/dev/null
    echo "  Virt type      : $VIRT_TYPE"
    echo "  Skip MAC spoof : $([[ $SKIP_MAC -eq 1 ]] && echo YES || echo NO)"
    echo "  Network manager: $(detect_netman)"
    echo "  FW backend     : $(detect_fw_backend)"
    echo "  Kernel         : $(uname -r)"
    echo "  OS             : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)"

    echo
    echo -e "${BOLD}Tor:${NC}"
    echo "  Service        : $(systemctl is-active tor 2>/dev/null || echo inactive)"
    echo "  SOCKS port     : $(nc -z 127.0.0.1 $TOR_PORT 2>/dev/null && echo OPEN || echo CLOSED)"
    echo "  Control port   : $(nc -z 127.0.0.1 $TOR_CONTROL_PORT 2>/dev/null && echo OPEN || echo CLOSED)"
    echo "  Cookie file    : $([[ -f "$COOKIE_FILE" ]] && echo EXISTS || echo MISSING)"
    echo "  torrc.d snippet: $([[ -f "$TORRC_SNIPPET" ]] && echo EXISTS || echo NOT FOUND)"

    echo
    echo -e "${BOLD}Bootstrap status:${NC}"
    journalctl -u tor --since "10 minutes ago" --no-pager -q 2>/dev/null \
        | grep -i "bootstrap" | tail -3 || echo "  No recent bootstrap logs"

    echo
    echo -e "${BOLD}Network:${NC}"
    echo "  Default route  : $(ip route | grep default | head -1 || echo none)"
    echo "  DNS config     : $(grep ^nameserver /etc/resolv.conf 2>/dev/null | head -3 || echo none)"
    echo "  IPv6 disabled  : $(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo unknown)"

    echo
    echo -e "${BOLD}Firewall (OUTPUT chain):${NC}"
    ipt -L OUTPUT -n --line-numbers 2>/dev/null | head -20 || echo "  Unable to read iptables"

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
    echo "  Visit: https://browserleaks.com/webrtc"

    echo
    echo -e "${BLUE}===== IPV6 LEAK =====${NC}"
    if sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "^1"; then
        echo "  IPv6 disabled — no IPv6 leak possible."
    else
        warn "  IPv6 ENABLED — possible leak!"
    fi

    echo
    echo -e "${BLUE}===== KILL-SWITCH =====${NC}"
    if ipt -L OUTPUT -n 2>/dev/null | grep -q "policy DROP"; then
        echo "  Kill-switch: ACTIVE (OUTPUT policy DROP)"
    else
        warn "  Kill-switch: NOT ACTIVE"
    fi

    echo
}

############################
# MENU
############################

menu() {
    while true; do
        clear
        echo -e "${BLUE}${BOLD}=================================${NC}"
        echo -e "${BLUE}${BOLD}            GHOSTLY              ${NC}"
        echo -e "${BLUE}${BOLD}=================================${NC}"
        echo
        echo -e "  Mode: ${CYAN}$MODE${NC}  |  Virt: ${CYAN}${VIRT_TYPE:-detecting...}${NC}"
        echo
        echo "  1. Enable Ghostly"
        echo "  2. Disable Ghostly"
        echo "  3. Rotate Tor Circuit"
        echo "  4. Status"
        echo "  5. Leak Test"
        echo "  6. Diagnostics"
        echo "  7. Exit"
        echo

        read -rp "Select [1-7]: " choice
        case "$choice" in
            1) start_ghostly  ;;
            2) stop_ghostly   ;;
            3) rotate_tor     ;;
            4) status_ghostly ;;
            5) leak_test      ;;
            6) diagnostics    ;;
            7) exit 0         ;;
            *) warn "Invalid option" ;;
        esac

        echo
        read -rp "Press Enter to continue..."
    done
}

############################
# MAIN
############################

mkdir -p "$(dirname "$LOG_FILE")" "$CONFIG_DIR" "$BACKUP_DIR"
detect_virt 2>/dev/null || true

case "${1:-}" in
    install)
        require_root
        install_deps
        ;;
    on|start)
        # Allow mode override: ghostly on --mode strict
        [[ "${2:-}" == "--mode" ]] && MODE="${3:-balanced}"
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
    diag|diagnostics)
        diagnostics
        ;;
    menu)
        menu
        ;;
    -v|--version|version)
        echo "Ghostly v${VERSION}"
        ;;
    *)
        echo
        echo -e "${BOLD}Ghostly${NC} - Hardened Anonymous Networking Toolkit"
        echo
        echo "Usage:"
        echo "  sudo ghostly install              Install dependencies"
        echo "  sudo ghostly on                   Enable Ghostly (balanced mode)"
        echo "  sudo ghostly on --mode strict     Enable with strict mode"
        echo "  sudo ghostly on --mode safe       Enable with safe mode"
        echo "  sudo ghostly off                  Disable Ghostly"
        echo "  sudo ghostly rotate               Rotate Tor circuit"
        echo "  sudo ghostly status               Show status"
        echo "  sudo ghostly leak-test            Run leak tests"
        echo "  sudo ghostly diag                 Environment diagnostics"
        echo "  sudo ghostly menu                 Interactive menu"
        echo "  ghostly --version                 Show version"
        echo
        echo "Modes:"
        echo "  balanced   Default. LAN excluded, standard circuits."
        echo "  strict     LAN also through Tor. Reduced circuits. Max privacy."
        echo "  safe       LAN excluded, more circuits. Max stability."
        echo
        ;;
esac
