#!/usr/bin/env bash
#
# ghostly.sh - Production-Grade Adaptive Anonymity Toolkit
# https://github.com/hanzzly/ghostly
#

set -Eeuo pipefail

############################
# VERSION
############################

VERSION="4.0"

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
# RUNTIME DEFAULTS
############################

TOR_USER="debian-tor"
BOOTSTRAP_TIMEOUT=90
MAC_RETRY=3

# User-facing mode (privacy level)
MODE="${GHOSTLY_MODE:-balanced}"      # strict | balanced | safe

# Runtime profile — auto-detected, can be overridden
# baremetal | vm | cloud | wsl | container
RUNTIME_PROFILE=""

# Tor routing mode — set by profile resolution
# transparent | socks-only
TOR_ROUTING_MODE=""

# Feature flags — resolved per profile
SKIP_MAC=0
SKIP_TRANSPARENT=0
SKIP_DNS_LOCK=0
SKIP_IPV6=0
SKIP_KILLSWITCH=0

# Verification state (populated during startup chain)
_SOCKS_OK=0
_CIRCUIT_OK=0
_ISTOR_OK=0
_FALLBACK_MODE=0

# LAN ranges excluded from Tor redirect
LAN_RANGES=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "169.254.0.0/16"
    "100.64.0.0/10"
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

    for bin in tor ip sysctl curl torsocks; do
        command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
    done

    # nc is optional — we use a portable wrapper; warn if missing
    if ! command -v nc >/dev/null 2>&1 && ! command -v socat >/dev/null 2>&1; then
        missing+=("netcat or socat")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing: ${missing[*]}. Run: sudo ghostly install"
    fi

    return 0
}

############################
# PORTABLE TCP CHECK
# Replaces nc -z which is not portable across BSD/GNU/BusyBox.
# Uses socat if available, falls back to /dev/tcp, then nc.
############################

# tcp_check HOST PORT — returns 0 if port open, 1 otherwise
tcp_check() {
    local host="$1" port="$2"
    if command -v socat >/dev/null 2>&1; then
        socat /dev/null "TCP:${host}:${port},connect-timeout=2" 2>/dev/null
        return $?
    elif [[ -e /dev/tcp ]]; then
        # bash built-in — works on Linux, not BusyBox
        (echo >/dev/tcp/"${host}"/"${port}") 2>/dev/null
        return $?
    elif command -v nc >/dev/null 2>&1; then
        # Try GNU nc (-z -w2), ignore unknown-flag errors from BSD nc
        nc -z -w2 "${host}" "${port}" 2>/dev/null
        return $?
    fi
    return 1
}

# tcp_send HOST PORT DATA — send data, return stdout; portable
# Uses socat first (reliable), falls back to nc without -q flag
tcp_send() {
    local host="$1" port="$2" data="$3"
    if command -v socat >/dev/null 2>&1; then
        printf '%s' "$data" | socat - "TCP:${host}:${port},connect-timeout=3" 2>/dev/null
    elif command -v nc >/dev/null 2>&1; then
        # BSD nc has no -q; GNU nc has -q; use timeout wrapper instead
        printf '%s' "$data" | timeout 3 nc "${host}" "${port}" 2>/dev/null
    fi
}

############################
# FIREWALL BACKEND
############################

detect_fw_backend() {
    if command -v nft >/dev/null 2>&1 && nft list tables &>/dev/null; then
        iptables --version 2>/dev/null | grep -q "nf_tables" \
            && echo "iptables-nft" || echo "nftables"
    elif command -v iptables >/dev/null 2>&1; then
        iptables --version 2>/dev/null | grep -q "legacy" \
            && echo "iptables-legacy" || echo "iptables-nft"
    else
        echo "unknown"
    fi
}

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
# ENVIRONMENT DETECTION
############################

# Raw virt string from systemd-detect-virt or manual checks
_VIRT_RAW="none"

detect_environment() {
    # Layer 1: systemd-detect-virt (most reliable)
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        _VIRT_RAW="$(systemd-detect-virt 2>/dev/null || echo 'none')"
    fi

    # Layer 2: Manual fallbacks if systemd gave "none"
    if [[ "$_VIRT_RAW" == "none" ]]; then
        if [[ -f /.dockerenv ]]; then
            _VIRT_RAW="docker"
        elif grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
            _VIRT_RAW="wsl"
        elif [[ -f /proc/1/environ ]] && \
             grep -qz "container=lxc\|container=podman" /proc/1/environ 2>/dev/null; then
            _VIRT_RAW="lxc"
        elif [[ -d /run/systemd/container ]]; then
            _VIRT_RAW="lxc"
        fi
    fi

    # Layer 3: Resolve to canonical runtime profile
    case "$_VIRT_RAW" in
        none|bare-metal)
            RUNTIME_PROFILE="baremetal"
            ;;
        wsl|wsl2|microsoft)
            RUNTIME_PROFILE="wsl"
            ;;
        docker|podman)
            RUNTIME_PROFILE="container"
            ;;
        lxc|lxc-libvirt|openvz|systemd-nspawn)
            RUNTIME_PROFILE="container"
            ;;
        kvm|qemu|vmware|hyperv|xen|bhyve|parallels)
            RUNTIME_PROFILE="vm"
            ;;
        amazon|azure|gce|oracle|openstack|upcloud|vultr|digitalocean)
            RUNTIME_PROFILE="cloud"
            ;;
        *)
            # Unknown virt — treat conservatively as vm
            RUNTIME_PROFILE="vm"
            ;;
    esac

    info "Environment detected: virt='$_VIRT_RAW' → profile='$RUNTIME_PROFILE'"
}

############################
# PROFILE RESOLUTION
# Sets all feature flags based on RUNTIME_PROFILE
############################

resolve_profile() {
    case "$RUNTIME_PROFILE" in

        baremetal)
            TOR_ROUTING_MODE="transparent"
            SKIP_MAC=0
            SKIP_TRANSPARENT=0
            SKIP_DNS_LOCK=0
            SKIP_IPV6=0
            SKIP_KILLSWITCH=0
            log "Profile: BAREMETAL — full transparent routing, MAC spoof, kill-switch"
            ;;

        vm)
            TOR_ROUTING_MODE="transparent"
            SKIP_MAC=1
            SKIP_TRANSPARENT=0
            SKIP_DNS_LOCK=0
            SKIP_IPV6=0
            SKIP_KILLSWITCH=0
            warn "Profile: VM — transparent routing, MAC spoof skipped"
            ;;

        cloud)
            TOR_ROUTING_MODE="transparent"
            SKIP_MAC=1
            SKIP_TRANSPARENT=0
            SKIP_DNS_LOCK=0
            SKIP_IPV6=1       # Cloud VPS often needs IPv6 for management
            SKIP_KILLSWITCH=0
            warn "Profile: CLOUD — transparent routing, MAC+IPv6 skipped"
            warn "CLOUD + STRICT WARNING: kill-switch will block non-Tor traffic."
            warn "Ensure SSH/management IP is whitelisted via --whitelist-ip before enabling."
            ;;

        wsl)
            TOR_ROUTING_MODE="socks-only"
            SKIP_MAC=1
            SKIP_TRANSPARENT=1
            SKIP_DNS_LOCK=1   # WSL DNS managed by Windows
            SKIP_IPV6=1
            SKIP_KILLSWITCH=1
            warn "Profile: WSL — SOCKS-only mode, no kernel networking changes"
            warn "WSL: Configure applications to use SOCKS5 127.0.0.1:${TOR_PORT}"
            ;;

        container)
            TOR_ROUTING_MODE="socks-only"
            SKIP_MAC=1
            SKIP_TRANSPARENT=1
            SKIP_DNS_LOCK=1
            SKIP_IPV6=1
            SKIP_KILLSWITCH=1
            warn "Profile: CONTAINER — SOCKS-only mode, no kernel modifications"
            ;;

        *)
            # Unknown — fail safe
            TOR_ROUTING_MODE="socks-only"
            SKIP_MAC=1
            SKIP_TRANSPARENT=1
            SKIP_DNS_LOCK=0
            SKIP_IPV6=0
            SKIP_KILLSWITCH=1
            warn "Profile: UNKNOWN ($RUNTIME_PROFILE) — defaulting to SOCKS-only safe mode"
            ;;
    esac

    # Mode overrides on top of profile
    # strict mode forces transparent on capable profiles
    if [[ "$MODE" == "strict" && "$TOR_ROUTING_MODE" == "socks-only" ]]; then
        warn "Strict mode requested but profile '$RUNTIME_PROFILE' only supports SOCKS. Staying SOCKS."
    fi

    info "Routing mode: $TOR_ROUTING_MODE"
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
    ip route 2>/dev/null | awk '/default/ {print $5}' | head -n1
}

############################
# INSTALL
############################

install_deps() {
    log "Installing dependencies..."
    apt-get update -qq
    apt-get install -y \
        tor torsocks proxychains4 macchanger curl \
        iptables iptables-persistent iproute2 \
        netcat-openbsd socat dnsutils nftables xxd
    log "Dependencies installed."
}

############################
# ROUTE BACKUP & RESTORE
############################

backup_routes() {
    mkdir -p "$BACKUP_DIR"
    ip route show > "$BACKUP_DIR/routes.bak" 2>/dev/null || true
    ip rule show  > "$BACKUP_DIR/rules.bak"  2>/dev/null || true
    log "Routing table backed up."
}

restore_routes() {
    [[ -f "$BACKUP_DIR/routes.bak" ]] || return 0
    log "Restoring default route..."
    local default_gw
    default_gw="$(grep '^default' "$BACKUP_DIR/routes.bak" | head -1 || true)"
    [[ -n "$default_gw" ]] && \
        ip route replace $default_gw 2>/dev/null || true
    log "Routes restored."
}

############################
# TOR CONFIG ORCHESTRATOR
#
# Architecture:
#   /etc/tor/torrc         → minimal bootstrap (include only)
#   /etc/tor/torrc.d/      → runtime snippets
#   ghostly.conf           → profile-generated by Ghostly
#
# Ghostly NEVER writes runtime directives into /etc/tor/torrc.
# All config lives in ghostly.conf only.
############################

# Directives that must NOT exist in /etc/tor/torrc when using torrc.d
# (duplicate binding causes "Address already in use")
_CONFLICT_DIRECTIVES=(
    "SocksPort"
    "ControlPort"
    "DNSPort"
    "TransPort"
    "AutomapHostsOnResolve"
    "VirtualAddrNetworkIPv4"
    "CookieAuthentication"
    "HashedControlPassword"
)

# Check /etc/tor/torrc for directives that would conflict with ghostly.conf
detect_torrc_conflicts() {
    [[ -f /etc/tor/torrc ]] || return 0

    local found=()
    for directive in "${_CONFLICT_DIRECTIVES[@]}"; do
        # Match uncommented lines only
        if grep -E "^[[:space:]]*${directive}[[:space:]]" /etc/tor/torrc \
                &>/dev/null 2>&1; then
            found+=("$directive")
        fi
    done

    if [[ ${#found[@]} -gt 0 ]]; then
        err "Legacy torrc conflict detected in /etc/tor/torrc:"
        for d in "${found[@]}"; do
            err "  → $d"
        done
        err "These directives will cause duplicate listener errors."
        err "Run: sudo ghostly fix-torrc   to auto-fix"
        return 1
    fi
    return 0
}

# Migrate /etc/tor/torrc to minimal bootstrap format
# Backs up original, strips conflicting directives, adds %include
sanitize_torrc() {
    local torrc="/etc/tor/torrc"
    local bak="$BACKUP_DIR/torrc.original.bak"

    mkdir -p "$BACKUP_DIR"

    # Only run once — don't clobber an already-sanitized torrc
    if grep -q "^# Ghostly: minimal bootstrap" "$torrc" 2>/dev/null; then
        info "torrc already in minimal bootstrap format."
        return 0
    fi

    log "Sanitizing /etc/tor/torrc → minimal bootstrap format..."

    # Backup original
    cp "$torrc" "$bak" 2>/dev/null || true
    log "Original torrc backed up to: $bak"

    # Build minimal torrc — comment out all conflicting directives,
    # preserve comments and non-conflicting lines, add %include
    local tmpfile; tmpfile="$(mktemp)"

    cat > "$tmpfile" <<'EOF'
# Ghostly: minimal bootstrap torrc
# All runtime config is in /etc/tor/torrc.d/ghostly.conf
# Do not add SocksPort, ControlPort, TransPort, DNSPort here.
# Generated by Ghostly — original backed up at /var/lib/ghostly/torrc.original.bak

EOF

    # Preserve non-conflicting, non-empty lines from original
    # Comment out any conflicting directives found
    while IFS= read -r line; do
        local skip=0
        for directive in "${_CONFLICT_DIRECTIVES[@]}"; do
            if echo "$line" | grep -qE "^[[:space:]]*${directive}[[:space:]]"; then
                echo "# [ghostly-disabled] $line" >> "$tmpfile"
                skip=1
                break
            fi
        done
        # Skip old ghostly %include lines (we'll re-add below)
        if echo "$line" | grep -q "torrc.d"; then
            skip=1
        fi
        [[ $skip -eq 0 ]] && echo "$line" >> "$tmpfile"
    done < "$torrc"

    # Add %include directive
    cat >> "$tmpfile" <<'EOF'

# Ghostly runtime includes
%include /etc/tor/torrc.d/*.conf
EOF

    mv "$tmpfile" "$torrc"
    chmod 644 "$torrc"
    log "torrc sanitized. Conflicting directives disabled."
}

# Write profile-isolated ghostly.conf — all runtime config here
write_torrc_snippet() {
    mkdir -p /etc/tor/torrc.d

    # Backup previous snippet if exists
    if [[ -f "$TORRC_SNIPPET" ]]; then
        cp "$TORRC_SNIPPET" "${TORRC_SNIPPET}.bak" 2>/dev/null || true
    fi

    local strict_nodes="0" max_circuits="32"
    case "$MODE" in
        strict)   strict_nodes="1"; max_circuits="8"  ;;
        safe)     max_circuits="64"                   ;;
        balanced) max_circuits="32"                   ;;
    esac

    # ── Base config (all profiles) ──
    cat > "$TORRC_SNIPPET" <<EOF
## ============================================
## Ghostly v${VERSION} — runtime config
## Profile  : ${RUNTIME_PROFILE}
## Mode     : ${MODE}
## Routing  : ${TOR_ROUTING_MODE}
## Generated: $(date '+%Y-%m-%d %H:%M:%S')
## DO NOT EDIT — managed by Ghostly
## ============================================

## Listener ports
SocksPort ${TOR_PORT}
ControlPort ${TOR_CONTROL_PORT}

## Auth — cookie only, no plaintext passwords
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
EOF

    # ── Transparent proxy block (baremetal / vm / cloud only) ──
    if [[ "$SKIP_TRANSPARENT" -eq 0 ]]; then
        cat >> "$TORRC_SNIPPET" <<EOF

## Transparent proxy — profile: ${RUNTIME_PROFILE}
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit
TransPort ${TOR_TRANS_PORT} IsolateClientAddr IsolateClientProtocol
DNSPort ${TOR_DNS_PORT}
EOF
    else
        # Explicitly ensure no TransPort/DNSPort in SOCKS-only profiles
        cat >> "$TORRC_SNIPPET" <<EOF

## SOCKS-only profile: ${RUNTIME_PROFILE}
## TransPort and DNSPort intentionally omitted.
## No transparent proxy — no kernel routing modifications.
## Route applications via SOCKS5: 127.0.0.1:${TOR_PORT}
EOF
    fi

    chmod 644 "$TORRC_SNIPPET"
    log "ghostly.conf written: $TORRC_SNIPPET"
}

# Validate config using tor --verify-config
validate_tor_config() {
    log "Validating Tor configuration..."
    local output
    if output="$(tor --verify-config --torrc-file /etc/tor/torrc 2>&1)"; then
        log "Tor config validation passed."
        return 0
    else
        err "Tor config validation FAILED:"
        echo "$output" | grep -v "^$" | while IFS= read -r line; do
            err "  $line"
        done
        err "Config file: $TORRC_SNIPPET"
        return 1
    fi
}

has_systemd() {
    command -v systemctl >/dev/null 2>&1 && \
    systemctl list-units >/dev/null 2>&1
}

service_start() {
    if has_systemd; then
        systemctl restart tor
    else
        service tor restart >/dev/null 2>&1 || \
        /etc/init.d/tor restart >/dev/null 2>&1
    fi
}

service_stop() {
    if has_systemd; then
        systemctl stop tor
    else
        service tor stop >/dev/null 2>&1 || \
        /etc/init.d/tor stop >/dev/null 2>&1
    fi
}

service_active() {
    if has_systemd; then
        systemctl is-active --quiet tor
    else
        pgrep -x tor >/dev/null 2>&1
    fi
}

# Main configure_tor — orchestrates the full flow
configure_tor() {
    log "Configuring Tor (profile: $RUNTIME_PROFILE, mode: $MODE, routing: $TOR_ROUTING_MODE)..."

    mkdir -p "$BACKUP_DIR" "$CONFIG_DIR" /etc/tor/torrc.d

    # Step 1: Ensure torrc is in minimal bootstrap format
    sanitize_torrc

    # Step 2: Write profile-isolated runtime snippet
    write_torrc_snippet

    # Step 3: Validate combined config (torrc + torrc.d/ghostly.conf)
    if ! validate_tor_config; then
        # Restore previous snippet if validation fails
        if [[ -f "${TORRC_SNIPPET}.bak" ]]; then
            warn "Restoring previous ghostly.conf after validation failure..."
            mv "${TORRC_SNIPPET}.bak" "$TORRC_SNIPPET"
        fi
        return 1
    fi

    # Step 4: Restart Tor
    service_start
    log "Tor configured and restarted."
}

# Exposed as a CLI command: sudo ghostly fix-torrc
fix_torrc() {
    require_root
    log "Running torrc sanitization..."
    sanitize_torrc
    log "Done. Run 'sudo ghostly diag' to verify."
}

############################
# STARTUP VERIFICATION CHAIN
# Returns 0 only if all required checks pass
############################

# Step 1: Tor service active
verify_service() {
    if ! service_active 2>/dev/null; then
        err "Tor service is not active."
        return 1
    fi
    log "Verification [1/4]: Tor service active."
    return 0
}

# Step 2: SOCKS port open
verify_socks_port() {
    local attempts=0
    while (( attempts < 10 )); do
        if tcp_check 127.0.0.1 "$TOR_PORT"; then
            _SOCKS_OK=1
            log "Verification [2/4]: SOCKS port open (127.0.0.1:${TOR_PORT})."
            return 0
        fi
        sleep 2
        attempts=$((attempts + 1))
    done
    err "SOCKS port ${TOR_PORT} not open after 20s."
    return 1
}

############################
# BOOTSTRAP VERIFICATION
#
# FIX: Use control port GETINFO as primary source of truth.
# Journal polling was the secondary fallback but caused a race:
# "3 minutes ago" window + sleep 3 loop could overlap or miss
# the bootstrap completion line on slow systems.
#
# New strategy:
#   Primary  → GETINFO status/bootstrap-phase (authoritative, real-time)
#   Fallback → journal scan (only if control port unreachable)
############################

# Step 3: Bootstrap to 100%
verify_bootstrap() {
    if [[ "$RUNTIME_PROFILE" == "wsl" ]]; then
        log "WSL detected — skipping journal bootstrap verification."
        return 0
    fi

    log "Waiting for Tor bootstrap (timeout: ${BOOTSTRAP_TIMEOUT}s)..."
    local elapsed=0

    while (( elapsed < BOOTSTRAP_TIMEOUT )); do

        # Primary: control port GETINFO (authoritative, no race)
        if tcp_check 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null; then
            local phase
            phase="$(tcp_send 127.0.0.1 "$TOR_CONTROL_PORT" \
                "AUTHENTICATE\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n" \
                | grep "PROGRESS=" | grep -o "PROGRESS=[0-9]*" | cut -d= -f2 || echo 0)"

            if [[ "$phase" == "100" ]]; then
                echo    # clear progress line
                log "Verification [3/4]: Bootstrap 100% (control port)."
                return 0
            fi
            echo -ne "\r${CYAN}[i]${NC} Bootstrap progress: ${phase:-0}%  (${elapsed}s / ${BOOTSTRAP_TIMEOUT}s)"
        else
            # Fallback: journal scan (only when control port not yet open)
            if journalctl -u tor --since "3 minutes ago" --no-pager -q 2>/dev/null \
                | grep -q "Bootstrapped 100%"; then
                echo
                log "Verification [3/4]: Bootstrap 100% (journal fallback)."
                return 0
            fi
            echo -ne "\r${YELLOW}[*]${NC} Bootstrapping... ${elapsed}s / ${BOOTSTRAP_TIMEOUT}s"
        fi

        sleep 3
        elapsed=$((elapsed + 3))
    done
    echo

    # Last-chance: journal scan before giving up
    if journalctl -u tor --since "5 minutes ago" --no-pager -q 2>/dev/null \
        | grep -q "Bootstrapped 100%"; then
        log "Verification [3/4]: Bootstrap 100% (journal last-chance)."
        return 0
    fi

    # Soft fail — SOCKS open is better than nothing
    if [[ "$_SOCKS_OK" -eq 1 ]]; then
        warn "Verification [3/4]: Bootstrap log not confirmed. SOCKS open — proceeding with caution."
        return 0
    fi

    err "Bootstrap timed out after ${BOOTSTRAP_TIMEOUT}s."
    return 1
}

# Step 4: IsTor=true confirmation
verify_tor_exit() {
    log "Verification [4/4]: Confirming Tor exit IP..."

    local ip="" tor_check=""

    if [[ "$TOR_ROUTING_MODE" == "socks-only" ]]; then
        # WSL/container: use SOCKS5 directly
        ip="$(curl -s --max-time 15 \
            --socks5-hostname "127.0.0.1:${TOR_PORT}" \
            https://ipinfo.io/ip 2>/dev/null || true)"
        tor_check="$(curl -s --max-time 15 \
            --socks5-hostname "127.0.0.1:${TOR_PORT}" \
            https://check.torproject.org/api/ip 2>/dev/null || true)"
    else
        # Transparent: use torsocks
        ip="$(torsocks curl -s --max-time 15 https://ipinfo.io/ip 2>/dev/null || true)"
        tor_check="$(torsocks curl -s --max-time 15 \
            https://check.torproject.org/api/ip 2>/dev/null || true)"
    fi

    if [[ -z "$ip" ]]; then
        warn "Could not reach Tor exit. Circuit may not be established yet."
        return 0
    fi

    if echo "$tor_check" | grep -q '"IsTor":true'; then
        _ISTOR_OK=1
        _CIRCUIT_OK=1
        log "Tor exit confirmed. IP: $ip"
        return 0
    else
        warn "IsTor check inconclusive. IP: $ip"
        # Not a hard failure — could be API issue
        return 0
    fi
}

# Full verification chain — called in sequence
run_verification_chain() {
    log "Running startup verification chain..."

    verify_service  || return 1
    verify_socks_port || return 1
    verify_bootstrap  || return 1
    verify_tor_exit   || warn "Exit verification inconclusive — check status after startup."

    log "Verification chain passed."
    return 0
}

############################
# DNS
############################

configure_dns() {
    if [[ "$SKIP_DNS_LOCK" -eq 1 ]]; then
        info "DNS lock skipped (profile: $RUNTIME_PROFILE)."
        return 0
    fi

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
    # WSL/container: jangan sentuh resolv.conf
    if [[ "$SKIP_DNS_LOCK" -eq 1 ]]; then
        info "DNS restore skipped (profile: $RUNTIME_PROFILE)."
        return 0
    fi

    log "Restoring DNS..."
    chattr -i /etc/resolv.conf 2>/dev/null || true

    if [[ -f "$BACKUP_DIR/resolv.conf.bak" ]]; then
        cp "$BACKUP_DIR/resolv.conf.bak" /etc/resolv.conf
        log "DNS restored."
    else
        warn "No DNS backup. Falling back to Cloudflare DNS."
        cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
    fi
}

############################
# IPv6
############################

disable_ipv6() {
    if [[ "$SKIP_IPV6" -eq 1 ]]; then
        info "IPv6 disable skipped (profile: $RUNTIME_PROFILE)."
        return 0
    fi
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
    rm -f /etc/sysctl.d/99-ghostly-no-ipv6.conf
    sysctl -w net.ipv6.conf.all.disable_ipv6=0     >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0       >/dev/null 2>&1 || true
    log "IPv6 re-enabled."
}

############################
# MAC SPOOF
############################

spoof_mac() {
    if [[ "$SKIP_MAC" -eq 1 ]]; then
        info "MAC spoof skipped (profile: $RUNTIME_PROFILE)."
        return 0
    fi
    command -v macchanger >/dev/null 2>&1 || {
        warn "macchanger not found. Skipping MAC spoof."
        return 0
    }

    local iface; iface="$(default_iface)"
    [[ -z "$iface" ]] && { err "No network interface found."; return 1; }

    log "Spoofing MAC on $iface..."
    local attempt=0
    while (( attempt < MAC_RETRY )); do
        ip link set "$iface" down
        sleep 1
        if macchanger -r "$iface" 2>/dev/null; then
            ip link set "$iface" up
            log "MAC spoofed → $(cat /sys/class/net/"$iface"/address)"
            return 0
        fi
        ip link set "$iface" up
        attempt=$((attempt + 1))
        warn "MAC spoof attempt $attempt failed, retrying..."
        sleep 2
    done
    warn "MAC spoofing failed after $MAC_RETRY attempts. Continuing."
}

restore_mac() {
    [[ "$SKIP_MAC" -eq 1 ]] && return 0
    command -v macchanger >/dev/null 2>&1 || return 0
    local iface; iface="$(default_iface)"
    [[ -z "$iface" ]] && return 0
    log "Restoring MAC on $iface..."
    ip link set "$iface" down; sleep 1
    macchanger -p "$iface" 2>/dev/null || true
    ip link set "$iface" up
    log "MAC restored."
}

############################
# FIREWALL
#
# FIX: configure_firewall is now idempotent.
# Previously: flush + rebuild unconditionally — calling twice while
# active caused an intermittent window where OUTPUT=ACCEPT (open)
# between flush and kill-switch re-application.
#
# New strategy:
#   1. Check if ghostly chain already exists (_GHOSTLY_FW_ACTIVE flag).
#   2. If active, skip re-application and return early.
#   3. Only flush + rebuild on first call (or after explicit restore_firewall).
#
# This ensures configure_firewall is safe to call multiple times
# (e.g. from fallback_to_socks) without creating a traffic-leak window.
############################

_GHOSTLY_FW_ACTIVE=0

_fw_chain_exists() {
    ipt -L GHOSTLY_OUTPUT -n &>/dev/null 2>&1
}

configure_firewall() {
    if [[ "$SKIP_TRANSPARENT" -eq 1 ]]; then
        info "Transparent firewall skipped (profile: $RUNTIME_PROFILE, routing: $TOR_ROUTING_MODE)."
        return 0
    fi

    # Idempotency guard: skip if already applied this session
    if [[ "$_GHOSTLY_FW_ACTIVE" -eq 1 ]] && _fw_chain_exists; then
        info "Firewall already configured — skipping re-application."
        return 0
    fi

    log "Applying transparent firewall (mode: $MODE)..."
    backup_firewall
    
    warn "Flushing existing iptables rules."
    warn "Docker/VPN/custom firewall rules may be disrupted."
    ipt -F; ipt -t nat -F; ipt -t mangle -F
    ipt -X 2>/dev/null || true

    # Create named chain for idempotency tracking
    ipt -N GHOSTLY_OUTPUT 2>/dev/null || true

    # START PERMISSIVE — OUTPUT → DROP only after Tor verified
    ipt -P INPUT   DROP
    ipt -P FORWARD DROP
    ipt -P OUTPUT  ACCEPT

    # Loopback
    ipt -A INPUT  -i lo -j ACCEPT
    ipt -A OUTPUT -o lo -j ACCEPT

    # Established
    ipt -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Tor daemon outbound always allowed
    ipt -A OUTPUT -m owner --uid-owner "$TOR_USER" -j ACCEPT

    # NAT: loopback RETURN (nf_tables compatible)
    ipt -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN
    ipt -t nat -A OUTPUT -p tcp -m owner --uid-owner "$TOR_USER" -j RETURN

    # NAT: LAN exclusions (not in strict mode)
    if [[ "$MODE" != "strict" ]]; then
        for lan in "${LAN_RANGES[@]}"; do
            ipt -t nat -A OUTPUT -p tcp -d "$lan" -j RETURN
            ipt -t nat -A OUTPUT -p udp -d "$lan" -j RETURN
        done
        log "LAN ranges excluded from Tor redirect."
    else
        warn "Strict mode: all traffic redirected through Tor."
        warn "STRICT MODE WARNING: SSH/management access may be disrupted."
        warn "Whitelist management IPs before enabling strict mode on cloud/remote servers."
    fi

    # NAT: redirect TCP → TransPort
    ipt -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports "$TOR_TRANS_PORT"

    # NAT: redirect DNS → DNSPort
    ipt -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "$TOR_DNS_PORT"
    ipt -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "$TOR_DNS_PORT"

    # DNS leak prevention
    ipt -A OUTPUT -p udp --dport 53 -m owner --uid-owner "$TOR_USER" -j ACCEPT
    ipt -A OUTPUT -p tcp --dport 53 -m owner --uid-owner "$TOR_USER" -j ACCEPT

    _GHOSTLY_FW_ACTIVE=1
    log "Firewall applied (OUTPUT=ACCEPT, awaiting kill-switch activation)."
}

apply_killswitch() {
    if [[ "$SKIP_KILLSWITCH" -eq 1 ]]; then
        info "Kill-switch skipped (profile: $RUNTIME_PROFILE)."
        return 0
    fi

    log "Activating kill-switch (OUTPUT → DROP)..."
    ipt -P OUTPUT DROP
    # Safety net — always keep Tor daemon allowed
    ipt -A OUTPUT -m owner --uid-owner "$TOR_USER" -j ACCEPT 2>/dev/null || true
    log "Kill-switch active. All non-Tor traffic blocked."
}

backup_firewall() {
    mkdir -p "$BACKUP_DIR"
    ipt_save > "$BACKUP_DIR/iptables.bak" 2>/dev/null || true
}

restore_firewall() {
    # Always ensure OUTPUT is open first
    ipt -P OUTPUT ACCEPT 2>/dev/null || true
    ipt -P INPUT  ACCEPT 2>/dev/null || true

    if [[ -f "$BACKUP_DIR/iptables.bak" ]]; then
        ipt_restore < "$BACKUP_DIR/iptables.bak" 2>/dev/null || true
        log "Firewall restored from backup."
    else
        warn "No firewall backup. Resetting to ACCEPT-all."
        ipt -F; ipt -t nat -F; ipt -t mangle -F
        ipt -X 2>/dev/null || true
        ipt -P INPUT ACCEPT; ipt -P FORWARD ACCEPT; ipt -P OUTPUT ACCEPT
    fi

    _GHOSTLY_FW_ACTIVE=0
}

############################
# FALLBACK: TRANSPARENT → SOCKS
############################

fallback_to_socks() {
    _FALLBACK_MODE=1
    TOR_ROUTING_MODE="socks-only"
    SKIP_TRANSPARENT=1
    SKIP_KILLSWITCH=1

    warn "═══════════════════════════════════════════"
    warn " FALLBACK: Transparent mode failed."
    warn " Downgrading to SOCKS-only SAFE MODE."
    warn " Applications must use SOCKS5 127.0.0.1:${TOR_PORT}"
    warn "═══════════════════════════════════════════"

    # Restore firewall to safe state before retrying
    # configure_firewall idempotency flag is reset by restore_firewall
    restore_firewall
    restore_dns

    # Reconfigure Tor without TransPort/DNSPort
    configure_tor

    if ! run_verification_chain; then
        err "SOCKS fallback also failed. Aborting."
        return 1
    fi

    log "SOCKS-only safe mode active."
    return 0
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
    err "Error (exit $exit_code) — rolling back all changes..."

    # Immediately open OUTPUT to prevent lockout
    ipt -P OUTPUT ACCEPT 2>/dev/null || true
    ipt -P INPUT  ACCEPT 2>/dev/null || true

    restore_firewall
    restore_dns
    restore_mac
    enable_ipv6
    restore_routes

    service_stop 2>/dev/null || true

    # Restore previous snippet if we have one, else remove
    if [[ -f "${TORRC_SNIPPET}.bak" ]]; then
        mv "${TORRC_SNIPPET}.bak" "$TORRC_SNIPPET" 2>/dev/null || true
        warn "Restored previous ghostly.conf from backup."
    else
        rm -f "$TORRC_SNIPPET" 2>/dev/null || true
    fi

    # Preserve minimal torrc — do NOT restore legacy conflicting torrc
    # The sanitized minimal torrc is always safe to keep

    clear_state

    echo
    warn "Rollback complete. Network restored to original state."
    warn "Log: $LOG_FILE"
}

############################
# STATE TRACKING
############################

save_state() {
    cat > "$STATE_FILE" <<EOF
active
MODE=$MODE
RUNTIME_PROFILE=$RUNTIME_PROFILE
TOR_ROUTING_MODE=$TOR_ROUTING_MODE
VIRT=$_VIRT_RAW
FALLBACK=$_FALLBACK_MODE
SKIP_MAC=$SKIP_MAC
SKIP_TRANSPARENT=$SKIP_TRANSPARENT
SKIP_KILLSWITCH=$SKIP_KILLSWITCH
ISTOR_OK=$_ISTOR_OK
STARTED=$(date '+%Y-%m-%d %H:%M:%S')
EOF
}

clear_state() {
    rm -f "$STATE_FILE"
}

is_active() {
    [[ -f "$STATE_FILE" ]] && grep -q "^active" "$STATE_FILE" 2>/dev/null
}

state_val() {
    [[ -f "$STATE_FILE" ]] && \
        grep "^${1}=" "$STATE_FILE" | cut -d= -f2 || echo ""
}

############################
# START
############################

start_ghostly() {
    require_root
    check_deps
    detect_environment
    resolve_profile

    if is_active; then
        warn "Ghostly is already active. Run 'ghostly off' first."
        return 1
    fi

    trap cleanup_on_error ERR

    log "==============================="
    log "  Starting Ghostly v${VERSION}"
    log "  Profile : ${RUNTIME_PROFILE}"
    log "  Mode    : ${MODE}"
    log "  Routing : ${TOR_ROUTING_MODE}"
    log "==============================="

    # 1. Backup
    backup_routes

    # 2. Pre-flight: check for legacy torrc conflicts BEFORE touching anything
    #    If conflicts exist, sanitize_torrc will fix them inside configure_tor.
    #    We warn early so the user knows what happened.
    if [[ -f /etc/tor/torrc ]] && \
       ! grep -q "^# Ghostly: minimal bootstrap" /etc/tor/torrc 2>/dev/null; then
        warn "Legacy /etc/tor/torrc detected — will be sanitized before Tor starts."
    fi

    # 3. Configure Tor (sanitize torrc, write ghostly.conf, validate, restart)
    configure_tor

    # 4. MAC spoof (skipped on VM/cloud/container/WSL)
    spoof_mac

    # 5. IPv6 (skipped on cloud/container)
    disable_ipv6

    # 6. Firewall — permissive (OUTPUT=ACCEPT) — skipped on WSL/container
    configure_firewall

    # 7. Verification chain: service → SOCKS → bootstrap → exit IP
    if ! run_verification_chain; then
        # Transparent mode failed — try SOCKS fallback
        if [[ "$TOR_ROUTING_MODE" == "transparent" ]]; then
            warn "Transparent mode verification failed. Attempting SOCKS fallback..."
            if ! fallback_to_socks; then
                cleanup_on_error
                exit 1
            fi
        else
            err "Verification chain failed."
            cleanup_on_error
            exit 1
        fi
    fi

    # 8. Lock DNS (after Tor confirmed, skipped on WSL/container)
    configure_dns

    # 9. Activate kill-switch (skipped on WSL/container)
    apply_killswitch

    # 10. Save state
    save_state

    trap - ERR

    echo
    log "==============================="
    if [[ "$_FALLBACK_MODE" -eq 1 ]]; then
        warn "  Ghostly ACTIVE (SOCKS fallback mode)"
        warn "  Use SOCKS5 127.0.0.1:${TOR_PORT}"
    else
        log "  Ghostly ACTIVE"
    fi
    log "==============================="

    # WSL-specific hint
    if [[ "$RUNTIME_PROFILE" == "wsl" ]]; then
        echo
        info "WSL SOCKS5 proxy: 127.0.0.1:${TOR_PORT}"
        info "Enable shell proxy:"
        info "  eval \"\$(ghostly env)\""
        info "Disable shell proxy:"
        info "  eval \"\$(ghostly unset-env)\""
        info "Export for shell: export https_proxy=socks5h://127.0.0.1:${TOR_PORT}"
        info "                  export http_proxy=socks5h://127.0.0.1:${TOR_PORT}"
    fi
}

############################
# STOP
############################

stop_ghostly() {
    require_root

    detect_environment

    log "==============================="
    log "  Stopping Ghostly"
    log "==============================="

    ipt -P OUTPUT ACCEPT 2>/dev/null || true
    ipt -P INPUT  ACCEPT 2>/dev/null || true

    restore_firewall
    restore_dns
    restore_mac
    enable_ipv6
    restore_routes

    service_stop 2>/dev/null || true
    rm -f "$TORRC_SNIPPET" 2>/dev/null || true
    clear_state

    log "Ghostly DISABLED."
    warn "Your real IP is now exposed."

    if [[ "$RUNTIME_PROFILE" == "wsl" ]]; then
        warn "WSL networking may require reset if connectivity breaks."
        warn "Run: wsl --shutdown (from Windows)"
    fi
}

############################
# ROTATE CIRCUIT
############################

rotate_tor() {
    require_root

    log "Requesting new Tor circuit..."

    tcp_check 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null || {
        err "Control port not reachable. Is Ghostly active?"
        return 1
    }

    [[ -r "$COOKIE_FILE" ]] || {
        err "Cookie not readable: $COOKIE_FILE"
        return 1
    }

    local cookie_hex
    cookie_hex="$(xxd -p "$COOKIE_FILE" 2>/dev/null | tr -d '\n')"

    tcp_send 127.0.0.1 "$TOR_CONTROL_PORT" \
        "$(printf "AUTHENTICATE %s\r\nSIGNAL NEWNYM\r\nQUIT\r\n" "$cookie_hex")" \
        >/dev/null 2>&1

    log "Waiting 10s for new circuit..."
    sleep 10
    verify_tor_exit
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

    local active_profile active_routing active_mode fallback
    active_profile="$(state_val RUNTIME_PROFILE)"
    active_routing="$(state_val TOR_ROUTING_MODE)"
    active_mode="$(state_val MODE)"
    fallback="$(state_val FALLBACK)"

    echo -n "  Active         : "
    is_active && echo -e "${GREEN}YES${NC}" || echo -e "${RED}NO${NC}"

    echo -n "  Runtime profile: "
    [[ -n "$active_profile" ]] && echo "$active_profile" || echo "(not running)"

    echo -n "  Routing mode   : "
    if [[ -n "$active_routing" ]]; then
        [[ "$fallback" == "1" ]] \
            && echo -e "${YELLOW}${active_routing} (fallback)${NC}" \
            || echo "$active_routing"
    else
        echo "(not running)"
    fi

    echo -n "  Privacy mode   : "; echo "${active_mode:-$MODE}"
    echo -n "  Virt/env       : "; echo "${_VIRT_RAW:-unknown}"
    echo -n "  Network mgr    : "; detect_netman
    echo -n "  FW backend     : "; detect_fw_backend

    echo
    echo -n "  Tor service    : "
    service_active && echo "active" || echo "inactive"

    echo -n "  SOCKS port     : "
    tcp_check 127.0.0.1 "$TOR_PORT" 2>/dev/null \
        && echo -e "${GREEN}open (${TOR_PORT})${NC}" \
        || echo -e "${RED}CLOSED${NC}"

    echo -n "  Control port   : "
    tcp_check 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null \
        && echo "open ($TOR_CONTROL_PORT)" \
        || echo -e "${RED}CLOSED${NC}"

    echo -n "  torrc mode     : "
    if grep -q "^# Ghostly: minimal bootstrap" /etc/tor/torrc 2>/dev/null; then
        echo -e "${GREEN}minimal (Ghostly-managed)${NC}"
    else
        echo -e "${YELLOW}legacy — run: sudo ghostly fix-torrc${NC}"
    fi

    echo -n "  Config source  : "
    [[ -f "$TORRC_SNIPPET" ]] \
        && echo "$TORRC_SNIPPET" \
        || echo -e "${YELLOW}not found${NC}"

    echo -n "  Duplicate check: "
    local has_conflict=0
    for directive in "${_CONFLICT_DIRECTIVES[@]}"; do
        if grep -qE "^[[:space:]]*${directive}[[:space:]]" /etc/tor/torrc 2>/dev/null; then
            has_conflict=1; break
        fi
    done
    [[ $has_conflict -eq 0 ]] \
        && echo -e "${GREEN}clean${NC}" \
        || echo -e "${RED}CONFLICT — run: sudo ghostly fix-torrc${NC}"

    echo -n "  Transparent    : "
    [[ "$(state_val SKIP_TRANSPARENT)" == "1" ]] \
        && echo -e "${YELLOW}disabled (profile)${NC}" \
        || echo -e "${GREEN}active${NC}"

    echo -n "  Kill-switch    : "
    if [[ "$(state_val SKIP_KILLSWITCH)" == "1" ]]; then
        echo -e "${YELLOW}disabled (profile)${NC}"
    else
        ipt -L OUTPUT -n 2>/dev/null | grep -q "policy DROP" \
            && echo -e "${GREEN}ACTIVE${NC}" \
            || echo -e "${YELLOW}inactive${NC}"
    fi

    echo -n "  IsTor verified : "
    [[ "$(state_val ISTOR_OK)" == "1" ]] \
        && echo -e "${GREEN}YES${NC}" \
        || echo -e "${YELLOW}unconfirmed${NC}"

    echo -n "  Public IP      : "
    if [[ "$active_routing" == "socks-only" ]]; then
        curl -s --max-time 8 \
            --socks5-hostname "127.0.0.1:${TOR_PORT}" \
            https://ipinfo.io/ip 2>/dev/null || echo "unavailable"
    else
        torsocks curl -s --max-time 8 https://ipinfo.io/ip 2>/dev/null \
            || echo "unavailable"
    fi
    echo

    echo -n "  Interface      : "; default_iface
    echo -n "  MAC address    : "
    local iface; iface="$(default_iface 2>/dev/null || true)"
    [[ -n "$iface" ]] && cat /sys/class/net/"$iface"/address 2>/dev/null \
        || echo "unknown"

    echo -n "  IPv6 disabled  : "
    sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown"

    echo -n "  DNS server     : "
    grep "^nameserver" /etc/resolv.conf 2>/dev/null \
        | awk '{print $2}' | head -1 || echo "unknown"

    echo
    [[ -n "$(state_val STARTED)" ]] && \
        echo "  Started: $(state_val STARTED)"
    echo
}

############################
# DIAGNOSTICS
############################

diagnostics() {
    detect_environment 2>/dev/null || true
    resolve_profile 2>/dev/null || true

    echo
    echo -e "${BLUE}${BOLD}=================================${NC}"
    echo -e "${BLUE}${BOLD}      GHOSTLY DIAGNOSTICS        ${NC}"
    echo -e "${BLUE}${BOLD}=================================${NC}"

    echo
    echo -e "${BOLD}── Environment ──${NC}"
    echo "  OS             : $(grep PRETTY_NAME /etc/os-release 2>/dev/null \
        | cut -d= -f2 | tr -d '"' || uname -s)"
    echo "  Kernel         : $(uname -r)"
    echo "  Virt (raw)     : $_VIRT_RAW"
    echo "  Runtime profile: $RUNTIME_PROFILE"
    echo "  Network manager: $(detect_netman)"
    echo "  FW backend     : $(detect_fw_backend)"

    echo
    echo -e "${BOLD}── Profile Capabilities ──${NC}"
    echo "  Routing mode        : $TOR_ROUTING_MODE"
    echo "  Transparent routing : $([[ $SKIP_TRANSPARENT -eq 0 ]] && echo SUPPORTED || echo "NOT SUPPORTED (SOCKS-only)")"
    echo "  MAC spoofing        : $([[ $SKIP_MAC -eq 0 ]] && echo SUPPORTED || echo SKIPPED)"
    echo "  IPv6 disable        : $([[ $SKIP_IPV6 -eq 0 ]] && echo SUPPORTED || echo SKIPPED)"
    echo "  DNS lock            : $([[ $SKIP_DNS_LOCK -eq 0 ]] && echo SUPPORTED || echo SKIPPED)"
    echo "  Kill-switch         : $([[ $SKIP_KILLSWITCH -eq 0 ]] && echo SUPPORTED || echo SKIPPED)"

    if [[ "$RUNTIME_PROFILE" == "wsl" ]]; then
        echo
        echo -e "  ${YELLOW}WSL WARNINGS:${NC}"
        echo "  • Transparent iptables redirect not supported in WSL"
        echo "  • DNS managed by Windows — resolv.conf changes may revert"
        echo "  • MAC spoofing unavailable on virtual adapters"
        echo "  • Use SOCKS5: 127.0.0.1:${TOR_PORT}"
        echo "  • export https_proxy=socks5h://127.0.0.1:${TOR_PORT}"
    fi

    echo
    echo -e "${BOLD}── Tor Config Architecture ──${NC}"

    # torrc mode: minimal/legacy
    local torrc_mode="unknown"
    if [[ -f /etc/tor/torrc ]]; then
        if grep -q "^# Ghostly: minimal bootstrap" /etc/tor/torrc 2>/dev/null; then
            torrc_mode="minimal (Ghostly-managed)"
        else
            torrc_mode="${RED}legacy — may conflict!${NC}"
        fi
    else
        torrc_mode="missing"
    fi
    echo -e "  torrc mode     : $torrc_mode"

    # Config source
    echo -n "  Config source  : "
    if [[ -f "$TORRC_SNIPPET" ]]; then
        echo "$TORRC_SNIPPET"
    else
        echo -e "${YELLOW}NOT FOUND${NC} (Ghostly not active or not configured)"
    fi

    # %include status
    echo -n "  %%include line  : "
    grep -q "torrc.d" /etc/tor/torrc 2>/dev/null \
        && echo -e "${GREEN}present${NC}" \
        || echo -e "${RED}MISSING — torrc.d not included!${NC}"

    # Duplicate directive detection
    echo
    echo -e "${BOLD}── Duplicate Directive Check ──${NC}"
    local conflicts_found=0
    if [[ -f /etc/tor/torrc ]]; then
        for directive in "${_CONFLICT_DIRECTIVES[@]}"; do
            if grep -qE "^[[:space:]]*${directive}[[:space:]]" /etc/tor/torrc 2>/dev/null; then
                echo -e "  ${RED}CONFLICT${NC}: '$directive' found in /etc/tor/torrc"
                conflicts_found=1
            fi
        done
    fi
    if [[ $conflicts_found -eq 0 ]]; then
        echo -e "  ${GREEN}No conflicts detected${NC} — torrc is clean"
    else
        echo -e "  ${YELLOW}Fix with: sudo ghostly fix-torrc${NC}"
    fi

    echo
    echo -e "${BOLD}── Tor Service ──${NC}"
    echo "  Service status : $(service_active && echo active || echo inactive)"
    echo "  SOCKS port     : $(tcp_check 127.0.0.1 $TOR_PORT 2>/dev/null && echo -e "${GREEN}OPEN${NC}" || echo -e "${RED}CLOSED${NC}")"
    echo "  Control port   : $(tcp_check 127.0.0.1 $TOR_CONTROL_PORT 2>/dev/null && echo "open ($TOR_CONTROL_PORT)" || echo -e "${RED}CLOSED${NC}")"
    echo "  Cookie file    : $([[ -f "$COOKIE_FILE" ]] && echo "EXISTS ($COOKIE_FILE)" || echo "MISSING")"
    echo "  torrc snippet  : $([[ -f "$TORRC_SNIPPET" ]] && echo "EXISTS" || echo "NOT FOUND")"

    # Show snippet content summary if exists
    if [[ -f "$TORRC_SNIPPET" ]]; then
        echo "  Snippet ports  :"
        grep -E "^(SocksPort|ControlPort|TransPort|DNSPort)" "$TORRC_SNIPPET" 2>/dev/null \
            | sed 's/^/    /' || echo "    (none found)"
    fi

    echo
    echo -e "${BOLD}── Bootstrap & Circuit ──${NC}"
    local phase="N/A"
    if tcp_check 127.0.0.1 "$TOR_CONTROL_PORT" 2>/dev/null; then
        phase="$(tcp_send 127.0.0.1 "$TOR_CONTROL_PORT" \
            "AUTHENTICATE\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n" \
            | grep "bootstrap-phase" | grep -o "PROGRESS=[0-9]*" \
            | cut -d= -f2 || echo "N/A")"
        echo "  Bootstrap      : ${phase}%"

        # Circuit establishment
        local circuit_status
        circuit_status="$(tcp_send 127.0.0.1 "$TOR_CONTROL_PORT" \
            "AUTHENTICATE\r\nGETINFO circuit-status\r\nQUIT\r\n" \
            | grep "^250+circuit-status" -A5 | grep "BUILT" | wc -l || echo 0)"
        echo "  Built circuits : ${circuit_status}"
    else
        echo "  Bootstrap      : control port not available"
    fi

    # SOCKS verification
    echo -n "  SOCKS verify   : "
    local socks_ip
    if [[ "$TOR_ROUTING_MODE" == "socks-only" ]] || \
       [[ "$(state_val TOR_ROUTING_MODE)" == "socks-only" ]]; then
        socks_ip="$(curl -s --max-time 8 \
            --socks5-hostname "127.0.0.1:${TOR_PORT}" \
            https://ipinfo.io/ip 2>/dev/null || true)"
    else
        socks_ip="$(torsocks curl -s --max-time 8 \
            https://ipinfo.io/ip 2>/dev/null || true)"
    fi
    [[ -n "$socks_ip" ]] \
        && echo -e "${GREEN}OK${NC} — exit IP: $socks_ip" \
        || echo -e "${RED}FAILED${NC} — no response via Tor"

    echo "  Recent Tor logs:"
    journalctl -u tor --since "5 minutes ago" --no-pager -q 2>/dev/null \
        | grep -i "bootstrap\|error\|warn\|address already\|bind\|failed" \
        | tail -8 | sed 's/^/    /' \
        || echo "    No recent logs"

    echo
    echo -e "${BOLD}── Network ──${NC}"
    echo "  Default route  : $(ip route 2>/dev/null | grep default | head -1 || echo none)"
    echo "  DNS config     : $(grep ^nameserver /etc/resolv.conf 2>/dev/null | head -2 || echo none)"
    echo "  IPv6 disabled  : $(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo unknown)"

    echo
    echo -e "${BOLD}── Firewall (OUTPUT chain) ──${NC}"
    ipt -L OUTPUT -n --line-numbers 2>/dev/null | head -20 \
        | sed 's/^/  /' || echo "  Unable to read iptables"

    echo
}

############################
# LEAK TEST
############################

leak_test() {
    log "Running comprehensive leak test..."

    # Detect how to route
    local routing; routing="$(state_val TOR_ROUTING_MODE)"
    [[ -z "$routing" ]] && routing="$TOR_ROUTING_MODE"
    [[ -z "$routing" ]] && routing="socks-only"

    _curl() {
        if [[ "$routing" == "socks-only" ]]; then
            curl -s --max-time 15 \
                --socks5-hostname "127.0.0.1:${TOR_PORT}" "$@"
        else
            torsocks curl -s --max-time 15 "$@"
        fi
    }

    echo
    echo -e "${BLUE}===== TOR CHECK =====${NC}"
    _curl https://check.torproject.org/api/ip 2>/dev/null \
        | python3 -m json.tool 2>/dev/null || echo "unavailable"

    echo
    echo -e "${BLUE}===== PUBLIC IP =====${NC}"
    _curl https://ipinfo.io 2>/dev/null \
        | python3 -m json.tool 2>/dev/null || echo "unavailable"

    echo
    echo -e "${BLUE}===== DNS LEAK =====${NC}"
    _curl "https://bash.ws/dnsleak/test/$RANDOM" 2>/dev/null \
        | python3 -m json.tool 2>/dev/null || \
        torsocks dig +short TXT whoami.cloudflare @1.1.1.1 2>/dev/null || \
        echo "DNS test unavailable"

    echo
    echo -e "${BLUE}===== WEBRTC =====${NC}"
    echo "  Cannot be tested from CLI."
    echo "  Visit: https://browserleaks.com/webrtc"

    echo
    echo -e "${BLUE}===== IPV6 LEAK =====${NC}"
    sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "^1" \
        && echo "  IPv6 disabled — no leak possible." \
        || warn "  IPv6 ENABLED — possible leak!"

    echo
    echo -e "${BLUE}===== KILL-SWITCH =====${NC}"
    if [[ "$(state_val SKIP_KILLSWITCH)" == "1" ]]; then
        warn "  Kill-switch disabled for profile: $(state_val RUNTIME_PROFILE)"
        warn "  SOCKS-only profile — applications must route via SOCKS5"
    elif ipt -L OUTPUT -n 2>/dev/null | grep -q "policy DROP"; then
        echo -e "  ${GREEN}Kill-switch ACTIVE (OUTPUT DROP)${NC}"
    else
        warn "  Kill-switch NOT ACTIVE"
    fi

    echo
    echo -e "${BLUE}===== ROUTING MODE =====${NC}"
    echo "  Active routing: ${routing:-unknown}"
    [[ "$routing" == "socks-only" ]] && \
        echo "  SOCKS5 endpoint: 127.0.0.1:${TOR_PORT}"

    echo
}

############################
# MENU
############################

menu() {
    detect_environment 2>/dev/null || true
    while true; do
        clear
        echo -e "${BLUE}${BOLD}=================================${NC}"
        echo -e "${BLUE}${BOLD}            GHOSTLY              ${NC}"
        echo -e "${BLUE}${BOLD}=================================${NC}"
        echo
        echo -e "  Profile : ${CYAN}${RUNTIME_PROFILE:-detecting...}${NC}"
        echo -e "  Mode    : ${CYAN}$MODE${NC}"
        echo -e "  Routing : ${CYAN}${TOR_ROUTING_MODE:-auto}${NC}"
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
proxy_env() {
cat <<EOF
export http_proxy="socks5h://127.0.0.1:${TOR_PORT}"
export https_proxy="socks5h://127.0.0.1:${TOR_PORT}"
export HTTP_PROXY="socks5h://127.0.0.1:${TOR_PORT}"
export HTTPS_PROXY="socks5h://127.0.0.1:${TOR_PORT}"
export all_proxy="socks5h://127.0.0.1:${TOR_PORT}"
export ALL_PROXY="socks5h://127.0.0.1:${TOR_PORT}"
EOF
}

proxy_unset() {
cat <<EOF
unset http_proxy
unset https_proxy
unset HTTP_PROXY
unset HTTPS_PROXY
unset all_proxy
unset ALL_PROXY
EOF
}

mkdir -p "$(dirname "$LOG_FILE")" "$CONFIG_DIR" "$BACKUP_DIR"

case "${1:-}" in
    env)
        proxy_env
        ;;
    unset-env)
        proxy_unset
        ;;
    install)
        require_root
        install_deps
        ;;
    on|start)
        [[ "${2:-}" == "--mode" ]] && MODE="${3:-balanced}"
        [[ "${2:-}" == "--profile" ]] && RUNTIME_PROFILE="${3:-}"
        start_ghostly
        ;;
    off|stop)
        stop_ghostly
        ;;
    rotate)
        rotate_tor
        ;;
    status)
        detect_environment 2>/dev/null || true
        status_ghostly
        ;;
    leak-test)
        leak_test
        ;;
    diag|diagnostics)
        require_root
        diagnostics
        ;;
    fix-torrc)
        require_root
        fix_torrc
        ;;
    menu)
        menu
        ;;
    -v|--version|version)
        echo "Ghostly v${VERSION}"
        ;;
    *)
        echo
        echo -e "${BOLD}Ghostly${NC} — Adaptive Hardened Anonymity Toolkit"
        echo
        echo "Usage:"
        echo "  sudo ghostly install                Install dependencies"
        echo "  sudo ghostly on                     Enable (auto-detect profile)"
        echo "  sudo ghostly on --mode strict       Enable with strict privacy mode"
        echo "  sudo ghostly on --mode safe         Enable with safe stability mode"
        echo "  sudo ghostly on --profile wsl       Force a specific runtime profile"
        echo "  sudo ghostly off                    Disable & restore everything"
        echo "  sudo ghostly rotate                 Rotate Tor circuit"
        echo "  sudo ghostly status                 Show full status"
        echo "  sudo ghostly leak-test              Run leak tests"
        echo "  sudo ghostly diag                   Environment diagnostics"
        echo "  sudo ghostly fix-torrc              Fix legacy torrc conflicts"
        echo "  sudo ghostly menu                   Interactive menu"
        echo "  ghostly --version                   Show version"
        echo
        echo "Privacy Modes:"
        echo "  balanced   Default. LAN excluded, standard circuits."
        echo "  strict     LAN also via Tor. Reduced circuits. Max privacy."
        echo "  safe       LAN excluded, more circuits. Max stability."
        echo
        echo "Runtime Profiles (auto-detected):"
        echo "  baremetal  Full transparent routing + MAC spoof + kill-switch"
        echo "  vm         Transparent routing, MAC skipped"
        echo "  cloud      Transparent routing, MAC + IPv6 skipped"
        echo "  wsl        SOCKS-only, no kernel modifications"
        echo "  container  SOCKS-only, no kernel modifications"
        echo
        ;;
esac
