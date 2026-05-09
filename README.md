# 👻 Ghostly

A production-grade hardened anonymity toolkit for Linux. Routes all traffic through [Tor](https://www.torproject.org/), spoofs your MAC address, disables IPv6, and applies a strict kill-switch firewall — with automatic rollback protection to prevent network lockout.

> ⚠️ **For legal and ethical use only.** Intended for privacy-conscious users, security researchers, journalists, and penetration testers working in authorized environments.

---

## Features

- 🔒 **Full traffic routing through Tor** — transparent proxy via iptables
- 🛡️ **Kill-switch firewall** — OUTPUT DROP applied *only after* Tor is verified
- 🔄 **Automatic rollback** — `trap ERR` restores everything on failure, no network lockout
- 🎭 **Smart MAC spoofing** — auto-skipped on WSL, Docker, Hyper-V, KVM, VPS
- 🚫 **IPv6 disable** — kernel-level, persists across hotplug events
- 🔐 **DNS over Tor** — locked via `chattr +i`, DNS applied after Tor is confirmed
- 🍪 **Cookie authentication** — no plaintext control passwords
- 📁 **torrc.d snippet** — non-destructive Tor config at `/etc/tor/torrc.d/ghostly.conf`
- 🌐 **LAN exclusions** — `192.168.x`, `10.x`, `172.16.x` excluded in balanced/safe mode
- ⚙️ **Three modes** — `balanced`, `strict`, `safe`
- 🩺 **Diagnostics** — virt type, network manager, firewall backend, bootstrap status
- 🧪 **Leak test** — IP, DNS, IPv6, kill-switch check
- 📋 **Timestamped logging** — `/var/log/ghostly.log`

---

## Requirements

- Linux (Debian/Ubuntu recommended)
- Root privileges
- `systemd`

---

## Installation

```bash
git clone https://github.com/hanzzly/ghostly
cd ghostly
chmod +x ghostly.sh
sudo ln -s "$(pwd)/ghostly.sh" /usr/local/bin/ghostly

# Install dependencies (tor, macchanger, iptables, nftables, etc.)
sudo ghostly install
```

---

## Usage

```bash
sudo ghostly on                   # Enable (balanced mode)
sudo ghostly on --mode strict     # Maximum privacy
sudo ghostly on --mode safe       # Maximum stability
sudo ghostly off                  # Disable & restore everything
sudo ghostly rotate               # Rotate Tor circuit (new identity)
sudo ghostly status               # Show current status
sudo ghostly leak-test            # Run leak tests
sudo ghostly diag                 # Environment diagnostics
sudo ghostly menu                 # Interactive menu
ghostly --version                 # Show version
```

---

## Modes

| Mode | LAN Excluded | Circuits | StrictNodes | Use Case |
|------|:---:|:---:|:---:|---------|
| `balanced` | ✅ | 32 | No | Default — privacy + usability |
| `strict` | ❌ | 8 | Yes | Maximum anonymity, all traffic via Tor |
| `safe` | ✅ | 64 | No | VM/unstable environments |

Override mode at any time:
```bash
sudo ghostly on --mode strict
# or set permanently:
export GHOSTLY_MODE=strict
```

---

## Startup Flow

Safe ordering prevents network lockout — kill-switch is applied **last**, after Tor is verified:

```
1. Backup routes & firewall
2. Configure Tor         → write /etc/tor/torrc.d/ghostly.conf
3. Start Tor             → systemctl restart tor
4. Spoof MAC             → skipped automatically on VMs/containers
5. Disable IPv6          → kernel sysctl + sysctl.d persist
6. Apply firewall        → OUTPUT stays ACCEPT (permissive)
7. Wait for bootstrap    → journalctl + control port check
8. Verify Tor exit IP    → check.torproject.org/api/ip
9. Lock DNS              → /etc/resolv.conf → 127.0.0.1, chattr +i
10. Activate kill-switch → OUTPUT policy → DROP
```

---

## Automatic Rollback

If any step fails (Tor bootstrap timeout, config error, etc.), Ghostly automatically restores your original state:

```
trap cleanup_on_error ERR
  → OUTPUT ACCEPT (immediate, prevents lockout)
  → restore iptables
  → restore resolv.conf
  → restore MAC
  → re-enable IPv6
  → restore routing table
  → stop Tor
  → remove torrc.d snippet
```

No manual intervention needed — your internet connection survives a failed startup.

---

## Virtualization Detection

MAC spoofing is automatically skipped for:

| Environment | Detection Method |
|------------|-----------------|
| WSL / WSL2 | `/proc/version` kernel string |
| Docker | `/.dockerenv` file |
| LXC | `/proc/1/environ` container flag |
| Hyper-V | `systemd-detect-virt` |
| KVM / QEMU | `systemd-detect-virt` |
| VMware | `systemd-detect-virt` |
| AWS / GCP / Azure | `systemd-detect-virt` |

---

## Firewall Design

Kill-switch uses **RETURN-based exclusions** instead of `! -flag` negation, ensuring compatibility with both `iptables-legacy` and `iptables-nft` (nf_tables) backends:

```
INPUT   → DROP (default)
FORWARD → DROP (default)
OUTPUT  → ACCEPT → DROP (after Tor verified)

ALLOW   loopback
ALLOW   established/related
ALLOW   Tor daemon (by UID)
RETURN  LAN ranges (balanced/safe mode)
NAT     TCP  → TransPort 9040
NAT     DNS  → DNSPort 5353
DROP    fallthrough
```

---

## File Locations

| Path | Purpose |
|------|---------|
| `/etc/ghostly/` | Config directory |
| `/etc/tor/torrc.d/ghostly.conf` | Tor config snippet (non-destructive) |
| `/var/lib/ghostly/iptables.bak` | Firewall backup |
| `/var/lib/ghostly/resolv.conf.bak` | DNS backup |
| `/var/lib/ghostly/routes.bak` | Routing table backup |
| `/var/lib/ghostly/state` | Active state file |
| `/var/log/ghostly.log` | Timestamped activity log |
| `/run/tor/control.authcookie` | Tor cookie auth (root-readable) |
| `/etc/sysctl.d/99-ghostly-no-ipv6.conf` | IPv6 disable persistence |

---

## Diagnostics

```bash
sudo ghostly diag
```

Reports:

- Virtualization type & MAC spoof eligibility
- Active network manager (NetworkManager / systemd-networkd / ifupdown)
- Firewall backend (iptables-legacy / iptables-nft / nftables)
- Tor service status & bootstrap log
- DNS configuration
- IPv6 status
- Firewall OUTPUT chain rules

---

## Security Notes

- **Cookie auth**: Tor control port uses `CookieAuthentication 1` — no plaintext passwords stored anywhere.
- **Non-destructive Tor config**: Ghostly writes to `/etc/tor/torrc.d/ghostly.conf` and adds a `%include` to the main `torrc`. Your existing Tor config is never overwritten.
- **DNS timing**: `resolv.conf` is only locked *after* Tor bootstraps — avoids a scenario where DNS is broken before Tor is ready.
- **Kill-switch timing**: `OUTPUT DROP` is applied *after* Tor exit is verified — prevents locking yourself out if Tor fails to start.

---

## Limitations

- **WebRTC**: Cannot be blocked at the OS level. Check manually at [browserleaks.com/webrtc](https://browserleaks.com/webrtc) or use Tor Browser / uBlock Origin.
- **UDP (non-DNS)**: Tor only carries TCP. Non-DNS UDP is blocked by the kill-switch (dropped, not leaked).
- **Tor Browser**: For maximum browser anonymity, use [Tor Browser](https://www.torproject.org/download/) alongside Ghostly.
- **Performance**: All traffic through Tor will be slower. Expected behavior.

---

## Disclaimer

This tool is provided for **educational and legitimate privacy use only**. The author is not responsible for any misuse. Always comply with the laws of your jurisdiction.

---

## License

MIT — see [LICENSE](LICENSE)
