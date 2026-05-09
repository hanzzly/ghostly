# 👻 Ghostly

A hardened anonymous networking toolkit for Linux that routes all traffic through [Tor](https://www.torproject.org/), spoofs your MAC address, disables IPv6, and applies a strict kill-switch firewall to prevent any traffic leaks.

> ⚠️ **For legal and ethical use only.** Intended for privacy-conscious users, security researchers, journalists, and penetration testers working in authorized environments.

---

## Features

- 🔒 **Full traffic routing through Tor** — transparent proxy via iptables
- 🛡️ **Kill-switch firewall** — all non-Tor traffic is dropped; no leaks possible
- 🎭 **MAC address spoofing** — randomizes hardware address on your network interface
- 🚫 **IPv6 disable** — prevents IPv6 leak, persists across hotplug events
- 🔐 **DNS over Tor** — DNS queries routed through Tor's DNSPort (no DNS leak)
- 🔄 **Circuit rotation** — request a new Tor identity on demand
- ✅ **Bootstrap verification** — confirms Tor is fully connected before proceeding
- 🧪 **Leak test** — checks IP, DNS, and IPv6 for any exposure
- 📋 **Full logging** — timestamped log at `/var/log/ghost.log`

---

## Requirements

- Linux (Debian/Ubuntu recommended)
- Root privileges
- `systemd`

---

## Installation

```bash
git clone https://github.com/hanzzly/ghostly.git
cd ghostly
chmod +x ghostly.sh
sudo ln -s "$(pwd)/ghostly.sh" /usr/local/bin/ghostly

# Install dependencies
sudo ghostly install
```

---

## Usage

```bash
sudo ghostly on           # Enable Ghost Mode
sudo ghostly off          # Disable Ghost Mode
sudo ghostly rotate       # Rotate Tor circuit (new identity)
sudo ghostly status       # Show current status
sudo ghostly leak-test    # Run leak tests
sudo ghostly menu         # Interactive menu
```

---

## How It Works

### When `ghost on` is run:

```
1. Configure Tor      → torrc with TransPort, DNSPort, HashedControlPassword
2. Spoof MAC          → macchanger randomizes hardware address
3. Disable IPv6       → sysctl + /etc/sysctl.d persist
4. Lock DNS           → /etc/resolv.conf → 127.0.0.1, chattr +i
5. Apply firewall     → iptables kill-switch, redirect TCP+DNS through Tor
6. Wait for bootstrap → reads journalctl for "Bootstrapped 100%"
7. Verify IP          → confirms traffic exits via Tor
```

### Firewall rules (simplified):

```
INPUT   → DROP (default)
FORWARD → DROP (default)
OUTPUT  → DROP (default)

ALLOW   loopback
ALLOW   established/related connections
ALLOW   Tor daemon outbound (by UID)
NAT     TCP → TransPort (9040)
NAT     DNS UDP/TCP → DNSPort (5353)
```

### When `ghost off` is run:

```
1. Restore iptables   → from backup at /var/lib/ghost/iptables.bak
2. Restore DNS        → from backup at /var/lib/ghost/resolv.conf.bak
3. Restore MAC        → macchanger -p restores permanent address
4. Re-enable IPv6     → sysctl + removes sysctl.d config
5. Stop Tor           → systemctl stop tor
```

---

## File Locations

| Path | Purpose |
|------|---------|
| `/etc/ghost/` | Ghost config directory |
| `/etc/ghost/.ctrl_pass` | Tor control password (root-only, `chmod 600`) |
| `/var/lib/ghost/` | Backups (iptables, resolv.conf, torrc) |
| `/var/log/ghost.log` | Timestamped activity log |
| `/etc/sysctl.d/99-ghost-no-ipv6.conf` | IPv6 disable persistence |

---

## Security Notes

- The Tor control port uses `HashedControlPassword` (auto-generated per hostname). Plain `AUTHENTICATE` without credentials will be rejected.
- `resolv.conf` is locked with `chattr +i` to prevent NetworkManager or other daemons from overwriting it.
- IPv6 is disabled at the kernel level and persisted via `sysctl.d` to survive interface hotplug events.
- Backups of iptables, DNS, and Tor config are taken before any modification, so `ghost off` cleanly restores your original state.
- WebRTC leaks cannot be prevented at the OS level — use a browser extension (e.g. uBlock Origin) or a Tor Browser.

---

## Limitations

- **WebRTC**: Cannot be blocked from the terminal. Check manually at [browserleaks.com/webrtc](https://browserleaks.com/webrtc).
- **UDP traffic (non-DNS)**: Tor only supports TCP. Non-DNS UDP is blocked by the kill-switch (dropped, not leaked).
- **Tor Browser**: For maximum browser anonymity, use [Tor Browser](https://www.torproject.org/download/) alongside this toolkit.
- **Speed**: All traffic through Tor will be slower than a direct connection. This is expected.

---

## Disclaimer

This tool is provided for **educational and legitimate privacy use only**. The author is not responsible for any misuse. Always comply with the laws of your jurisdiction.

---

## License

MIT
