# 👻 Ghostly

A production-grade adaptive anonymity toolkit for Linux. Automatically detects your runtime environment and configures the optimal Tor anonymity strategy — full transparent routing on bare metal, SOCKS-only safe mode on WSL/containers, with automatic fallback and zero-lockout rollback protection.

> ⚠️ **For legal and ethical use only.** Intended for privacy-conscious users, security researchers, journalists, and penetration testers working in authorized environments.

---

## Features

- 🧠 **Adaptive runtime profiles** — auto-detects baremetal, VM, cloud, WSL, container
- 🔀 **Automatic routing mode selection** — transparent or SOCKS-only, based on environment
- 🔄 **Transparent → SOCKS fallback** — if transparent mode fails, downgrades automatically
- 🔒 **Full transparent Tor routing** — iptables-based on supported environments
- 🛡️ **Kill-switch firewall** — OUTPUT DROP applied *only after* Tor verified
- 🔐 **Startup verification chain** — service → SOCKS → bootstrap → IsTor=true
- 🎭 **Smart MAC spoofing** — auto-skipped on WSL, Docker, Hyper-V, KVM, cloud
- 🚫 **IPv6 disable** — kernel-level, skipped on cloud/container
- 🔑 **Cookie authentication** — no plaintext passwords anywhere
- 📁 **torrc.d snippet** — non-destructive Tor config
- 🌐 **LAN exclusions** — `10.x`, `172.16.x`, `192.168.x` excluded in balanced/safe mode
- 🩺 **Adaptive diagnostics** — profile capabilities, WSL warnings, bootstrap phase
- ↩️ **Zero-lockout rollback** — `trap ERR` restores everything on any failure
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

sudo ghostly install
```

---

## Usage

```bash
sudo ghostly on                      # Enable (auto-detect profile + mode)
sudo ghostly on --mode strict        # Maximum privacy
sudo ghostly on --mode safe          # Maximum stability
sudo ghostly on --profile wsl        # Force a specific runtime profile
sudo ghostly off                     # Disable & restore everything
sudo ghostly rotate                  # Rotate Tor circuit (new identity)
sudo ghostly status                  # Full status with profile info
sudo ghostly leak-test               # Leak tests (routing-aware)
sudo ghostly diag                    # Full environment diagnostics
sudo ghostly menu                    # Interactive menu
ghostly --version                    # Show version
```

---

## Runtime Profiles

Ghostly automatically selects the right profile. You can also force one with `--profile`.

| Profile | Transparent | MAC Spoof | IPv6 Disable | DNS Lock | Kill-Switch |
|---------|:-----------:|:---------:|:------------:|:--------:|:-----------:|
| `baremetal` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `vm` | ✅ | ❌ | ✅ | ✅ | ✅ |
| `cloud` | ✅ | ❌ | ❌ | ✅ | ✅ |
| `wsl` | ❌ | ❌ | ✅ | ❌ | ❌ |
| `container` | ❌ | ❌ | ❌ | ❌ | ❌ |

### WSL & Container: SOCKS-only mode

On WSL and containers, Ghostly cannot modify kernel networking. Instead:

```bash
# Ghostly starts Tor and gives you SOCKS5 access:
export https_proxy=socks5h://127.0.0.1:9050
export http_proxy=socks5h://127.0.0.1:9050

# curl direct:
curl --socks5-hostname 127.0.0.1:9050 https://ipinfo.io/ip

# proxychains:
proxychains4 curl https://ipinfo.io/ip
```

---

## Detection Logic

```
1. systemd-detect-virt           (primary — most reliable)
2. /.dockerenv                   (Docker/Podman fallback)
3. /proc/version grep microsoft  (WSL fallback)
4. /proc/1/environ container=lxc (LXC fallback)
5. /run/systemd/container        (systemd-nspawn)

Detected virt string → canonical profile:
  none / bare-metal  → baremetal
  wsl / wsl2         → wsl
  docker / podman    → container
  lxc / openvz       → container
  kvm / vmware / xen → vm
  amazon / azure     → cloud
```

---

## Privacy Modes

| Mode | LAN Excluded | Circuits | StrictNodes | Use Case |
|------|:---:|:---:|:---:|---------|
| `balanced` | ✅ | 32 | No | Default |
| `strict` | ❌ | 8 | Yes | Maximum anonymity |
| `safe` | ✅ | 64 | No | VM/unstable environments |

Modes combine with profiles. For example: `vm` + `strict` = transparent routing (kernel-level), no LAN exclusion, 8 circuits.

---

## Startup Verification Chain

Ghostly runs 4 verification steps before activating the kill-switch:

```
[1/4] Tor service active       → systemctl is-active tor
[2/4] SOCKS port open          → nc -z 127.0.0.1:9050
[3/4] Bootstrap 100%           → journalctl + control port GETINFO
[4/4] IsTor=true               → check.torproject.org/api/ip
         ↓ pass                        ↓ fail
  Lock DNS → Kill-switch       Transparent → SOCKS fallback
                                       ↓ also fail
                                   Full rollback
```

Kill-switch (`OUTPUT DROP`) is **never** applied before step 4 passes.

---

## Automatic Fallback

If transparent routing fails verification, Ghostly automatically downgrades:

```
transparent mode failed
  → restore firewall (OUTPUT ACCEPT)
  → reconfigure Tor without TransPort/DNSPort
  → re-run verification chain in SOCKS-only mode
  → if passes: continue in SOCKS fallback mode
  → if fails: full rollback, exit cleanly
```

Status will show `routing: socks-only (fallback)` when this occurs.

---

## Rollback Protection

Every startup step is wrapped in `trap cleanup_on_error ERR`:

```
Any error →
  OUTPUT ACCEPT  (immediate, prevents lockout)
  restore iptables
  restore resolv.conf
  restore MAC address
  re-enable IPv6
  restore routing table
  stop Tor
  remove torrc.d snippet
  clear state file
```

Your internet connection survives any failure.

---

## Tor Config (torrc.d)

Ghostly writes a profile-aware snippet to `/etc/tor/torrc.d/ghostly.conf` and adds a `%include` to the main `torrc`. Your existing Tor config is never overwritten.

**baremetal/vm/cloud snippet includes:**
```
SocksPort, ControlPort, CookieAuthentication
TransPort 9040 IsolateClientAddr IsolateClientProtocol
DNSPort 5353
VirtualAddrNetworkIPv4, AutomapHostsOnResolve
```

**wsl/container snippet includes:**
```
SocksPort, ControlPort, CookieAuthentication
# (no TransPort, no DNSPort)
```

---

## File Locations

| Path | Purpose |
|------|---------|
| `/etc/ghostly/` | Config directory |
| `/etc/tor/torrc.d/ghostly.conf` | Tor config snippet |
| `/var/lib/ghostly/iptables.bak` | Firewall backup |
| `/var/lib/ghostly/resolv.conf.bak` | DNS backup |
| `/var/lib/ghostly/routes.bak` | Routing table backup |
| `/var/lib/ghostly/state` | Active state file |
| `/var/log/ghostly.log` | Timestamped activity log |
| `/run/tor/control.authcookie` | Tor cookie (root-readable) |
| `/etc/sysctl.d/99-ghostly-no-ipv6.conf` | IPv6 disable persistence |

---

## Diagnostics

```bash
sudo ghostly diag
```

Reports:

- Runtime profile + capability matrix
- WSL/container compatibility warnings
- Tor service status + bootstrap phase (live from control port)
- Active torrc.d snippet
- Firewall OUTPUT chain rules
- Network manager + firewall backend detection
- DNS and IPv6 status

---

## Limitations

- **WebRTC**: Cannot be blocked at the OS level. Check at [browserleaks.com/webrtc](https://browserleaks.com/webrtc) or use Tor Browser.
- **UDP (non-DNS)**: Tor only carries TCP. Non-DNS UDP is dropped by the kill-switch.
- **WSL kill-switch**: Not possible in WSL — use SOCKS5 proxy per-application.
- **Performance**: Traffic through Tor will be slower. Expected behavior.

---

## Disclaimer

This tool is provided for **educational and legitimate privacy use only**. The author is not responsible for any misuse. Always comply with the laws of your jurisdiction.

---

## License

MIT — see [LICENSE](LICENSE)
