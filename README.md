# Ghostly

**Toolkit Anonimitas Adaptif Tingkat Produksi**

Ghostly adalah toolkit anonimitas berbasis Bash yang merutekan seluruh traffic sistem melalui jaringan Tor. Ghostly mendeteksi lingkungan runtime secara otomatis — bare metal, VM, cloud VPS, WSL, atau container — lalu menyesuaikan perilakunya: menerapkan transparent proxy penuh dengan kill-switch jika memungkinkan, atau turun ke mode SOCKS-only secara graceful ketika modifikasi kernel tidak tersedia.

---

## Fitur

- **Profil berbasis environment** — deteksi otomatis bare metal, VM, cloud, WSL, dan container; setiap profil hanya mengaktifkan fitur yang benar-benar berjalan di environment tersebut
- **Transparent proxy** — mengalihkan seluruh traffic TCP dan DNS melalui Tor tanpa konfigurasi per-aplikasi (bare metal / VM / cloud)
- **Fallback SOCKS-only** — mode aman untuk WSL dan container di mana modifikasi kernel tidak diizinkan
- **Rantai verifikasi 4 langkah** — health service → SOCKS port → bootstrap 100% → konfirmasi IsTor
- **Kill-switch** — set `OUTPUT DROP` setelah Tor dikonfirmasi; mencegah traffic bocor jika Tor mati
- **Spoofing MAC address** — mengacak MAC saat startup (bare metal saja)
- **Nonaktifkan IPv6** — memblokir vektor kebocoran IPv6 via sysctl
- **Kunci DNS** — menulis `nameserver 127.0.0.1` dan mengunci `/etc/resolv.conf` secara immutable
- **Rotasi sirkuit** — mengirim `SIGNAL NEWNYM` melalui control port dengan cookie auth
- **Auto-rollback** — ERR trap memulihkan firewall, DNS, MAC, IPv6, dan route jika terjadi error
- **Firewall idempoten** — memanggil `configure_firewall` dua kali tetap aman; tidak ada jendela bocor antara flush dan kill-switch
- **Arsitektur torrc** — tidak pernah menimpa `/etc/tor/torrc`; semua konfigurasi runtime ditulis ke `/etc/tor/torrc.d/ghostly.conf`

---

## Persyaratan

- Linux (Debian/Ubuntu disarankan)
- Bash 4.0+
- Root / sudo

Dependensi diinstal otomatis via `sudo ghostly install`:

```
tor  torsocks  proxychains4  macchanger  curl
iptables  iptables-persistent  iproute2
netcat-openbsd  socat  dnsutils  nftables  xxd
```

---

## Instalasi

```bash
# Clone repositori
git clone https://github.com/hanzzly/ghostly
cd ghostly

# Instal dependensi
sudo bash ghostly.sh install

# Instal sebagai perintah sistem (opsional)
sudo cp ghostly.sh /usr/local/bin/ghostly
sudo chmod +x /usr/local/bin/ghostly
```

---

## Mulai Cepat

```bash
# Aktifkan dengan profil yang terdeteksi otomatis
sudo ghostly on

# Aktifkan dengan mode privasi tertentu
sudo ghostly on --mode strict
sudo ghostly on --mode balanced   # default
sudo ghostly on --mode safe

# Paksa profil runtime tertentu
sudo ghostly on --profile wsl
sudo ghostly on --profile baremetal

# Cek status
sudo ghostly status

# Nonaktifkan dan pulihkan semua pengaturan
sudo ghostly off
```

---

## Semua Perintah

| Perintah | Keterangan |
|---|---|
| `sudo ghostly install` | Instal semua dependensi via apt |
| `sudo ghostly on` | Aktifkan — deteksi profil dan mode otomatis |
| `sudo ghostly on --mode <mode>` | Aktifkan dengan mode privasi tertentu |
| `sudo ghostly on --profile <profil>` | Paksa profil runtime tertentu |
| `sudo ghostly off` | Nonaktifkan, pulihkan firewall / DNS / MAC / IPv6 |
| `sudo ghostly rotate` | Minta sirkuit Tor baru (SIGNAL NEWNYM) |
| `sudo ghostly status` | Dashboard status lengkap |
| `sudo ghostly leak-test` | Tes kebocoran IP, DNS, IPv6, dan kill-switch |
| `sudo ghostly diag` | Diagnostik environment dan konfigurasi mendalam |
| `sudo ghostly fix-torrc` | Bersihkan konflik di `/etc/tor/torrc` lama |
| `sudo ghostly menu` | Menu TUI interaktif |
| `ghostly env` | Cetak ekspor variabel environment proxy |
| `ghostly unset-env` | Cetak perintah hapus variabel environment proxy |
| `ghostly --version` | Tampilkan versi |

---

## Mode Privasi

Mode mengatur perilaku sirkuit Tor dan kebijakan routing LAN. Diatur via `--mode` atau variabel environment `GHOSTLY_MODE`.

| Mode | Traffic LAN | Maks Sirkuit | Kapan Dipakai |
|---|---|---|---|
| `balanced` | Dikecualikan dari Tor | 32 | Default — keseimbangan privasi dan stabilitas |
| `strict` | Juga dirutekan melalui Tor | 8 | Privasi maksimum; akses LAN bisa terganggu |
| `safe` | Dikecualikan dari Tor | 64 | Stabilitas maksimum; pergantian sirkuit minimal |

```bash
# Mode persisten via variabel environment
export GHOSTLY_MODE=strict
sudo ghostly on
```

> **Peringatan — strict mode di server cloud/remote:** mengaktifkan strict mode akan merutekan semua traffic termasuk SSH melalui Tor. Jika kill-switch aktif sebelum sesi SSH terbentuk melalui klien yang mendukung Tor, kamu akan terkunci. Whitelist IP manajemen sebelum mengaktifkan strict mode di server remote.

---

## Profil Runtime

Ghostly mendeteksi environment menggunakan strategi 3 lapis: `systemd-detect-virt` → pengecekan manual `/proc` → fallback konservatif. Setiap profil hanya mengaktifkan fitur yang aman dan fungsional di environment tersebut.

| Profil | Routing | Spoof MAC | Nonaktifkan IPv6 | Kunci DNS | Kill-switch |
|---|---|---|---|---|---|
| `baremetal` | Transparent | ✓ | ✓ | ✓ | ✓ |
| `vm` | Transparent | — | ✓ | ✓ | ✓ |
| `cloud` | Transparent | — | — | ✓ | ✓ |
| `wsl` | SOCKS-only | — | — | — | — |
| `container` | SOCKS-only | — | — | — | — |

### Profil SOCKS-only (WSL / container)

Di WSL dan container, Ghostly menjalankan Tor dan mengekspos proxy SOCKS5 di `127.0.0.1:9050`. Tidak ada perubahan kernel yang dilakukan. Aplikasi harus dikonfigurasi secara eksplisit untuk menggunakan proxy ini.

```bash
# Terapkan ke shell saat ini
eval "$(ghostly env)"

# Atau ekspor manual
export https_proxy=socks5h://127.0.0.1:9050
export http_proxy=socks5h://127.0.0.1:9050

# Hapus proxy dari shell
eval "$(ghostly unset-env)"
```

---

## Cara Kerja

### Urutan startup

```
detect_environment → resolve_profile
        ↓
  configure_tor        (sanitasi torrc, tulis ghostly.conf, validasi, restart)
        ↓
  spoof_mac            (bare metal saja)
        ↓
  disable_ipv6         (bare metal / vm / cloud)
        ↓
  configure_firewall   (profil transparent saja — OUTPUT=ACCEPT)
        ↓
  rantai verifikasi:
    [1] service aktif?
    [2] SOCKS port terbuka?
    [3] bootstrap 100%?  (control port primer, journal fallback)
    [4] IsTor dikonfirmasi? (check.torproject.org/api/ip)
        ↓
  configure_dns        (kunci resolv.conf ke 127.0.0.1)
        ↓
  apply_killswitch     (OUTPUT → DROP)
        ↓
  save_state
```

Jika langkah 3 gagal pada profil transparent, Ghostly otomatis turun ke mode SOCKS-only dan menjalankan ulang rantai verifikasi sebelum menyerah.

### Arsitektur torrc

Ghostly tidak pernah menulis direktif runtime ke `/etc/tor/torrc`. Semua konfigurasi diisolasi di `/etc/tor/torrc.d/ghostly.conf`.

```
/etc/tor/torrc              ← bootstrap minimal (include saja)
/etc/tor/torrc.d/
    ghostly.conf            ← semua konfigurasi runtime (dikelola Ghostly)
```

Saat pertama kali dijalankan, jika `/etc/tor/torrc` mengandung direktif yang konflik (misal `SocksPort`, `ControlPort`, `TransPort`), Ghostly akan membersihkannya secara otomatis dan membackup file asli ke `/var/lib/ghostly/torrc.original.bak`.

Untuk membersihkan torrc secara manual:

```bash
sudo ghostly fix-torrc
sudo ghostly diag
```

### Aturan firewall (mode transparent)

```
INPUT   → DROP (default)
FORWARD → DROP (default)
OUTPUT  → ACCEPT → DROP setelah kill-switch aktif

NAT OUTPUT:
  127.0.0.0/8        → RETURN  (bypass loopback)
  uid daemon tor     → RETURN  (Tor sendiri bypass redirect)
  rentang LAN        → RETURN  (kecuali strict mode)
  TCP --syn          → REDIRECT → :9040 (TransPort)
  UDP/TCP port 53    → REDIRECT → :5353 (DNSPort)
```

---

## Lokasi File

| Path | Fungsi |
|---|---|
| `/etc/tor/torrc.d/ghostly.conf` | Konfigurasi Tor runtime |
| `/etc/tor/torrc` | Bootstrap minimal (include saja) |
| `/var/lib/ghostly/state` | State sesi aktif |
| `/var/lib/ghostly/iptables.bak` | Backup firewall (dipulihkan saat `off`) |
| `/var/lib/ghostly/resolv.conf.bak` | Backup DNS (dipulihkan saat `off`) |
| `/var/lib/ghostly/torrc.original.bak` | torrc asli sebelum sanitasi |
| `/var/log/ghostly.log` | Log operasi |
| `/run/tor/control.authcookie` | Cookie control port Tor |

---

## Variabel Environment

| Variabel | Default | Keterangan |
|---|---|---|
| `GHOSTLY_MODE` | `balanced` | Mode privasi (`strict` / `balanced` / `safe`) |

---

## Port

| Port | Fungsi |
|---|---|
| `9050` | Proxy SOCKS5 Tor |
| `9040` | TransPort Tor (redirect TCP transparent) |
| `5353` | DNSPort Tor (redirect DNS) |
| `9051` | Control port Tor |

---

## Pemecahan Masalah

**Tor gagal start — "Address already in use"**

File `/etc/tor/torrc` kemungkinan memiliki direktif port yang konflik dari instalasi Tor sebelumnya.

```bash
sudo ghostly fix-torrc
sudo ghostly diag
```

**Bootstrap timeout**

```bash
sudo ghostly diag     # menampilkan % bootstrap live dan log Tor terbaru
sudo ghostly rotate   # minta sirkuit baru
```

**SSH terputus setelah mengaktifkan strict mode di server cloud**

Strict mode merutekan semua traffic termasuk koneksi SSH melalui Tor. Aktifkan kembali melalui konsol VPS dan ganti ke mode `balanced`:

```bash
sudo ghostly off
sudo ghostly on --mode balanced
```

**WSL: proxy tidak berjalan setelah diaktifkan**

WSL tidak dapat memodifikasi kernel networking. Terapkan proxy ke shell secara manual:

```bash
eval "$(ghostly env)"
curl https://check.torproject.org/api/ip
```

**Verifikasi Tor aktif**

```bash
sudo ghostly status
sudo ghostly leak-test
```

---

## Catatan Keamanan

- Ghostly menggunakan **cookie authentication** untuk control port Tor. Tidak ada password plaintext yang disimpan.
- Kill-switch mengset `iptables OUTPUT DROP` setelah Tor dikonfirmasi. Jika Tor crash setelah aktivasi, semua traffic keluar diblokir sampai `sudo ghostly off` dijalankan.
- Spoofing MAC hanya berlaku pada interface default. Dilewati pada profil VM, cloud, WSL, dan container karena tidak berpengaruh atau tidak tersedia.
- Pada profil cloud, IPv6 sengaja dibiarkan aktif — penyedia cloud sering menggunakan IPv6 untuk akses management plane. Pastikan traffic IPv6 tidak membocorkan data sensitif jika ini menjadi perhatian.
- `strict` mode menonaktifkan pengecualian LAN. Semua traffic termasuk LAN, SSH, dan antarmuka manajemen dialihkan melalui Tor.

---

## Lisensi

MIT — lihat [LICENSE](LICENSE)
