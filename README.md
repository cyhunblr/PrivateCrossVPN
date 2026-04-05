<p align="center" style="margin-bottom: 0;">
  <img src="img/logo.png" alt="PrivateCrossVPN" width="400">
</p>

<p align="center" style="margin-top: 6px;">
  <span style="font-size: 42px; font-weight: 800; color: #ffffff; letter-spacing: 0.5px;">PrivateCrossVPN</span><br>
  <strong>Production-ready VPN client manager for self-hosted infrastructure</strong><br>
</p>

<p align="center">
  <a href="https://github.com/cyhunblr/PrivateCrossVPN/actions/workflows/ci.yml"><img src="https://github.com/cyhunblr/PrivateCrossVPN/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/cyhunblr/PrivateCrossVPN/actions/workflows/release.yml"><img src="https://github.com/cyhunblr/PrivateCrossVPN/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="https://github.com/cyhunblr/PrivateCrossVPN/releases"><img src="https://img.shields.io/github/v/release/cyhunblr/PrivateCrossVPN?sort=semver" alt="Latest Release"></a>
  <a href="https://github.com/cyhunblr/PrivateCrossVPN/blob/main/LICENSE"><img src="https://img.shields.io/github/license/cyhunblr/PrivateCrossVPN" alt="License"></a>
</p>

---

PrivateCrossVPN is a desktop control plane for your own VPN endpoints. It provides one interface to configure and operate WireGuard, OpenVPN, and SSH SOCKS5 tunnels with operational safety features built in.

Core product goals:

- Reliable connection lifecycle management for daily use.
- Security-first traffic control via kill-switch logic.
- Practical profile management for multiple servers and protocols.
- Reproducible release artifacts from CI/CD.

Releases are produced automatically from `main` and published with prebuilt artifacts.

---

## Features

| Feature | Description |
|---|---|
| **WireGuard** | Connects via `wg-quick` (Linux) / `wireguard.exe /installtunnelservice` (Windows) |
| **OpenVPN** | Launches the official `openvpn` binary with `.ovpn` configs |
| **SSH SOCKS5** | Creates a local SOCKS5 proxy via `ssh -D` — no full tunnel needed |
| **Kill-Switch** | Blocks all non-VPN traffic using `iptables` (Linux) / `netsh advfirewall` (Windows) |
| **Auto-Reconnect** | Monitors tunnel health and restores dropped connections (exponential back-off, 5 retries) |
| **Config Editor** | Built-in forms for each protocol — fill in fields, save, and connect. No manual file editing |
| **Profile Manager** | Save, load, switch, and delete profiles. Last-used profile is remembered across sessions |
| **IP Monitor** | Real-time public IP, location, ISP, and timezone via ipinfo.io |
| **Configurable Storage** | Default config directory: `~/.privatecrossvpn/configs/` — changeable from the UI |
| **Cross-Platform** | Single codebase for Windows 11 and Linux |

---

## Screenshots

```
+---------------------------+------------------------------------------+
|  PrivateCrossVPN v1.2.0   |  Status & Location                       |
|                           |  ● Connected          Uptime: 00:14:32   |
|  Saved Profiles           |  IP: 185.xxx.xxx.xx   Kill-Switch: ON    |
|  [my-wireguard     ][X]  |  Location: Frankfurt, Hesse, DE           |
|                           |  ISP: DigitalOcean LLC                   |
|  Protocol                 |                                          |
|  [WireGuard         v]   |  +--------------------------------------+ |
|                           |  | WireGuard | OpenVPN | SSH SOCKS5    | |
|  [Import from File...]    |  | Profile Name: [my-wireguard       ] | |
|                           |  | Private Key:  [*********************] | |
|  [x] Kill-Switch          |  | Address:      [10.0.0.2/24         ] | |
|                           |  | DNS:          [1.1.1.1             ] | |
|  Configs Folder           |  | Peer Key:     [abc123...           ] | |
|  ~/.privatecrossvpn/...   |  | Endpoint:     [vpn.example.com:518 ] | |
|  [Change...]              |  | Allowed IPs:  [0.0.0.0/0, ::/0    ] | |
|                           |  |          [Save Profile]               | |
|  Theme                    |  +--------------------------------------+ |
|  [Dark               v]  |                                          |
|                           |  Activity Log                    [Clear] |
|  [      Connect      ]   |  2026-04-04 17:05:02 [INFO] WireGuard.. |
|  [    Disconnect      ]   |  2026-04-04 17:05:03 [INFO] Connected.  |
+---------------------------+------------------------------------------+
```

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Python dependency footprint is intentionally small (`customtkinter`). Protocol binaries (WireGuard, OpenVPN, SSH) are installed at OS level.

### 2. Run

```bash
# Linux
python3 privatecrossvpn.py

# Windows (right-click terminal -> Run as Administrator)
python privatecrossvpn.py
```

On Linux, privileged operations (tunnel/firewall actions) request authentication at runtime when needed.

### 3. Create a Profile

1. Select a protocol from the sidebar (WireGuard / OpenVPN / SSH SOCKS5)
2. Fill in the fields in the config editor tab
3. Click **Save Profile**
4. Click **Connect**

Or import an existing `.conf` / `.ovpn` file via **Import from File...**.

## Commit Style

This repo uses Conventional Commits for clearer history and safer AI-generated commits:

- `feat: ...`
- `fix: ...`
- `refactor: ...`
- `chore: ...`
- `docs: ...`

When VS Code or Copilot suggests a commit message, keep it in this format instead of a generic summary.

To enable the local commit hook:

```bash
git config core.hooksPath .githooks
chmod +x .githooks/commit-msg
```

---

## System Requirements

### Platform

- **Linux**: x64 distro with compatible glibc for the selected release artifact (`ubuntu-20.04`, `ubuntu-22.04`, or `ubuntu-24.04` build)
- **Windows**: use the GitHub-hosted build artifact (`windows-latest`)

CI/CD note: CI runs on your self-hosted Linux x64 runner. Release builds publish a Linux matrix (`ubuntu-20.04` self-hosted, `ubuntu-22.04` and `ubuntu-24.04` GitHub-hosted) plus one Windows artifact (`windows-latest`).

### Release Artifacts

- `PrivateCrossVPN-linux-ubuntu-20.04`
- `PrivateCrossVPN-linux-ubuntu-22.04`
- `PrivateCrossVPN-linux-ubuntu-24.04`
- `PrivateCrossVPN-windows-latest.exe`

### Python

- Python **3.10+**
- `customtkinter >= 5.2.0`

### VPN Binaries

| Protocol | Linux | Windows |
|---|---|---|
| WireGuard | `sudo apt install wireguard` | [wireguard.com/install](https://www.wireguard.com/install/) |
| OpenVPN | `sudo apt install openvpn` | [openvpn.net/community-downloads](https://openvpn.net/community-downloads/) |
| SSH SOCKS5 | `ssh` (pre-installed) | OpenSSH (built into Windows 11) |

### Kill-Switch

- **Linux**: `iptables` (pre-installed on Ubuntu)
- **Windows**: `netsh` (built-in)

---

## Configuration

### File Locations

| Item | Path |
|---|---|
| App data directory | `~/.privatecrossvpn/` |
| Saved profiles & configs | `~/.privatecrossvpn/configs/` |
| Application settings | `~/.privatecrossvpn/settings.json` |

The configs directory can be changed from the sidebar ("Change..." button). The setting persists across sessions.

### Profile Format

Profiles are saved as JSON files in the configs directory. When you save a WireGuard or OpenVPN profile, the corresponding `.conf` / `.ovpn` file is auto-generated alongside the JSON.

```
~/.privatecrossvpn/configs/
  my-wireguard.json        # Profile metadata
  my-wireguard.conf        # Generated WireGuard config
  my-openvpn.json
  my-openvpn.ovpn          # Generated OpenVPN config
  my-ssh-tunnel.json       # SSH profile (no extra file needed)
```

---

## Protocols Guide

### WireGuard

Fill in the config editor:

| Field | Example | Description |
|---|---|---|
| Profile Name | `do-frankfurt` | Unique name for this profile |
| Private Key | `oK8Y3...` | Your WireGuard private key (`wg genkey`) |
| Address | `10.0.0.2/24` | Tunnel IP assigned to you |
| DNS | `1.1.1.1` | DNS server used while connected |
| Peer Public Key | `xTIB...` | Server's public key |
| Preshared Key | *(optional)* | Extra layer of symmetric encryption |
| Endpoint | `vpn.example.com:51820` | Server address and port |
| Allowed IPs | `0.0.0.0/0, ::/0` | Route all traffic through VPN |
| Keepalive | `25` | NAT keepalive interval in seconds |

### OpenVPN

Fill in the config editor:

| Field | Example | Description |
|---|---|---|
| Profile Name | `azure-vpn` | Unique name |
| Remote Server | `vpn.example.com` | OpenVPN server hostname/IP |
| Port | `1194` | Server port |
| Protocol | `udp` | `udp` or `tcp` |
| Device | `tun` | `tun` (routed) or `tap` (bridged) |
| Cipher | `AES-256-GCM` | Encryption cipher |
| Auth | `SHA256` | HMAC digest |
| CA Cert | *(paste PEM)* | Certificate Authority certificate |
| Extra directives | *(optional)* | Any additional OpenVPN directives |

You can also **Import from File** to use an existing `.ovpn`.

### SSH SOCKS5

A lightweight alternative — no VPN software needed on the client. Creates a local SOCKS5 proxy.

| Field | Example | Description |
|---|---|---|
| Profile Name | `my-ssh` | Unique name |
| SSH Host | `203.0.113.10` | Your SSH server |
| SSH Port | `22` | SSH port |
| SSH User | `root` | SSH username |
| SOCKS5 Port | `1080` | Local proxy port |
| SSH Key | `mykey.pem` | Private key file (optional) |

After connecting, configure your browser to use **SOCKS5 proxy** at `127.0.0.1:1080`.

**Browser Setup:**

- **Firefox**: Settings -> Network Settings -> Manual proxy -> SOCKS Host: `127.0.0.1`, Port: `1080`, SOCKS v5
- **Chrome**: Launch with `--proxy-server="socks5://127.0.0.1:1080"`
- **System-wide (Linux)**: `export ALL_PROXY=socks5://127.0.0.1:1080`

---

## Kill-Switch

When enabled, the kill-switch blocks **all** outbound traffic except:

- Traffic to the VPN server itself
- Loopback (127.0.0.0/8)
- LAN subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

This prevents data leaks if the VPN drops unexpectedly. The kill-switch is **automatically disabled** when you disconnect.

| OS | Implementation |
|---|---|
| Linux | Custom `iptables` chain (`PrivateCrossVPN_KillSwitch`) inserted into OUTPUT |
| Windows | `netsh advfirewall` outbound policy set to block, with whitelist rules |

---

## Auto-Reconnect

PrivateCrossVPN monitors tunnel health every **15 seconds**. If a drop is detected:

1. Waits **3 seconds**, then attempts reconnect
2. On failure, doubles the delay (6s, 12s, 24s, 48s)
3. Gives up after **5 consecutive failures**
4. UI shows the current state (Reconnecting / Error)

---

## Packaging

### Windows (.exe) — PyInstaller

```powershell
pip install pyinstaller

# Find customtkinter path
python -c "import customtkinter; print(customtkinter.__path__[0])"

# Build (replace the path below)
pyinstaller --noconfirm --onefile --windowed ^
    --name "PrivateCrossVPN" ^
    --add-data "C:\Python311\Lib\site-packages\customtkinter;customtkinter" ^
    privatecrossvpn.py
```

Output: `dist/PrivateCrossVPN.exe` — run as Administrator.

### Linux Binary — Nuitka

```bash
pip install nuitka ordered-set
sudo apt install patchelf ccache

python3 -m nuitka \
    --onefile \
    --enable-plugin=tk-inter \
    --include-package=customtkinter \
    --output-filename=PrivateCrossVPN \
    privatecrossvpn.py
```

Run with: `sudo ./PrivateCrossVPN`

### Linux Binary — PyInstaller (alternative)

```bash
pip install pyinstaller
CTK=$(python3 -c "import customtkinter; print(customtkinter.__path__[0])")

pyinstaller --noconfirm --onefile --windowed \
    --name "PrivateCrossVPN" \
    --add-data "${CTK}:customtkinter" \
    privatecrossvpn.py

sudo ./dist/PrivateCrossVPN
```

---

## Cloud VPN Server Setup

Step-by-step guides for setting up your own VPN server on popular cloud providers:

| Provider | Guide |
|---|---|
| DigitalOcean | [docs/digitalocean-setup.md](docs/digitalocean-setup.md) |
| Microsoft Azure | [docs/azure-setup.md](docs/azure-setup.md) |
| Namecheap / .tech Domain | [docs/namecheap-domain-setup.md](docs/namecheap-domain-setup.md) |

---

## Project Structure

```
PrivateCrossVPN/
├── privatecrossvpn.py            # Single-file application (~1100 lines)
├── requirements.txt              # Python dependencies
├── BUILD.md                      # Detailed packaging instructions
├── README.md                     # This file
└── docs/
    ├── digitalocean-setup.md     # DigitalOcean VPN server guide
    ├── azure-setup.md            # Microsoft Azure VPN server guide
    └── namecheap-domain-setup.md # Domain setup for your VPN
```

---

## Security Notes

- All subprocess calls use `shell=False` to prevent command injection
- Config files are stored in user-owned directories with default permissions
- Kill-switch rules are scoped and cleaned up on disconnect/exit
- No telemetry, no analytics, no external calls except `ipinfo.io` for IP display
- Private keys are stored in local JSON profiles — protect `~/.privatecrossvpn/` accordingly

---

## License

MIT
