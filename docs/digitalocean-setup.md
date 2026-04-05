# DigitalOcean VPN Server Setup

Set up your own WireGuard or OpenVPN server on a DigitalOcean Droplet, then connect to it with PrivateCrossVPN.

---

## Table of Contents

1. [Create a Droplet](#1-create-a-droplet)
2. [Initial Server Setup](#2-initial-server-setup)
3. [Option A: WireGuard Server](#3a-wireguard-server)
4. [Option B: OpenVPN Server](#3b-openvpn-server)
5. [Option C: SSH SOCKS5 (No Extra Software)](#3c-ssh-socks5)
6. [Connect with PrivateCrossVPN](#4-connect-with-privatecrossvpn)
7. [Cost Estimate](#5-cost-estimate)

---

## 1. Create a Droplet

1. Sign up / log in at [cloud.digitalocean.com](https://cloud.digitalocean.com)
2. Click **Create** -> **Droplets**
3. Configure:

| Setting | Recommended Value |
|---|---|
| Region | Choose the location closest to you, or the region you want to appear from (e.g., Frankfurt, NYC, Singapore) |
| Image | **Ubuntu 22.04 LTS** |
| Size | **Basic** -> **Regular** -> **$6/mo** (1 vCPU, 1 GB RAM, 25 GB SSD) — more than enough for a personal VPN |
| Authentication | **SSH Key** (recommended) or Password |
| Hostname | `vpn-server` (or anything you like) |

1. Click **Create Droplet**
2. Note the **public IPv4 address** (e.g., `164.90.xxx.xxx`)

### SSH Key Setup (before creating the Droplet)

You need an SSH key pair to securely access your server. The **private key** stays on your local machine, the **public key** goes to DigitalOcean.

#### Option A: Use an existing key

Check if you already have a key:

```bash
ls ~/.ssh/*.pub
```

Common key files: `id_ed25519`, `id_rsa`, `id_ecdsa`. If any `.pub` file is listed, you already have a key. Print it:

```bash
# Replace with your actual key name
cat ~/.ssh/id_rsa.pub
```

Skip to Step 3 below.

> **Tip**: PrivateCrossVPN's **Setup** wizard (in the app) auto-detects existing keys. You can also browse for any key file via "Use Existing Key".

#### Option B: Generate a new key

Choose any name you like (examples: `id_ed25519`, `do_vpn`, `myserver`):

**Linux / macOS:**

```bash
ssh-keygen -t ed25519 -C "my-vpn" -f ~/.ssh/id_ed25519
```

**Windows 11 (PowerShell):**

```powershell
ssh-keygen -t ed25519 -C "my-vpn" -f $env:USERPROFILE\.ssh\id_ed25519
```

- Press Enter when asked for a passphrase (or set one for extra security)
- Two files are created:
  - `~/.ssh/id_ed25519` — private key (keep secret, never share)
  - `~/.ssh/id_ed25519.pub` — public key (this goes to DigitalOcean)

> **Note**: You can use any filename, not just `id_ed25519`. Just remember the name — you'll need to point PrivateCrossVPN to the private key file.

#### Step 3: Copy the public key

```bash
# Replace with your key name
cat ~/.ssh/id_ed25519.pub
```

```powershell
# Windows
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub
```

Copy the entire output (starts with `ssh-ed25519 ...` or `ssh-rsa ...`).

#### Step 4: Add the key to DigitalOcean

1. Go to [cloud.digitalocean.com/account/security](https://cloud.digitalocean.com/account/security)
2. Scroll to **SSH Keys** → click **Add SSH Key**
3. Paste the public key content into the box
4. Give it a name (e.g., `my-laptop`)
5. Click **Add SSH Key**

Now when creating a Droplet, select this key under **Authentication → SSH Key**.

---

## 2. Initial Server Setup

SSH into your new droplet:

```bash
ssh -i ~/.ssh/vpn_key root@YOUR_DROPLET_IP
```

Run basic hardening:

```bash
# Update system
apt update && apt upgrade -y

# Enable firewall
ufw allow OpenSSH
ufw enable

# (Optional) Create a non-root user
adduser vpnuser
usermod -aG sudo vpnuser
```

---

## 3a. WireGuard Server

### Install WireGuard

```bash
apt install wireguard -y
```

### Generate Server Keys

```bash
cd /etc/wireguard
umask 077

wg genkey | tee server_private.key | wg pubkey > server_public.key
```

### Generate Client Keys

```bash
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

### Server Config

Create `/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <contents of server_private.key>
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <contents of client_public.key>
AllowedIPs = 10.0.0.2/32
```

### Enable IP Forwarding

```bash
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p
```

### Open Firewall Port

```bash
ufw allow 51820/udp
```

### Start WireGuard

```bash
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Verify
wg show
```

### PrivateCrossVPN Profile

In PrivateCrossVPN, create a **WireGuard** profile:

| Field | Value |
|---|---|
| Profile Name | `do-frankfurt` (or your region) |
| Private Key | Contents of `client_private.key` |
| Address | `10.0.0.2/24` |
| DNS | `1.1.1.1` |
| Peer Public Key | Contents of `server_public.key` |
| Endpoint | `YOUR_DROPLET_IP:51820` |
| Allowed IPs | `0.0.0.0/0, ::/0` |
| Keepalive | `25` |

Click **Save Profile**, then **Connect**.

---

## 3b. OpenVPN Server

The fastest way to get OpenVPN running on a fresh server:

### Quick Install Script

```bash
# Download and run the official install script
curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
chmod +x openvpn-install.sh
./openvpn-install.sh
```

Follow the interactive prompts:

- **IP address**: auto-detected (your Droplet IP)
- **Protocol**: UDP (recommended)
- **Port**: 1194 (default)
- **DNS**: 1.1.1.1 (Cloudflare) or your choice
- **Client name**: `privatecrossvpn`

The script generates a `.ovpn` file at `/root/privatecrossvpn.ovpn`.

### Download the Config

```bash
# From your local machine
scp -i ~/.ssh/vpn_key root@YOUR_DROPLET_IP:/root/privatecrossvpn.ovpn .
```

### Open Firewall Port

```bash
ufw allow 1194/udp
```

### Connect with PrivateCrossVPN

In the app, click **Import from File...** and select the downloaded `.ovpn` file. Or manually fill in the OpenVPN tab fields if you prefer.

---

## 3c. SSH SOCKS5 (No Extra Software)

This is the simplest option — no VPN software to install on the server. SSH is already running.

### (Optional) Harden SSH

Edit `/etc/ssh/sshd_config`:

```
PasswordAuthentication no
PermitRootLogin prohibit-password
```

```bash
systemctl restart sshd
```

### PrivateCrossVPN Profile

In the app, select **SSH SOCKS5** and create a profile:

| Field | Value |
|---|---|
| Profile Name | `do-ssh` |
| SSH Host | `YOUR_DROPLET_IP` |
| SSH Port | `22` |
| SSH User | `root` (or `vpnuser` if you created one) |
| SOCKS5 Port | `1080` |
| SSH Key | Browse to `~/.ssh/vpn_key` (rename to `.pem` if needed) |

Click **Save Profile**, then **Connect**. Configure your browser to use SOCKS5 proxy at `127.0.0.1:1080`.

---

## 4. Connect with PrivateCrossVPN

```bash
sudo -E python3 privatecrossvpn.py
```

1. Select your saved profile from the dropdown
2. (Optional) Enable **Kill-Switch**
3. Click **Connect**
4. Verify: the Status card should show your Droplet's IP and location

---

## 5. Cost Estimate

| Resource | Cost |
|---|---|
| Droplet (Basic, 1 vCPU, 1 GB) | **$6/month** |
| Bandwidth (1 TB included) | $0 (included) |
| Additional bandwidth | $0.01/GB |

For a personal VPN, the $6/mo droplet is more than sufficient. DigitalOcean also offers $4/mo droplets (512 MB RAM) that work fine for WireGuard and SSH tunneling.

---

## Tips

- **Snapshots**: Take a DigitalOcean snapshot of your configured droplet. If you break something, you can restore in seconds.
- **Floating IPs**: Assign a Reserved IP to your droplet so the IP doesn't change if you rebuild it.
- **Multiple Regions**: Create droplets in different regions (NYC, London, Singapore) and save a profile for each in PrivateCrossVPN.
- **Destroy when idle**: If you only need a VPN occasionally, destroy the droplet when not in use and recreate from a snapshot. You only pay for uptime.
- **Monitoring**: Enable DigitalOcean monitoring to track bandwidth usage from the dashboard.
