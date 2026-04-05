# Microsoft Azure VPN Server Setup

Set up your own WireGuard, OpenVPN, or SSH SOCKS5 server on an Azure Virtual Machine, then connect to it with PrivateCrossVPN.

> This guide is written with **Azure for Students** subscription in mind. It works with any Azure subscription.

---

## Table of Contents

1. [Create a Virtual Machine (Portal)](#1-create-a-virtual-machine-portal)
2. [Configure Network Security Group (NSG)](#2-configure-network-security-group-nsg)
3. [Connect to Your Server](#3-connect-to-your-server)
4. [Option A: WireGuard Server](#4a-wireguard-server)
5. [Option B: OpenVPN Server](#4b-openvpn-server)
6. [Option C: SSH SOCKS5 (No Extra Software)](#4c-ssh-socks5)
7. [Connect with PrivateCrossVPN](#5-connect-with-privatecrossvpn)
8. [Cost & Optimization](#6-cost--optimization)

---

## 1. Create a Virtual Machine (Portal)

Log in at [portal.azure.com](https://portal.azure.com).

Click **Create a resource** → **Virtual machine** → **Azure virtual machine**.

### Basics tab

#### Project details

| Setting | Value |
|---|---|
| **Subscription** | `Azure for Students` (or your subscription) |
| **Resource group** | Click "Create new" → name it `vpn-rg` |

#### Instance details

| Setting | Value | Notes |
|---|---|---|
| **Virtual machine name** | `vpn-server` | Any name you like |
| **Region** | `(Europe) North Europe` | Pick the region you want to appear from |
| **Availability options** | `Availability zone` | Default is fine |
| **Availability zone** | `Zone 1` | Default |
| **Security type** | `Trusted launch virtual machines` | Default |
| **Image** | `Ubuntu Server 24.04 LTS - x64 Gen2` | Select from the list |
| **VM architecture** | `x64` | **Not** Arm64 |
| **Size** | **Standard_B1s** (1 vCPU, 1 GB) | Click "See all sizes", search for `B1s`. This is the cheapest option and more than enough for a personal VPN |

> **Azure for Students** gives you $100 credit. With B1s, that lasts ~13 months.

#### Administrator account

| Setting | Value |
|---|---|
| **Authentication type** | `SSH public key` (recommended) |
| **Username** | `azureuser` (default, keep it) |
| **SSH public key source** | `Generate new key pair` |
| **SSH Key Type** | `Ed25519 SSH Format` (recommended — shorter, secure) or `RSA SSH Format` |
| **Key pair name** | `vpn-server-key` |

> If you already have an SSH key, select "Use existing key" and paste your public key.

#### Inbound port rules

| Setting | Value |
|---|---|
| **Public inbound ports** | `Allow selected ports` |
| **Select inbound ports** | `SSH (22)` |

> You'll see a warning: "This will allow all IP addresses to access your virtual machine." This is acceptable for initial setup. You can restrict source IPs later via NSG.

### Disks tab

| Setting | Value |
|---|---|
| **OS disk type** | `Standard SSD` (cheapest) or `Premium SSD` (faster) |
| **Size** | 30 GB (default, sufficient) |

Leave other settings as default.

### Networking tab

| Setting | Value |
|---|---|
| **Virtual network** | `(New) vpn-server-vnet` (auto-created) |
| **Subnet** | `default` (auto-created) |
| **Public IP** | `(New) vpn-server-ip` (auto-created) |
| **NIC network security group** | `Basic` |

Accept the defaults. A public IP is automatically assigned.

### Management tab

| Setting | Value |
|---|---|
| **Auto-shutdown** | `Enable` — saves money when you're not using the VPN |
| **Shutdown time** | e.g., `02:00 AM` |
| **Time zone** | Your local timezone |

### Monitoring, Advanced, Tags tabs

Leave defaults. No changes needed.

### Review + create

1. Click the **Review + create** tab
2. Review the summary (especially Size and Region)
3. Click **Create**
4. Click **"Download private key and create resource"**
5. A `.pem` file will download — **do not lose this file**, it's required to connect to your server

> Creation takes 1-2 minutes. When complete, click **"Go to resource"** and note the **Public IP address**.

---

## 2. Configure Network Security Group (NSG)

SSH (22) is already open. You need to open additional ports for your VPN protocol.

### Via Portal

1. Go to your VM page → **Networking** → **Network settings** in the left menu
2. Click **Add inbound port rule**

### WireGuard rule

| Setting | Value |
|---|---|
| Source | `Any` |
| Source port ranges | `*` |
| Destination | `Any` |
| Service | `Custom` |
| Destination port ranges | `51820` |
| Protocol | `UDP` |
| Action | `Allow` |
| Priority | `1001` |
| Name | `AllowWireGuard` |

### OpenVPN rule

| Setting | Value |
|---|---|
| Destination port ranges | `1194` |
| Protocol | `UDP` |
| Name | `AllowOpenVPN` |
| *(other fields same as above)* | |

### Via CLI (alternative)

```bash
# WireGuard
az network nsg rule create \
    --resource-group vpn-rg \
    --nsg-name vpn-serverNSG \
    --name AllowWireGuard \
    --priority 1001 \
    --destination-port-ranges 51820 \
    --protocol Udp \
    --access Allow

# OpenVPN
az network nsg rule create \
    --resource-group vpn-rg \
    --nsg-name vpn-serverNSG \
    --name AllowOpenVPN \
    --priority 1002 \
    --destination-port-ranges 1194 \
    --protocol Udp \
    --access Allow
```

---

## 3. Connect to Your Server

Use the downloaded `.pem` file to SSH into your VM:

```bash
# Set permissions on the .pem file (required)
chmod 400 ~/Downloads/vpn-server-key.pem

# Connect
ssh -i ~/Downloads/vpn-server-key.pem azureuser@YOUR_VM_PUBLIC_IP
```

Update the system:

```bash
sudo apt update && sudo apt upgrade -y
```

---

## 4a. WireGuard Server

### Install

```bash
sudo apt install wireguard -y
```

### Generate Keys

```bash
cd /etc/wireguard
sudo bash -c 'umask 077; wg genkey | tee server_private.key | wg pubkey > server_public.key'
sudo bash -c 'umask 077; wg genkey | tee client_private.key | wg pubkey > client_public.key'
```

Read the keys (you'll need them for PrivateCrossVPN):

```bash
sudo cat server_public.key    # This goes into "Peer Public Key"
sudo cat client_private.key   # This goes into "Private Key"
```

### Server Config

Create `/etc/wireguard/wg0.conf`:

```bash
sudo nano /etc/wireguard/wg0.conf
```

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

> **Note**: Some Azure VMs use a different network interface name. Verify with `ip route show default` and replace `eth0` if different.

### Enable IP Forwarding

On the VM:

```bash
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Also enable in Azure** (critical step!):

1. VM page → **Networking** → click on the network interface name
2. Left menu → **IP configurations**
3. **Enable IP forwarding** → set to `Enabled` → **Save**

Or via CLI:

```bash
az network nic update \
    --resource-group vpn-rg \
    --name vpn-serverVMNic \
    --ip-forwarding true
```

### Start WireGuard

```bash
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
sudo wg show  # Verify
```

### PrivateCrossVPN Profile

| Field | Value |
|---|---|
| Profile Name | `azure-northeurope` |
| Private Key | Contents of `client_private.key` |
| Address | `10.0.0.2/24` |
| DNS | `1.1.1.1` |
| Peer Public Key | Contents of `server_public.key` |
| Endpoint | `YOUR_VM_PUBLIC_IP:51820` |
| Allowed IPs | `0.0.0.0/0, ::/0` |
| Keepalive | `25` |

---

## 4b. OpenVPN Server

### Quick Install

```bash
curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
chmod +x openvpn-install.sh
sudo ./openvpn-install.sh
```

Follow the prompts (defaults are fine):

- **IP address**: auto-detected
- **Protocol**: UDP
- **Port**: 1194
- **DNS**: 1.1.1.1 (Cloudflare)
- **Client name**: `privatecrossvpn`

The script generates `/root/privatecrossvpn.ovpn`.

### Download the Config

```bash
# On the server: copy to an accessible location
sudo cp /root/privatecrossvpn.ovpn /home/azureuser/
sudo chown azureuser /home/azureuser/privatecrossvpn.ovpn

# On your local machine: download
scp -i ~/Downloads/vpn-server-key.pem azureuser@YOUR_VM_PUBLIC_IP:/home/azureuser/privatecrossvpn.ovpn .
```

### Connect

In PrivateCrossVPN, click **Import from File...** and select the downloaded `.ovpn` file. A profile is automatically created.

---

## 4c. SSH SOCKS5

The simplest option — no VPN software to install on the server. SSH is already running.

### (Optional) Harden SSH

```bash
sudo nano /etc/ssh/sshd_config
```

```
PasswordAuthentication no
PermitRootLogin prohibit-password
```

```bash
sudo systemctl restart sshd
```

### PrivateCrossVPN Profile

| Field | Value |
|---|---|
| Profile Name | `azure-ssh` |
| SSH Host | `YOUR_VM_PUBLIC_IP` |
| SSH Port | `22` |
| SSH User | `azureuser` |
| SOCKS5 Port | `1080` |
| SSH Key | Browse to the `.pem` file downloaded from Azure |

After connecting, configure your browser to use SOCKS5 proxy at `127.0.0.1:1080`.

---

## 5. Connect with PrivateCrossVPN

```bash
sudo -E python3 privatecrossvpn.py
```

1. Select your Azure profile from the dropdown
2. (Optional) Enable **Kill-Switch**
3. Click **Connect**
4. The Status card should display your Azure VM's IP and region

---

## 6. Cost & Optimization

### VM Pricing

| Size | vCPU | RAM | Monthly Cost |
|---|---|---|---|
| Standard_B1ls | 1 | 0.5 GB | ~$3.80 |
| **Standard_B1s** | 1 | 1 GB | ~$7.59 |
| Standard_B2s | 2 | 4 GB | ~$30.37 |
| Standard_D2s_v3 | 2 | 8 GB | ~$78.11 (default — **don't pick this**) |

> For a personal VPN, **B1s** is more than enough. D-series is overkill.

### Azure for Students

- **$100 credit** (valid for 12 months)
- **No credit card** required
- B1s with $100 credit lasts ~13 months
- Some services (including B1s) are free for 12 months (750 hours/month)

### Cost-Saving Tips

**Auto-shutdown** (most effective):

- Enable during VM creation in the Management tab
- Or: VM → **Auto-shutdown** → set a time (e.g., 2:00 AM)
- Manually start the VM when you need it

**Deallocate when idle**:

- Stopping a VM from the portal is not enough — you must **deallocate** to stop compute charges
- Disk charges continue (~$1.50/month for 30 GB Standard SSD)

```bash
# Deallocate (compute charges stop)
az vm deallocate --resource-group vpn-rg --name vpn-server

# Start again
az vm start --resource-group vpn-rg --name vpn-server
```

> **Warning**: When you deallocate and restart, the public IP may change. Assign a **Static IP** to prevent this.

### Assign Static IP

Portal: Go to your **Public IP** resource → **Configuration** → Assignment: `Static` → **Save**

```bash
az network public-ip update \
    --resource-group vpn-rg \
    --name vpn-serverPublicIP \
    --allocation-method Static
```

### Data Transfer

| Direction | Cost |
|---|---|
| Inbound | Free |
| Outbound | First 100 GB/month free, then ~$0.087/GB |

---

## Tips

- **DNS label**: Assign a DNS name to your public IP so you don't have to hardcode IPs
  - Portal → Public IP → **Configuration** → DNS name label: `myvpn`
  - Result: `myvpn.northeurope.cloudapp.azure.com`
  - Use this as the Endpoint in your PrivateCrossVPN profile

- **Multiple regions**: Create VMs in different regions and save a profile for each
  - `North Europe` (Dublin), `West Europe` (Amsterdam), `East US`, `Southeast Asia` (Singapore)

- **Regular updates**: Run `sudo apt update && sudo apt upgrade -y` monthly

- **Clean up completely**: When you're done, delete the entire resource group to avoid residual charges:

  ```bash
  az group delete --name vpn-rg --yes --no-wait
  ```

  This deletes the VM, disk, IP, NSG, and VNet — no more charges.
