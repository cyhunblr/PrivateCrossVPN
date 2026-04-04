# Microsoft Azure VPN Server Setup

Set up your own WireGuard or OpenVPN server on an Azure Virtual Machine, then connect to it with PrivateCrossVPN.

---

## Table of Contents

1. [Create an Azure VM](#1-create-an-azure-vm)
2. [Configure Network Security Group](#2-configure-network-security-group)
3. [Initial Server Setup](#3-initial-server-setup)
4. [Option A: WireGuard Server](#4a-wireguard-server)
5. [Option B: OpenVPN Server](#4b-openvpn-server)
6. [Option C: SSH SOCKS5](#4c-ssh-socks5)
7. [Connect with PrivateCrossVPN](#5-connect-with-privatecrossvpn)
8. [Cost Estimate & Optimization](#6-cost-estimate--optimization)

---

## 1. Create an Azure VM

### Via Azure Portal

1. Log in at [portal.azure.com](https://portal.azure.com)
2. Click **Create a resource** -> **Virtual Machine**
3. Configure:

| Setting | Recommended Value |
|---|---|
| Subscription | Your subscription |
| Resource Group | Create new: `vpn-rg` |
| VM Name | `vpn-server` |
| Region | Choose your desired exit location (e.g., `West Europe`, `East US`, `Southeast Asia`) |
| Image | **Ubuntu Server 22.04 LTS - x64 Gen2** |
| Size | **Standard_B1s** (1 vCPU, 1 GB RAM) — cheapest option, sufficient for personal VPN |
| Authentication | **SSH public key** |
| SSH Key Source | Generate new or use existing |
| Inbound ports | Allow SSH (22) |

4. **Disks**: Standard SSD, 30 GB (default is fine)
5. **Networking**: Leave defaults (a new VNet, subnet, public IP, and NSG will be created)
6. Click **Review + create** -> **Create**
7. **Download the private key** (.pem file) when prompted

### Via Azure CLI

```bash
# Login
az login

# Create resource group
az group create --name vpn-rg --location westeurope

# Create VM
az vm create \
    --resource-group vpn-rg \
    --name vpn-server \
    --image Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest \
    --size Standard_B1s \
    --admin-username azureuser \
    --generate-ssh-keys \
    --public-ip-sku Standard

# Note the publicIpAddress in the output
```

---

## 2. Configure Network Security Group

Azure's NSG acts as a firewall. You need to open ports for your VPN protocol.

### Via Portal

1. Go to your VM -> **Networking** -> **Network Security Group**
2. Click **Add inbound port rule**

### Required Rules

| Protocol | Port | Purpose |
|---|---|---|
| TCP | 22 | SSH access (already open) |
| UDP | 51820 | WireGuard (if using WireGuard) |
| UDP | 1194 | OpenVPN (if using OpenVPN) |

### Via CLI

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

## 3. Initial Server Setup

SSH into your VM:

```bash
# If you downloaded the .pem from Azure Portal
chmod 400 ~/Downloads/vpn-server_key.pem
ssh -i ~/Downloads/vpn-server_key.pem azureuser@YOUR_VM_PUBLIC_IP

# If you used az vm create with --generate-ssh-keys
ssh azureuser@YOUR_VM_PUBLIC_IP
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

### Server Config

Create `/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <server_private.key contents>
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <client_public.key contents>
AllowedIPs = 10.0.0.2/32
```

> **Note**: On some Azure VMs the network interface is named `eth0`. Verify with `ip route show default` and replace if different.

### Enable IP Forwarding

```bash
# On the VM
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Also enable in Azure** (important!):

1. Portal -> VM -> **Networking** -> Click the network interface
2. **IP configurations** -> **Enable IP forwarding** -> Save

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
| Profile Name | `azure-westeurope` |
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

Follow prompts (defaults are fine). The script generates `/root/client.ovpn`.

### Download Config

```bash
# From your local machine
scp -i ~/Downloads/vpn-server_key.pem azureuser@YOUR_VM_PUBLIC_IP:/home/azureuser/client.ovpn .

# You may need to copy it first on the server:
# sudo cp /root/client.ovpn /home/azureuser/ && sudo chown azureuser /home/azureuser/client.ovpn
```

### Connect

Import the `.ovpn` file in PrivateCrossVPN via **Import from File...**.

---

## 4c. SSH SOCKS5

No server-side setup needed beyond what Azure already provides.

### PrivateCrossVPN Profile

| Field | Value |
|---|---|
| Profile Name | `azure-ssh` |
| SSH Host | `YOUR_VM_PUBLIC_IP` |
| SSH Port | `22` |
| SSH User | `azureuser` |
| SOCKS5 Port | `1080` |
| SSH Key | Browse to the `.pem` file downloaded from Azure |

---

## 5. Connect with PrivateCrossVPN

```bash
sudo -E python3 privatecrossvpn.py
```

1. Select your Azure profile from the dropdown
2. Enable **Kill-Switch** if desired
3. Click **Connect**
4. The Status card should display your Azure VM's IP and region

---

## 6. Cost Estimate & Optimization

### VM Pricing (Pay-as-you-go)

| Size | vCPU | RAM | Approx. Cost |
|---|---|---|---|
| **Standard_B1s** | 1 | 1 GB | ~$7.59/month |
| Standard_B1ls | 1 | 0.5 GB | ~$3.80/month |
| Standard_B2s | 2 | 4 GB | ~$30.37/month |

### Cost Optimization Tips

- **Azure Free Account**: New accounts get $200 credit for 30 days + 12 months of B1s free (750 hrs/month).
- **Reserved Instances**: 1-year reservation on B1s reduces cost to ~$4.53/month (40% savings).
- **Auto-shutdown**: Set auto-shutdown in the VM settings if you only need VPN during certain hours.
  - Portal -> VM -> **Auto-shutdown** -> Enable, set time
- **Spot VMs**: For non-critical/temporary use, Spot VMs can be 60-90% cheaper (but may be evicted).
- **Deallocate when idle**: Stop (deallocate) the VM when not in use. You pay $0 for compute but keep the disk (~$1.50/month for 30 GB).

```bash
# Deallocate
az vm deallocate --resource-group vpn-rg --name vpn-server

# Start
az vm start --resource-group vpn-rg --name vpn-server
```

> **Important**: When you deallocate and restart, the public IP may change unless you assigned a **Static** public IP.

### Assign Static IP

```bash
az network public-ip update \
    --resource-group vpn-rg \
    --name vpn-serverPublicIP \
    --allocation-method Static
```

### Data Transfer

- **Outbound**: First 100 GB/month free, then ~$0.087/GB (varies by region)
- **Inbound**: Free

---

## Tips

- **Multiple Regions**: Azure has 60+ regions worldwide. Create VMs in different regions for geo-flexibility.
- **DNS Name**: Assign a DNS label to your public IP (e.g., `myvpn.westeurope.cloudapp.azure.com`) to avoid hardcoding IPs.
  - Portal -> Public IP -> **Configuration** -> DNS name label
- **Update regularly**: `sudo apt update && sudo apt upgrade -y` and reboot monthly.
- **Monitoring**: Enable Azure Monitor and set alerts for high bandwidth usage.
- **Delete everything when done**: Delete the entire resource group to avoid residual charges:
  ```bash
  az group delete --name vpn-rg --yes --no-wait
  ```
