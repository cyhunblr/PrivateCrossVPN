# Namecheap / .tech Domain Setup for Your VPN

Point a custom domain (e.g., `vpn.yourdomain.tech`) to your VPN server. This makes your server easier to remember, enables DNS-based failover, and looks more professional in your PrivateCrossVPN profiles.

---

## Table of Contents

1. [Why Use a Domain?](#1-why-use-a-domain)
2. [Register a Domain on Namecheap](#2-register-a-domain-on-namecheap)
3. [Configure DNS Records](#3-configure-dns-records)
4. [Using with PrivateCrossVPN](#4-using-with-privatecrossvpn)
5. [Advanced: Dynamic DNS](#5-advanced-dynamic-dns)
6. [Advanced: Multiple Server Regions](#6-advanced-multiple-server-regions)
7. [.tech Domain Notes](#7-tech-domain-notes)

---

## 1. Why Use a Domain?

| Benefit | Description |
|---|---|
| **Memorable** | `vpn.mysite.tech` is easier to remember than `164.90.234.17` |
| **Portable** | If you rebuild your server (new IP), just update the DNS record — no need to change PrivateCrossVPN profiles |
| **Multi-region** | Use subdomains for different regions: `us.vpn.mysite.tech`, `eu.vpn.mysite.tech` |
| **Privacy** | Your VPN config files contain a domain instead of a raw IP |
| **TLS/SSL** | Required if you ever want to serve a web panel over HTTPS |

---

## 2. Register a Domain on Namecheap

1. Go to [namecheap.com](https://www.namecheap.com)
2. Search for a domain name (e.g., `myprivatevpn.tech`)
3. Popular affordable TLDs for VPN use:

| TLD | Typical Price | Notes |
|---|---|---|
| `.tech` | ~$4-10/year (first year promo) | Great for tech projects, often discounted |
| `.xyz` | ~$1-2/year | Very cheap |
| `.online` | ~$1-3/year | Budget option |
| `.com` | ~$9-12/year | Classic, but more expensive |
| `.net` | ~$10-13/year | Alternative classic |

1. Add to cart and complete purchase
2. During registration:
   - **WhoisGuard**: Enable (free on Namecheap) — hides your personal info from WHOIS lookups
   - **Auto-renew**: Enable if you want to keep the domain

---

## 3. Configure DNS Records

### Use Namecheap's BasicDNS (Default)

1. Log in to Namecheap -> **Domain List** -> Click **Manage** on your domain
2. Go to the **Advanced DNS** tab
3. Remove any default parking records
4. Add the following records:

### For a Single VPN Server

| Type | Host | Value | TTL |
|---|---|---|---|
| **A** | `vpn` | `YOUR_SERVER_IP` (e.g., `164.90.234.17`) | Automatic |

This creates `vpn.yourdomain.tech` pointing to your server.

### For Multiple Regions

| Type | Host | Value | TTL |
|---|---|---|---|
| A | `us` | `US_SERVER_IP` | Automatic |
| A | `eu` | `EU_SERVER_IP` | Automatic |
| A | `sg` | `SINGAPORE_SERVER_IP` | Automatic |
| A | `vpn` | `DEFAULT_SERVER_IP` | Automatic |

Now you have `us.yourdomain.tech`, `eu.yourdomain.tech`, etc.

### For SSH Access Too

| Type | Host | Value | TTL |
|---|---|---|---|
| A | `vpn` | `YOUR_SERVER_IP` | Automatic |
| A | `ssh` | `YOUR_SERVER_IP` | Automatic |

### Verify DNS Propagation

After adding records, verify with:

```bash
# Check if DNS has propagated (may take 5-30 minutes)
dig vpn.yourdomain.tech +short
nslookup vpn.yourdomain.tech

# Or use an online tool: https://dnschecker.org
```

---

## 4. Using with PrivateCrossVPN

Once DNS is set up, use the domain instead of an IP in your profiles.

### WireGuard Profile

| Field | Value |
|---|---|
| Endpoint | `vpn.yourdomain.tech:51820` |
| *(other fields)* | *(same as before)* |

### OpenVPN Profile

| Field | Value |
|---|---|
| Remote Server | `vpn.yourdomain.tech` |
| Port | `1194` |

### SSH SOCKS5 Profile

| Field | Value |
|---|---|
| SSH Host | `vpn.yourdomain.tech` |
| SSH Port | `22` |

### Benefit: Server Migration

If you need to move to a new server (new IP `203.0.113.50`):

1. Update the DNS A record for `vpn` to `203.0.113.50` on Namecheap
2. Wait for propagation (~5-30 minutes)
3. Your PrivateCrossVPN profiles automatically connect to the new server — no profile edits needed

---

## 5. Advanced: Dynamic DNS

If your server's IP changes frequently (e.g., Azure VM without static IP), you can use Namecheap's Dynamic DNS (DDNS) feature.

### Enable DDNS on Namecheap

1. **Domain List** -> **Manage** -> **Advanced DNS**
2. Toggle **Dynamic DNS** to ON
3. Note the **Dynamic DNS Password** shown

### Update from Your Server

Create a cron job on your VPN server to update the DNS record automatically:

```bash
# Install ddclient or use curl directly
# Using Namecheap's DDNS API:

# /usr/local/bin/update-ddns.sh
#!/bin/bash
DOMAIN="yourdomain.tech"
HOST="vpn"
PASSWORD="your_ddns_password"

curl -s "https://dynamicdns.park-your-domain.com/update?host=${HOST}&domain=${DOMAIN}&password=${PASSWORD}"
```

```bash
chmod +x /usr/local/bin/update-ddns.sh

# Run every 5 minutes via cron
crontab -e
# Add: */5 * * * * /usr/local/bin/update-ddns.sh > /dev/null 2>&1
```

---

## 6. Advanced: Multiple Server Regions

Combine DigitalOcean / Azure with Namecheap for a multi-region VPN setup:

```
yourdomain.tech
├── us.yourdomain.tech  ->  DigitalOcean NYC     (104.131.xxx.xxx)
├── eu.yourdomain.tech  ->  DigitalOcean Frankfurt (164.90.xxx.xxx)
├── sg.yourdomain.tech  ->  Azure Southeast Asia  (20.xxx.xxx.xxx)
└── vpn.yourdomain.tech ->  (your default/closest server)
```

In PrivateCrossVPN, create a profile for each:

| Profile Name | Endpoint / SSH Host |
|---|---|
| `us-wireguard` | `us.yourdomain.tech:51820` |
| `eu-wireguard` | `eu.yourdomain.tech:51820` |
| `sg-ssh` | `sg.yourdomain.tech` |

Switch between regions by selecting a different profile from the dropdown.

---

## 7. .tech Domain Notes

The `.tech` TLD is managed by Radix and is popular for technology projects.

### Pricing on Namecheap

| Period | Approx. Price |
|---|---|
| 1st year (promo) | $4 - $10 |
| Renewal | $35 - $50/year |

> **Important**: `.tech` renewal prices are significantly higher than the first-year price. Budget accordingly or consider:
>
> - Transferring to a registrar with lower renewal pricing
> - Using a cheaper TLD (`.xyz` renews at ~$10/year)
> - Checking Namecheap coupons at renewal time

### Alternatives to .tech

| TLD | 1st Year | Renewal | Notes |
|---|---|---|---|
| `.xyz` | ~$1 | ~$10 | Best budget option |
| `.online` | ~$1 | ~$25 | Cheap first year |
| `.dev` | ~$12 | ~$12 | Stable pricing, HSTS preloaded (forces HTTPS) |
| `.io` | ~$30 | ~$30 | Popular in tech, stable pricing |
| `.com` | ~$9 | ~$12 | Classic, no surprises |

### WhoisGuard / Privacy

Namecheap includes free WhoisGuard (WHOIS privacy protection) with all domains. This hides your personal name, address, and email from public WHOIS lookups. **Always keep this enabled** for a VPN domain.

---

## Troubleshooting

### DNS Not Resolving

```bash
# Check if the record exists
dig vpn.yourdomain.tech A

# If no answer, wait longer (propagation can take up to 48 hours, usually 5-30 min)
# Or check for typos in the Namecheap DNS panel
```

### Connection Timeout with Domain

1. Verify DNS resolves: `dig vpn.yourdomain.tech +short`
2. Verify the IP is correct: compare with your server's actual IP
3. Ping the domain: `ping vpn.yourdomain.tech`
4. If DNS works but VPN fails, the issue is server-side (firewall, service not running)

### Domain Expired

If your domain expires, VPN profiles using it will fail to connect. You'll see DNS resolution errors in the PrivateCrossVPN activity log. Renew the domain or temporarily edit profiles to use the raw IP address.
