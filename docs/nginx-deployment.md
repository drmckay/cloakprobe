# Nginx Deployment Guide

This guide covers nginx reverse proxy configurations for CloakProbe in different deployment scenarios.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Security Considerations](#security-considerations)
- [Configuration 1: Behind Cloudflare](#configuration-1-behind-cloudflare)
- [Configuration 2: Direct nginx (No Cloudflare)](#configuration-2-direct-nginx-no-cloudflare)
- [Configuration 3: IPv6-Only Instance](#configuration-3-ipv6-only-instance)
- [Dual-Stack Detection Setup](#dual-stack-detection-setup)
- [Cloudflare IP Snippet](#cloudflare-ip-snippet)
- [Systemd Service Examples](#systemd-service-examples)

## Architecture Overview

CloakProbe supports multiple deployment architectures:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DEPLOYMENT SCENARIOS                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Cloudflare Mode (ip.example.com)                                        │
│     Internet → Cloudflare CDN → nginx → CloakProbe (mode=cloudflare)        │
│     - Full Cloudflare headers (geo, security scores, etc.)                  │
│     - IP from CF-Connecting-IP header                                       │
│                                                                              │
│  2. Nginx Mode (ip-direct.example.com)                                      │
│     Internet → nginx → CloakProbe (mode=nginx)                              │
│     - No Cloudflare features                                                │
│     - IP from X-Real-IP / X-Forwarded-For header                            │
│                                                                              │
│  3. IPv6-Only Mode (ip6.example.com)                                        │
│     Internet (IPv6) → nginx (IPv6 only) → CloakProbe (mode=nginx)           │
│     - For dual-stack network detection                                      │
│     - Only accessible via IPv6                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Considerations

### Header Spoofing Prevention

**Critical**: Never trust client-provided IP headers without verification.

| Scenario | Risk | Solution |
|----------|------|----------|
| Cloudflare mode | Attacker sends fake `CF-Connecting-IP` | Only accept connections from Cloudflare IPs |
| Nginx mode | Attacker sends fake `X-Forwarded-For` | Always overwrite with `$remote_addr` |

### Rules

1. **Cloudflare vhosts**: Use `include cloudflare-only.conf` to restrict to CF IPs
2. **Direct vhosts**: Always set `proxy_set_header X-Real-IP $remote_addr`
3. **Never use** `$proxy_add_x_forwarded_for` - it appends to existing (potentially spoofed) values

---

## Configuration 1: Behind Cloudflare

For domains proxied through Cloudflare (orange cloud enabled).

### CloakProbe Config

```toml
# /etc/cloakprobe/cloudflare.toml
[server]
bind_address = "127.0.0.1"
port = 8080
mode = "cloudflare"
region = "eu-central"

[privacy]
mode = "strict"

[database]
asn_db_path = "/opt/cloakprobe/data/asn_db.bin"
ripe_db_path = "/opt/cloakprobe/data/ripe_db.bin"
```

### Nginx Config

```nginx
# /etc/nginx/sites-available/ip.example.com

server {
    listen 80;
    server_name ip.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ip.example.com;

    # SSL (Cloudflare Full/Strict mode)
    ssl_certificate     /etc/letsencrypt/live/ip.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ip.example.com/privkey.pem;

    # SECURITY: Only allow Cloudflare IPs
    include /etc/nginx/snippets/cloudflare-only.conf;

    # Disable logging for privacy
    access_log off;
    error_log /dev/null crit;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        # Standard headers
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Client IP (already converted by real_ip_header in snippet)
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;

        # Pass through Cloudflare headers for extended info
        # These are safe because we only accept CF connections
    }
}
```

---

## Configuration 2: Direct nginx (No Cloudflare)

For domains that bypass Cloudflare entirely.

### CloakProbe Config

```toml
# /etc/cloakprobe/nginx.toml
[server]
bind_address = "127.0.0.1"
port = 8081
mode = "nginx"
region = "eu-central"

[privacy]
mode = "strict"

[database]
asn_db_path = "/opt/cloakprobe/data/asn_db.bin"
ripe_db_path = "/opt/cloakprobe/data/ripe_db.bin"
```

### Nginx Config

```nginx
# /etc/nginx/sites-available/ip-direct.example.com

server {
    listen 80;
    listen [::]:80;
    server_name ip-direct.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ip-direct.example.com;

    ssl_certificate     /etc/letsencrypt/live/ip-direct.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ip-direct.example.com/privkey.pem;

    # Disable logging for privacy
    access_log off;
    error_log /dev/null crit;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # SECURITY: Always use $remote_addr, never trust incoming headers
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;

        # SECURITY: Clear any spoofed Cloudflare headers
        proxy_set_header CF-Connecting-IP  "";
        proxy_set_header CF-IPCountry      "";
        proxy_set_header CF-Ray            "";
        proxy_set_header CF-Visitor        "";
    }
}
```

---

## Configuration 3: IPv6-Only Instance

For dual-stack network detection. This instance **only** listens on IPv6.

### CloakProbe Config

```toml
# /etc/cloakprobe/ipv6.toml
[server]
bind_address = "::1"      # IPv6 localhost
port = 8082
mode = "nginx"
region = "eu-central-v6"

[privacy]
mode = "strict"

[database]
asn_db_path = "/opt/cloakprobe/data/asn_db.bin"
ripe_db_path = "/opt/cloakprobe/data/ripe_db.bin"
```

### Nginx Config

```nginx
# /etc/nginx/sites-available/ip6.example.com

# NO IPv4 listener - IPv6 only!
server {
    listen [::]:80 ipv6only=on;
    server_name ip6.example.com;
    return 301 https://$host$request_uri;
}

server {
    # CRITICAL: Only IPv6, no IPv4
    listen [::]:443 ssl http2 ipv6only=on;
    server_name ip6.example.com;

    ssl_certificate     /etc/letsencrypt/live/ip6.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ip6.example.com/privkey.pem;

    # Disable logging for privacy
    access_log off;
    error_log /dev/null crit;

    location / {
        proxy_pass http://[::1]:8082;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # SECURITY: Always use $remote_addr
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;

        # Clear spoofed headers
        proxy_set_header CF-Connecting-IP  "";
        proxy_set_header CF-IPCountry      "";
        proxy_set_header CF-Ray            "";
        proxy_set_header CF-Visitor        "";
    }
}
```

### DNS Setup for IPv6-Only

```
; Only AAAA record, no A record!
ip6.example.com.    IN    AAAA    2001:db8::1
```

---

## Dual-Stack Detection Setup

Use multiple CloakProbe instances to detect client network capabilities:

| Endpoint | Protocol | Purpose |
|----------|----------|---------|
| `ip.example.com` | IPv4 + IPv6 (via CF) | Primary, full features |
| `ip4.example.com` | IPv4 only | Test IPv4 connectivity |
| `ip6.example.com` | IPv6 only | Test IPv6 connectivity |

### Client-Side Detection Example

```javascript
async function detectNetworkStack() {
    const results = {
        ipv4: null,
        ipv6: null,
        dualStack: false
    };

    // Test IPv4
    try {
        const v4 = await fetch('https://ip4.example.com/api/v1/json');
        const data = await v4.json();
        results.ipv4 = data.ip;
    } catch (e) {
        results.ipv4 = null;
    }

    // Test IPv6
    try {
        const v6 = await fetch('https://ip6.example.com/api/v1/json');
        const data = await v6.json();
        results.ipv6 = data.ip;
    } catch (e) {
        results.ipv6 = null;
    }

    results.dualStack = results.ipv4 !== null && results.ipv6 !== null;
    return results;
}
```

---

## Cloudflare IP Snippet

Create this reusable snippet for Cloudflare-only vhosts:

```nginx
# /etc/nginx/snippets/cloudflare-only.conf
#
# Include this in vhosts that should only accept Cloudflare connections.
# Update periodically: https://www.cloudflare.com/ips/

# Cloudflare IPv4 ranges
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;

# Cloudflare IPv6 ranges
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

# Trust CF-Connecting-IP as the real client IP
real_ip_header CF-Connecting-IP;

# DENY all non-Cloudflare IPs
allow 173.245.48.0/20;
allow 103.21.244.0/22;
allow 103.22.200.0/22;
allow 103.31.4.0/22;
allow 141.101.64.0/18;
allow 108.162.192.0/18;
allow 190.93.240.0/20;
allow 188.114.96.0/20;
allow 197.234.240.0/22;
allow 198.41.128.0/17;
allow 162.158.0.0/15;
allow 104.16.0.0/13;
allow 104.24.0.0/14;
allow 172.64.0.0/13;
allow 131.0.72.0/22;
allow 2400:cb00::/32;
allow 2606:4700::/32;
allow 2803:f800::/32;
allow 2405:b500::/32;
allow 2405:8100::/32;
allow 2a06:98c0::/29;
allow 2c0f:f248::/32;
deny all;
```

### Auto-Update Script

```bash
#!/bin/bash
# /opt/cloakprobe/scripts/update-cloudflare-ips.sh
#
# Updates Cloudflare IP ranges for nginx
# Run via cron: 0 0 * * * /opt/cloakprobe/scripts/update-cloudflare-ips.sh

set -e

CF_IPS_V4="https://www.cloudflare.com/ips-v4"
CF_IPS_V6="https://www.cloudflare.com/ips-v6"
OUTPUT="/etc/nginx/snippets/cloudflare-only.conf"
TEMP=$(mktemp)

cat > "$TEMP" << 'EOF'
# Cloudflare IP ranges - Auto-generated
# Last updated: $(date -Iseconds)
# Source: https://www.cloudflare.com/ips/

EOF

echo "# IPv4 ranges" >> "$TEMP"
for ip in $(curl -sf "$CF_IPS_V4"); do
    echo "set_real_ip_from $ip;" >> "$TEMP"
done

echo -e "\n# IPv6 ranges" >> "$TEMP"
for ip in $(curl -sf "$CF_IPS_V6"); do
    echo "set_real_ip_from $ip;" >> "$TEMP"
done

echo -e "\nreal_ip_header CF-Connecting-IP;\n" >> "$TEMP"

echo "# Allow rules" >> "$TEMP"
for ip in $(curl -sf "$CF_IPS_V4"); do
    echo "allow $ip;" >> "$TEMP"
done
for ip in $(curl -sf "$CF_IPS_V6"); do
    echo "allow $ip;" >> "$TEMP"
done
echo "deny all;" >> "$TEMP"

# Test nginx config before applying
cp "$TEMP" "$OUTPUT"
if nginx -t 2>/dev/null; then
    systemctl reload nginx
    echo "Cloudflare IPs updated successfully"
else
    echo "ERROR: nginx config test failed" >&2
    exit 1
fi

rm -f "$TEMP"
```

---

## Systemd Service Examples

### Multiple Instance Setup

```ini
# /etc/systemd/system/cloakprobe@.service
[Unit]
Description=CloakProbe IP Info Service (%i)
After=network.target

[Service]
Type=simple
User=cloakprobe
Group=cloakprobe
WorkingDirectory=/opt/cloakprobe
ExecStart=/opt/cloakprobe/cloakprobe -c /etc/cloakprobe/%i.toml
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/opt/cloakprobe

[Install]
WantedBy=multi-user.target
```

Usage:

```bash
# Enable and start instances
sudo systemctl enable cloakprobe@cloudflare
sudo systemctl enable cloakprobe@nginx
sudo systemctl enable cloakprobe@ipv6

sudo systemctl start cloakprobe@cloudflare
sudo systemctl start cloakprobe@nginx
sudo systemctl start cloakprobe@ipv6

# Check status
sudo systemctl status cloakprobe@*
```

---

## Summary

| Instance | Port | Mode | Config | Use Case |
|----------|------|------|--------|----------|
| Cloudflare | 8080 | `cloudflare` | `/etc/cloakprobe/cloudflare.toml` | Primary, full features |
| Direct | 8081 | `nginx` | `/etc/cloakprobe/nginx.toml` | No Cloudflare dependency |
| IPv6-only | 8082 | `nginx` | `/etc/cloakprobe/ipv6.toml` | Dual-stack detection |

