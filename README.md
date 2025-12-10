# CloakProbe

<div align="center">
  <img src="assets/badge.png" alt="CloakProbe Social Banner" width="100%">
</div>

<div align="center">

[![CI](https://github.com/drmckay/cloakprobe/workflows/CI/badge.svg)](https://github.com/drmckay/cloakprobe/actions)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)

Privacy-first, security-focused IP information service designed to run behind Cloudflare.

</div>

> ⚠️ **Commercial Use Notice**: This software is licensed under AGPL-3.0 with additional commercial use restrictions. Commercial use requires explicit written permission. See [LICENSE](LICENSE) for details.

## Features

- 🔒 **Privacy-first**: No tracking, no ads, no analytics
- 🛡️ **Security-focused**: Comprehensive security headers, input validation
- 🌐 **IPv4 & IPv6**: Full support for both IP versions
- 📊 **Detailed Information**: IP details (multiple formats), ASN lookup, network information, organization details from all 5 RIRs
- 🎨 **Modern UI**: Beautiful dark theme, responsive design, one-click IP copy
- ⚡ **Fast**: Built with Rust for performance
- 🔧 **Easy Setup**: Simple configuration, Docker-ready
- 📡 **Cloudflare Integration**: Reads client IP from Cloudflare headers (CF-Connecting-IP)
- 🌍 **Cloudflare Worker Headers**: Supports extended Cloudflare Worker headers (X-CF-Country, X-CF-City, X-CF-ASN, X-CF-Trust-Score, etc.)
- 🔒 **XSS Protection**: All Cloudflare header values are sanitized before HTML rendering
- 🗄️ **Local ASN Database**: Uses ip2asn-based binary database (`asn_db.bin`)
- 🏢 **Multi-RIR Organization Data**: Organization details from all 5 RIRs (RIPE, APNIC, LACNIC, AFRINIC, ARIN)
- 🔍 **Reverse DNS Lookup**: Client-side reverse DNS (PTR) lookup using Cloudflare DNS over HTTPS (DoH) - only on user interaction
- 🌐 **ISP Hint Detection**: Client-side authoritative NS lookup to identify ISP/provider from nameserver hostnames

## Requirements

- Rust (stable, e.g. 1.80+)
- Linux / macOS
- `curl`, `gunzip` (for gzip package)

## Installation

> 📖 **Detailed Installation Guide**: See [INSTALL.md](INSTALL.md) for comprehensive installation instructions, troubleshooting, and manual setup.

### Quick Install (from GitHub Release)

```bash
# Download and run the installation script
curl -fsSL https://raw.githubusercontent.com/drmckay/cloakprobe/main/install.sh | sudo bash

# Download ASN database
sudo /opt/cloakprobe/scripts/update_asn_db.sh

# Start the service
sudo systemctl start cloakprobe

# Check status
sudo systemctl status cloakprobe
```

### Manual Installation

```bash
git clone https://github.com/drmckay/cloakprobe.git
cd cloakprobe

# Build
cargo build --release

# Generate IP→ASN database
./scripts/update_asn_db.sh

# Run locally
CLOAKPROBE_PRIVACY_MODE=strict \
CLOAKPROBE_ASN_DB_PATH=./data/asn_db.bin \
CLOAKPROBE_REGION=eu-central \
  ./target/release/cloakprobe
```

Default address: `0.0.0.0:8080`.

### Systemd Service

The installation script automatically sets up a systemd service. Manual setup:

```bash
# Copy service file
sudo cp cloakprobe.service /etc/systemd/system/

# Edit paths if needed
sudo nano /etc/systemd/system/cloakprobe.service

# Reload systemd
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable cloakprobe
sudo systemctl start cloakprobe
```

## Configuration

CloakProbe uses a TOML configuration file for clean, organized settings. Environment variables can override config file values for container deployments.

### Configuration File

Copy the example config and customize:

```bash
cp cloakprobe.example.toml cloakprobe.toml
```

Config file locations (in order of priority):
1. Path specified with `-c/--config` argument
2. `./cloakprobe.toml` (current directory)
3. `/etc/cloakprobe/cloakprobe.toml` (system-wide)

Example configuration:

```toml
[server]
bind_address = "0.0.0.0"
port = 8080
mode = "cloudflare"    # "cloudflare" or "nginx"
region = "eu-central"  # optional

[privacy]
mode = "strict"        # "strict" or "balanced"

[database]
asn_db_path = "data/asn_db.bin"
org_db_path = "data/orgs_db.bin"
```

### Proxy Modes

- **`cloudflare`**: Trust `CF-Connecting-IP` header (default). Use when running behind Cloudflare CDN.
- **`nginx`**: Trust `X-Real-IP` and `X-Forwarded-For` headers. Use when running behind nginx or other standard reverse proxies without Cloudflare.

### Command Line Options

```bash
cloakprobe [OPTIONS]

OPTIONS:
    -c, --config <PATH>    Path to configuration file (TOML)
    -h, --help             Print help information
    -v, --version          Print version information
```

### Environment Variables (Override Config)

Environment variables override TOML config values (useful for containers):

- `CLOAKPROBE_BIND_ADDRESS`: IP address to bind to
- `CLOAKPROBE_PORT`: Port number
- `CLOAKPROBE_MODE`: Proxy mode (`cloudflare` or `nginx`)
- `CLOAKPROBE_REGION`: Server region identifier
- `CLOAKPROBE_PRIVACY_MODE`: Privacy mode (`strict` or `balanced`)
- `CLOAKPROBE_ASN_DB_PATH`: Path to ASN database
- `CLOAKPROBE_ORG_DB_PATH`: Path to multi-RIR organization database

**Note**: If database paths are not specified, CloakProbe will automatically search for databases in the `data/` directory.

## API Endpoints

- `GET /` – HTML UI (dark card-based view with detailed IP information)
- `GET /privacy` – Privacy Policy page (GDPR and CCPA compliant)
- `GET /api/v1/json` – JSON debug info
- `GET /api/v1/plain` – Plain text output, convenient for CLI
- `GET /healthz` – Health check, returns `{"status":"ok"}`

## Database Updates

CloakProbe uses two databases:

### 1. IP→ASN Database (ip2asn)

Uses the **ip2asn-combined.tsv.gz** database from [iptoasn.com](https://iptoasn.com/) (Public Domain / PDDL).

- Format: `range_start range_end AS_number country_code AS_description`
- Contains both IPv4 and IPv6 ranges.
- Script: `scripts/update_asn_db.sh`
- Output: `data/asn_db.bin`

### 2. Multi-RIR Organization Database

Uses data from all 5 Regional Internet Registries (RIRs) to map ASN → Organization details.

- **Sources**: RIPE, APNIC, LACNIC, AFRINIC (RPSL format), ARIN (delegated stats fallback)
- **Data**: org_id, org_name, country, RIR, org_type, abuse_contact, last_updated
- **Script**: `scripts/update_org_db.sh`
- **Output**: `data/orgs_db.bin`

### Usage

```bash
cd /opt/cloakprobe
cargo build --release

# Update ASN database (IP ranges)
./scripts/update_asn_db.sh

# Update multi-RIR organization database
./scripts/update_org_db.sh
```

Then:

```bash
# Databases will be automatically found in ./data/ if environment variables are not set
CLOAKPROBE_PRIVACY_MODE=strict \
  ./target/release/cloakprobe
```

Or explicitly specify database paths:

```bash
CLOAKPROBE_ASN_DB_PATH=/opt/cloakprobe/data/asn_db.bin \
CLOAKPROBE_ORG_DB_PATH=/opt/cloakprobe/data/orgs_db.bin \
CLOAKPROBE_PRIVACY_MODE=strict \
  ./target/release/cloakprobe
```

### Cron Example

```cron
# Update ASN database daily at 3:00 AM
0 3 * * * /opt/cloakprobe/scripts/update_asn_db.sh >> /var/log/cloakprobe-asn-update.log 2>&1

# Update multi-RIR organization database weekly on Sunday at 4:00 AM
0 4 * * 0 /opt/cloakprobe/scripts/update_org_db.sh >> /var/log/cloakprobe-org-update.log 2>&1
```

---

## Running Behind Nginx

> 📖 **Detailed Nginx Guide**: See [docs/nginx-deployment.md](docs/nginx-deployment.md) for comprehensive nginx configurations including security hardening, Cloudflare IP restrictions, and dual-stack detection setup.

### Quick Setup

CloakProbe supports two proxy modes:

| Mode | Use Case | Trusted Header |
|------|----------|----------------|
| `cloudflare` | Behind Cloudflare CDN | `CF-Connecting-IP` |
| `nginx` | Direct nginx (no CF) | `X-Real-IP` |

**Basic nginx config:**

```nginx
server {
    listen 443 ssl http2;
    server_name ip.example.com;

    ssl_certificate     /etc/letsencrypt/live/ip.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ip.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # IMPORTANT: Always use $remote_addr to prevent IP spoofing
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;
    }
}
```

### Security Warning

**Never use `$proxy_add_x_forwarded_for`** - it appends to existing headers, allowing IP spoofing. Always use `$remote_addr`.

For Cloudflare deployments, restrict connections to Cloudflare IPs only. See [docs/nginx-deployment.md](docs/nginx-deployment.md) for the full security configuration.

### Dual-Stack Detection

For IPv4/IPv6 network capability detection, deploy multiple instances:

- `ip.example.com` - Primary (Cloudflare, dual-stack)
- `ip4.example.com` - IPv4-only (A record only)
- `ip6.example.com` - IPv6-only (AAAA record only, no Cloudflare)

See [docs/nginx-deployment.md](docs/nginx-deployment.md) for complete setup instructions

---

## Security Headers

The app sets the following HTTP headers on every response:

- `Content-Security-Policy`
- `Referrer-Policy`
- `X-Frame-Options`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `Permissions-Policy`

No external scripts, fonts, or analytics sources; all assets come from the same domain. The only external connection allowed is to `cloudflare-dns.com` for the optional client-side reverse DNS lookup feature (only when user explicitly clicks the lookup button).

### Input Sanitization

All Cloudflare header values are sanitized before being rendered in HTML to prevent XSS (Cross-Site Scripting) attacks. HTML special characters (`<`, `>`, `&`, `"`, `'`, `/`) are automatically escaped, ensuring that malicious header values cannot inject JavaScript or HTML into the page.

### Privacy Policy

CloakProbe includes a comprehensive Privacy Policy page (`/privacy`) that is GDPR and CCPA compliant. The policy explains:
- What data is collected and processed
- How data is handled (no disk storage, no logging in strict mode)
- Cloudflare's data processing practices
- User rights under GDPR and CCPA
- Security measures implemented
- Reverse DNS lookup feature (client-side only, on user interaction)

The privacy policy is accessible from the main page footer and can be viewed at `/privacy`.

### Reverse DNS and ISP Hint Lookup

CloakProbe includes optional client-side DNS lookup features:

**Reverse DNS (PTR) Lookup:**
- **User-initiated only**: The lookup only happens when the user explicitly clicks the "Lookup Reverse DNS" button
- **Client-side**: Uses Cloudflare DNS over HTTPS (DoH) directly from the browser
- **No server-side processing**: No data is sent to the CloakProbe server
- **Privacy-focused**: Cloudflare DoH is privacy-focused and does not log queries
- **No automatic requests**: The page does not send any external requests automatically

**Authoritative NS (ISP Hint) Lookup:**
- **Runs in parallel**: When PTR lookup is triggered, NS lookup runs simultaneously
- **ISP detection**: Extracts ISP/provider domain from nameserver hostnames (e.g., `ns1.telekom.hu` → `telekom.hu`)
- **Useful for identification**: Helps identify the actual ISP even when reverse DNS hostname doesn't contain the provider name

---

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) first.

## License

This project is licensed under the **GNU Affero General Public License v3.0** with additional commercial use restrictions.

**Non-commercial use** (personal, educational, research, non-profit) is permitted under AGPL-3.0.

**Commercial use** requires explicit written permission from the copyright holders.

See [LICENSE](LICENSE) for full details.

## Security

Please report security vulnerabilities privately. See [SECURITY.md](SECURITY.md) for details.

## Development / Extension

- **Code Structure**: Modular architecture with separate handler modules (`handlers/`), header extraction (`headers/`), utilities (`utils/`), and formatters (`formatters/`)
- **ASN lookup**: `src/asn.rs` uses a binary prefix-range database from ip2asn.
- **Tor / VPN detection**:
  - The `NetworkInfo` struct contains `tor_exit` and `vpn_or_hosting` flags, these default to `false`.
- **Reverse DNS**:
  - Client-side reverse DNS lookup is available via the HTML UI using Cloudflare DNS over HTTPS (DoH)
  - The lookup happens entirely in the browser when the user clicks the "Lookup Reverse DNS" button
  - No server-side reverse DNS lookup is implemented (the API response does not include reverse DNS)
- **Testing**:
  - Comprehensive test suite with 70 tests covering handlers, headers, utils, and formatters
  - All handlers have dedicated test modules
  - Run tests with `cargo test`
  - Ensure code passes `cargo fmt` and `cargo clippy` without warnings

## Acknowledgments

- Uses [iptoasn.com](https://iptoasn.com/) data (Public Domain / PDDL)
- Uses data from all 5 Regional Internet Registries (RIRs): [RIPE NCC](https://www.ripe.net/), [APNIC](https://www.apnic.net/), [LACNIC](https://www.lacnic.net/), [AFRINIC](https://www.afrinic.net/), [ARIN](https://www.arin.net/)
- Built with [Rust](https://www.rust-lang.org/) and [Axum](https://github.com/tokio-rs/axum)
