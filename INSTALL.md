# Installation Guide

This guide covers different installation methods for CloakProbe.

## Quick Install from GitHub Release

The easiest way to install CloakProbe is using the automated installation script:

```bash
curl -fsSL https://raw.githubusercontent.com/drmckay/cloakprobe/main/install.sh | sudo bash
```

This script will:
1. Detect your system architecture
2. Download the latest release from GitHub
3. Install the binary to `/opt/cloakprobe`
4. Create a `cloakprobe` system user
5. Set up systemd service
6. Enable the service (but not start it)

### After Installation

1. **Download ASN Database** (IP ranges → ASN):
   ```bash
   sudo /opt/cloakprobe/scripts/update_asn_db.sh
   ```

2. **Download RIPE Organization Database** (ASN → Company name):
   ```bash
   sudo /opt/cloakprobe/scripts/update_ripe_db.sh
   ```

3. **Start the Service**:
   ```bash
   sudo systemctl start cloakprobe
   ```

4. **Check Status**:
   ```bash
   sudo systemctl status cloakprobe
   ```

5. **View Logs**:
   ```bash
   sudo journalctl -u cloakprobe -f
   ```

## Manual Installation

### Step 1: Build from Source

```bash
git clone https://github.com/drmckay/cloakprobe.git
cd cloakprobe
cargo build --release
```

### Step 2: Install Binary

```bash
sudo mkdir -p /opt/cloakprobe/data
sudo cp target/release/cloakprobe /opt/cloakprobe/
sudo chmod +x /opt/cloakprobe/cloakprobe
```

### Step 3: Create System User

```bash
sudo useradd -r -s /bin/false -d /opt/cloakprobe cloakprobe
sudo chown -R cloakprobe:cloakprobe /opt/cloakprobe
```

### Step 4: Setup Databases

```bash
# Copy update scripts
sudo cp scripts/update_asn_db.sh /opt/cloakprobe/scripts/
sudo cp scripts/update_ripe_db.sh /opt/cloakprobe/scripts/
sudo chmod +x /opt/cloakprobe/scripts/*.sh

# Download ASN database (IP ranges)
sudo /opt/cloakprobe/scripts/update_asn_db.sh

# Download RIPE organization database (company names)
sudo /opt/cloakprobe/scripts/update_ripe_db.sh
```

### Step 5: Install Systemd Service

```bash
sudo cp cloakprobe.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloakprobe
sudo systemctl start cloakprobe
```

## Configuration

Edit the systemd service file to customize settings:

```bash
sudo nano /etc/systemd/system/cloakprobe.service
```

Key environment variables:
- `CLOAKPROBE_PRIVACY_MODE`: `strict` or `balanced`
- `CLOAKPROBE_ASN_DB_PATH`: Path to ASN database. If not set, automatically searches in `data/asn_db.bin` and `./data/asn_db.bin`
- `CLOAKPROBE_RIPE_DB_PATH`: Path to RIPE organization database. If not set, automatically searches in `data/ripe_db.bin` and `./data/ripe_db.bin`
- `CLOAKPROBE_REGION`: Optional region identifier
- `PORT`: Port to bind to (default: `8080`)

**Note**: Starting with version 0.1.1, CloakProbe automatically searches for database files in the `data/` directory if environment variables are not set. This makes configuration easier - you can simply place database files in the `data/` directory relative to where you run the binary.

After editing, reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart cloakprobe
```

## Updating

To update to a newer version:

```bash
# Stop service
sudo systemctl stop cloakprobe

# Run installer again (it will overwrite)
curl -fsSL https://raw.githubusercontent.com/drmckay/cloakprobe/main/install.sh | sudo bash

# Start service
sudo systemctl start cloakprobe
```

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop cloakprobe
sudo systemctl disable cloakprobe

# Remove service file
sudo rm /etc/systemd/system/cloakprobe.service
sudo systemctl daemon-reload

# Remove files
sudo rm -rf /opt/cloakprobe

# Remove user (optional)
sudo userdel cloakprobe
```

## Troubleshooting

### Service won't start

Check logs:
```bash
sudo journalctl -u cloakprobe -n 50
```

Common issues:
- ASN database missing: Run `update_asn_db.sh`
- RIPE database missing: Run `update_ripe_db.sh` (optional, for organization names)
- Permission issues: Check file ownership (`cloakprobe:cloakprobe`)
- Port already in use: Change `PORT` in service file

### Binary not found

Ensure the binary exists and is executable:
```bash
ls -la /opt/cloakprobe/cloakprobe
sudo chmod +x /opt/cloakprobe/cloakprobe
```

### ASN database update fails

Check internet connection and disk space:
```bash
df -h /opt/cloakprobe/data
curl -I https://iptoasn.com/data/ip2asn-combined.tsv.gz
```

## Privacy Policy

CloakProbe includes a comprehensive Privacy Policy page accessible at `/privacy`. The policy is GDPR and CCPA compliant and explains:

- What data is collected and processed
- How data is handled (no disk storage, no logging in strict mode)
- Cloudflare's data processing practices
- User rights under GDPR and CCPA
- Security measures implemented
- Reverse DNS lookup feature (client-side only, on user interaction)

The privacy policy is accessible from the main page footer and can be viewed at `http://your-server/privacy`.

### Reverse DNS Lookup

CloakProbe includes an optional client-side reverse DNS lookup feature that allows users to query the hostname (PTR record) associated with their IP address:

- **User-initiated only**: The lookup only happens when the user explicitly clicks the "Lookup Reverse DNS" button
- **Client-side**: Uses Cloudflare DNS over HTTPS (DoH) directly from the browser
- **No server-side processing**: No data is sent to the CloakProbe server
- **Privacy-focused**: Cloudflare DoH is privacy-focused and does not log queries
- **No automatic requests**: The page does not send any external requests automatically, neither client-side nor server-side

