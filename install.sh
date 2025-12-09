#!/bin/bash
set -euo pipefail

# CloakProbe Installation Script
# This script downloads the latest release from GitHub and sets up the service

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/cloakprobe"
CONFIG_DIR="/etc/cloakprobe"
SERVICE_USER="cloakprobe"
SERVICE_GROUP="cloakprobe"
GITHUB_REPO="drmckay/cloakprobe"
BINARY_NAME="cloakprobe"
BUILDER_BINARY="asn_builder"
RIPE_BUILDER_BINARY="ripe_builder"
SERVICE_FILE="systemd/cloakprobe.service"
CONFIG_FILE="cloakprobe.example.toml"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_os() {
    log_info "Checking operating system compatibility..."
    
    # Check if Linux
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "This installer is for Linux only"
        log_error "Detected OS: $(uname -s)"
        log_error "For other platforms, please build from source: https://github.com/drmckay/cloakprobe"
        exit 1
    fi
    
    # Detect distribution
    local distro=""
    local distro_version=""
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        distro="${ID:-unknown}"
        distro_version="${VERSION_ID:-unknown}"
    elif [[ -f /etc/redhat-release ]]; then
        distro="rhel"
        distro_version=$(cat /etc/redhat-release)
    elif [[ -f /etc/debian_version ]]; then
        distro="debian"
        distro_version=$(cat /etc/debian_version)
    else
        distro="unknown"
    fi
    
    log_info "Detected distribution: ${distro} ${distro_version}"
    
    # Check for systemd (required for service)
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd is required but not found"
        log_error "This installer requires a systemd-based Linux distribution"
        exit 1
    fi
    
    # Check for required commands
    local missing_commands=()
    
    if ! command -v curl &> /dev/null; then
        missing_commands+=("curl")
    fi
    
    if ! command -v tar &> /dev/null; then
        missing_commands+=("tar")
    fi
    
    if ! command -v useradd &> /dev/null; then
        missing_commands+=("useradd")
    fi
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing_commands[*]}"
        log_error "Please install them using your package manager:"
        
        case "${distro}" in
            ubuntu|debian)
                log_error "  sudo apt-get update && sudo apt-get install -y ${missing_commands[*]}"
                ;;
            fedora|rhel|centos)
                log_error "  sudo dnf install -y ${missing_commands[*]}"
                ;;
            arch|manjaro)
                log_error "  sudo pacman -S ${missing_commands[*]}"
                ;;
            opensuse*)
                log_error "  sudo zypper install ${missing_commands[*]}"
                ;;
            *)
                log_error "  Install ${missing_commands[*]} using your package manager"
                ;;
        esac
        exit 1
    fi
    
    # Warn about unsupported distributions (but don't fail)
    case "${distro}" in
        ubuntu|debian|fedora|rhel|centos|arch|manjaro|opensuse*|alpine)
            log_info "Distribution ${distro} is supported"
            ;;
        *)
            log_warn "Distribution ${distro} may not be fully tested"
            log_warn "Proceeding anyway, but issues may occur"
            ;;
    esac
    
    log_info "OS compatibility check passed"
}

detect_arch() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64)
            echo "x86_64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            log_error "Supported architectures: x86_64, aarch64"
            exit 1
            ;;
    esac
}

get_latest_release() {
    local repo=$1
    curl -s "https://api.github.com/repos/${repo}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

download_release() {
    local repo=$1
    local version=$2
    local arch=$3
    # Version without 'v' prefix for filename
    local version_num="${version#v}"
    # New filename format: cloakprobe-VERSION-linux-ARCH.tar.gz
    local download_url="https://github.com/${repo}/releases/download/${version}/${BINARY_NAME}-${version_num}-linux-${arch}.tar.gz"
    
    log_info "Downloading release ${version} for linux-${arch}..."
    log_info "URL: ${download_url}"
    
    if ! curl -L -f -o /tmp/cloakprobe.tar.gz "${download_url}"; then
        log_error "Failed to download release"
        exit 1
    fi
    
    log_info "Download completed"
}

install_binary() {
    log_info "Installing binary to ${INSTALL_DIR}..."
    
    # Create installation directory structure
    mkdir -p "${INSTALL_DIR}/data"
    mkdir -p "${INSTALL_DIR}/scripts"
    mkdir -p "${INSTALL_DIR}/templates"
    mkdir -p "${CONFIG_DIR}"
    
    # Extract archive to temp directory
    local temp_extract="/tmp/cloakprobe_extract"
    mkdir -p "${temp_extract}"
    tar -xzf /tmp/cloakprobe.tar.gz -C "${temp_extract}"
    
    # Find the extracted directory (handles both old and new package formats)
    # New format: cloakprobe-VERSION-linux-ARCH/
    # Old format: files directly in extract dir
    local package_dir="${temp_extract}"
    if [[ -d "${temp_extract}"/cloakprobe-* ]]; then
        package_dir=$(find "${temp_extract}" -maxdepth 1 -type d -name "cloakprobe-*" | head -1)
        log_info "Found package directory: $(basename ${package_dir})"
    fi
    
    # Copy binary
    if [[ -f "${package_dir}/${BINARY_NAME}" ]]; then
        cp "${package_dir}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
        log_info "Binary installed"
    else
        log_error "Binary not found in archive"
        exit 1
    fi
    
    # Copy ASN database if it exists
    if [[ -f "${package_dir}/data/asn_db.bin" ]]; then
        cp "${package_dir}/data/asn_db.bin" "${INSTALL_DIR}/data/asn_db.bin"
        log_info "ASN database installed"
    else
        log_warn "ASN database not found in archive"
    fi
    
    # Copy RIPE database if it exists
    if [[ -f "${package_dir}/data/ripe_db.bin" ]]; then
        cp "${package_dir}/data/ripe_db.bin" "${INSTALL_DIR}/data/ripe_db.bin"
        log_info "RIPE database installed"
    fi
    
    # Copy templates if they exist
    if [[ -d "${package_dir}/templates" ]]; then
        cp -r "${package_dir}/templates/"* "${INSTALL_DIR}/templates/" 2>/dev/null || true
        log_info "Templates installed"
    fi
    
    # Copy and install configuration file
    if [[ -f "${package_dir}/${CONFIG_FILE}" ]]; then
        # Copy example to install dir
        cp "${package_dir}/${CONFIG_FILE}" "${INSTALL_DIR}/${CONFIG_FILE}"
        
        # Create default config if it doesn't exist
        if [[ ! -f "${CONFIG_DIR}/cloakprobe.toml" ]]; then
            cp "${package_dir}/${CONFIG_FILE}" "${CONFIG_DIR}/cloakprobe.toml"
            # Update paths in config for installed location
            sed -i "s|data/asn_db.bin|${INSTALL_DIR}/data/asn_db.bin|g" "${CONFIG_DIR}/cloakprobe.toml"
            sed -i "s|data/ripe_db.bin|${INSTALL_DIR}/data/ripe_db.bin|g" "${CONFIG_DIR}/cloakprobe.toml"
            log_info "Configuration file installed to ${CONFIG_DIR}/cloakprobe.toml"
        else
            log_info "Configuration file already exists, skipping"
        fi
    fi
    
    # Copy service files if they exist
    if [[ -f "${package_dir}/${SERVICE_FILE}" ]]; then
        mkdir -p "${INSTALL_DIR}/systemd"
        cp "${package_dir}/${SERVICE_FILE}" "${INSTALL_DIR}/${SERVICE_FILE}"
        log_info "Service file installed"
    fi
    
    if [[ -f "${package_dir}/systemd/cloakprobe@.service" ]]; then
        cp "${package_dir}/systemd/cloakprobe@.service" "${INSTALL_DIR}/systemd/cloakprobe@.service"
        log_info "Multi-instance service template installed"
    fi
    
    # Copy builder binaries if they exist
    if [[ -f "${package_dir}/${BUILDER_BINARY}" ]]; then
        cp "${package_dir}/${BUILDER_BINARY}" "${INSTALL_DIR}/${BUILDER_BINARY}"
        chmod +x "${INSTALL_DIR}/${BUILDER_BINARY}"
        log_info "asn_builder binary installed"
    fi
    
    if [[ -f "${package_dir}/${RIPE_BUILDER_BINARY}" ]]; then
        cp "${package_dir}/${RIPE_BUILDER_BINARY}" "${INSTALL_DIR}/${RIPE_BUILDER_BINARY}"
        chmod +x "${INSTALL_DIR}/${RIPE_BUILDER_BINARY}"
        log_info "ripe_builder binary installed"
    fi
    
    # Copy update scripts if they exist
    if [[ -f "${package_dir}/scripts/update_asn_db.sh" ]]; then
        cp "${package_dir}/scripts/update_asn_db.sh" "${INSTALL_DIR}/scripts/update_asn_db.sh"
        chmod +x "${INSTALL_DIR}/scripts/update_asn_db.sh"
        log_info "ASN update script installed"
    fi
    
    if [[ -f "${package_dir}/scripts/update_ripe_db.sh" ]]; then
        cp "${package_dir}/scripts/update_ripe_db.sh" "${INSTALL_DIR}/scripts/update_ripe_db.sh"
        chmod +x "${INSTALL_DIR}/scripts/update_ripe_db.sh"
        log_info "RIPE organization update script installed"
    fi
    
    # Copy documentation if it exists
    if [[ -d "${package_dir}/docs" ]]; then
        mkdir -p "${INSTALL_DIR}/docs"
        cp -r "${package_dir}/docs/"* "${INSTALL_DIR}/docs/" 2>/dev/null || true
        log_info "Documentation installed"
    fi
    
    # Cleanup
    rm -rf "${temp_extract}"
    rm -f /tmp/cloakprobe.tar.gz
}

create_user() {
    if id "${SERVICE_USER}" &>/dev/null; then
        log_info "User ${SERVICE_USER} already exists"
    else
        log_info "Creating user ${SERVICE_USER}..."
        useradd -r -s /bin/false -d "${INSTALL_DIR}" "${SERVICE_USER}"
    fi
}

setup_permissions() {
    log_info "Setting up permissions..."
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}"
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${CONFIG_DIR}"
    chmod 755 "${INSTALL_DIR}"
    chmod 755 "${INSTALL_DIR}/data"
    chmod 755 "${CONFIG_DIR}"
    chmod 644 "${CONFIG_DIR}/cloakprobe.toml" 2>/dev/null || true
}

install_systemd_service() {
    log_info "Installing systemd service..."
    
    local service_path="${INSTALL_DIR}/${SERVICE_FILE}"
    if [[ ! -f "${service_path}" ]]; then
        log_warn "Service file not found, using default..."
        service_path="$(pwd)/${SERVICE_FILE}"
    fi
    
    if [[ -f "${service_path}" ]]; then
        # Update paths in service file
        sed -i "s|/opt/cloakprobe|${INSTALL_DIR}|g" "${service_path}"
        sed -i "s|/etc/cloakprobe|${CONFIG_DIR}|g" "${service_path}"
        cp "${service_path}" "/etc/systemd/system/cloakprobe.service"
        log_info "Service installed: cloakprobe.service"
    else
        log_error "Service file not found: ${service_path}"
        exit 1
    fi
    
    # Install multi-instance template service (for advanced deployments)
    local template_path="${INSTALL_DIR}/systemd/cloakprobe@.service"
    if [[ -f "${template_path}" ]]; then
        sed -i "s|/opt/cloakprobe|${INSTALL_DIR}|g" "${template_path}"
        sed -i "s|/etc/cloakprobe|${CONFIG_DIR}|g" "${template_path}"
        cp "${template_path}" "/etc/systemd/system/cloakprobe@.service"
        log_info "Multi-instance template installed: cloakprobe@.service"
    fi
    
    systemctl daemon-reload
}

setup_asn_database() {
    log_info "Setting up ASN database..."
    
    # Check if database was included in release
    if [[ -f "${INSTALL_DIR}/data/asn_db.bin" ]]; then
        log_info "ASN database found in release package"
        local db_size=$(du -h "${INSTALL_DIR}/data/asn_db.bin" | cut -f1)
        log_info "Database size: ${db_size}"
    else
        log_warn "ASN database not found in release package"
        if [[ -f "${INSTALL_DIR}/scripts/update_asn_db.sh" ]]; then
            log_info "ASN database update script is available"
            log_warn "Run '${INSTALL_DIR}/scripts/update_asn_db.sh' to download the ASN database"
        else
            log_warn "ASN database update script not found"
            log_warn "You'll need to manually download and setup the ASN database"
        fi
    fi
}

enable_service() {
    log_info "Enabling service..."
    systemctl enable "${SERVICE_FILE}"
    log_info "Service enabled (not started yet)"
}

setup_cron() {
    log_info "Setting up automatic ASN database updates..."
    
    # Check if cron is available
    if ! command -v crontab &> /dev/null; then
        log_warn "crontab not found, skipping cron setup"
        log_warn "You can manually set up a cron job to run: ${INSTALL_DIR}/scripts/update_asn_db.sh"
        return
    fi
    
    # Check if update script exists
    if [[ ! -f "${INSTALL_DIR}/scripts/update_asn_db.sh" ]]; then
        log_warn "Update script not found, skipping cron setup"
        return
    fi
    
    # Create log directory
    local log_dir="/var/log/cloakprobe"
    mkdir -p "${log_dir}"
    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${log_dir}" 2>/dev/null || true
    
    # Cron job: Run daily at 3:00 AM
    local cron_schedule="0 3 * * *"
    local cron_command="${INSTALL_DIR}/scripts/update_asn_db.sh >> ${log_dir}/asn-update.log 2>&1"
    local cron_job="${cron_schedule} ${cron_command}"
    
    # Check if cron job already exists
    local existing_cron=$(crontab -u "${SERVICE_USER}" -l 2>/dev/null | grep -F "${INSTALL_DIR}/scripts/update_asn_db.sh" || true)
    
    if [[ -n "${existing_cron}" ]]; then
        log_info "Cron job already exists for ASN database updates"
        return
    fi
    
    # Add cron job
    log_info "Adding cron job for daily ASN database updates (3:00 AM)..."
    
    # Get existing crontab or create empty one
    local current_cron=$(crontab -u "${SERVICE_USER}" -l 2>/dev/null || echo "")
    
    # Add new cron job
    if [[ -z "${current_cron}" ]]; then
        echo "${cron_job}" | crontab -u "${SERVICE_USER}" -
    else
        (echo "${current_cron}"; echo "${cron_job}") | crontab -u "${SERVICE_USER}" -
    fi
    
    log_info "Cron job installed successfully"
    log_info "ASN database will be updated daily at 3:00 AM"
    log_info "Logs will be written to: ${log_dir}/asn-update.log"
}

print_summary() {
    echo ""
    log_info "Installation completed!"
    echo ""
    
    # Check installation status
    echo "Installation status:"
    
    if [[ -f "${INSTALL_DIR}/data/asn_db.bin" ]]; then
        echo "  ✅ ASN database installed"
    else
        echo "  ⚠️  ASN database not found"
    fi
    
    if [[ -f "${CONFIG_DIR}/cloakprobe.toml" ]]; then
        echo "  ✅ Configuration file: ${CONFIG_DIR}/cloakprobe.toml"
    else
        echo "  ⚠️  Configuration file not found"
    fi
    
    if [[ -f "${INSTALL_DIR}/templates/index.html.tera" ]]; then
        echo "  ✅ Templates installed"
    fi
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Configuration:"
    echo ""
    echo "  CloakProbe uses a TOML configuration file for all settings."
    echo "  Edit the configuration file to customize your deployment:"
    echo ""
    echo "    sudo nano ${CONFIG_DIR}/cloakprobe.toml"
    echo ""
    echo "  Key settings:"
    echo "    [server]"
    echo "    bind_address = \"127.0.0.1\"  # Listen address"
    echo "    port = 8080                   # Listen port"
    echo "    mode = \"cloudflare\"          # or \"nginx\" for direct proxy"
    echo ""
    echo "  For detailed nginx configuration examples, see:"
    echo "    ${INSTALL_DIR}/docs/nginx-deployment.md"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Next steps:"
    echo ""
    
    local step=1
    
    if [[ ! -f "${INSTALL_DIR}/data/asn_db.bin" ]]; then
        echo "  ${step}. Download ASN database:"
        echo "     sudo ${INSTALL_DIR}/scripts/update_asn_db.sh"
        echo ""
        ((step++))
    fi
    
    echo "  ${step}. (Optional) Download RIPE organization database:"
    echo "     sudo ${INSTALL_DIR}/scripts/update_ripe_db.sh"
    echo ""
    ((step++))
    
    echo "  ${step}. Edit configuration (if needed):"
    echo "     sudo nano ${CONFIG_DIR}/cloakprobe.toml"
    echo ""
    ((step++))
    
    echo "  ${step}. Start the service:"
    echo "     sudo systemctl start cloakprobe"
    echo ""
    ((step++))
    
    echo "  ${step}. Check status:"
    echo "     sudo systemctl status cloakprobe"
    echo ""
    ((step++))
    
    echo "  ${step}. View logs:"
    echo "     sudo journalctl -u cloakprobe -f"
    echo ""
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Automatic database updates:"
    
    if command -v crontab &> /dev/null; then
        if crontab -u "${SERVICE_USER}" -l 2>/dev/null | grep -q "${INSTALL_DIR}/scripts/update_asn_db.sh"; then
            echo "  ✅ ASN database updates configured (daily at 3:00 AM)"
        else
            echo "  ⚠️  ASN database updates not configured"
        fi
        
        if crontab -u "${SERVICE_USER}" -l 2>/dev/null | grep -q "${INSTALL_DIR}/scripts/update_ripe_db.sh"; then
            echo "  ✅ RIPE organization database updates configured (daily at 4:00 AM)"
        else
            echo "  ⚠️  RIPE organization database updates not configured"
        fi
        
        if ! crontab -u "${SERVICE_USER}" -l 2>/dev/null | grep -q "${INSTALL_DIR}/scripts/update"; then
            echo ""
            echo "  To set up automatic updates:"
            echo "    sudo crontab -u ${SERVICE_USER} -e"
            echo "    Add:"
            echo "      0 3 * * * ${INSTALL_DIR}/scripts/update_asn_db.sh >> /var/log/cloakprobe/asn-update.log 2>&1"
            echo "      0 4 * * * ${INSTALL_DIR}/scripts/update_ripe_db.sh >> /var/log/cloakprobe/ripe-update.log 2>&1"
        fi
    else
        echo "  ⚠️  crontab not found, automatic updates not configured"
    fi
    echo ""
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Command line options:"
    echo "  ${INSTALL_DIR}/cloakprobe --help"
    echo "  ${INSTALL_DIR}/cloakprobe -c /path/to/config.toml"
    echo ""
}

# Main installation process
main() {
    log_info "CloakProbe Installation Script"
    log_info "=============================="
    echo ""
    
    check_root
    check_os
    
    # Detect architecture
    ARCH=$(detect_arch)
    log_info "Detected architecture: ${ARCH}"
    
    # Get latest release
    log_info "Fetching latest release..."
    VERSION=$(get_latest_release "${GITHUB_REPO}")
    if [[ -z "${VERSION}" ]]; then
        log_error "Failed to fetch latest release"
        exit 1
    fi
    log_info "Latest version: ${VERSION}"
    
    # Download release
    download_release "${GITHUB_REPO}" "${VERSION}" "${ARCH}"
    
    # Install
    install_binary
    create_user
    setup_permissions
    install_systemd_service
    setup_asn_database
    enable_service
    setup_cron
    
    # Summary
    print_summary
}

# Run main function
main "$@"

