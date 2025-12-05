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
SERVICE_USER="cloakprobe"
SERVICE_GROUP="cloakprobe"
GITHUB_REPO="drmckay/cloakprobe"
BINARY_NAME="cloakprobe"
BUILDER_BINARY="asn_builder"
RIPE_BUILDER_BINARY="ripe_builder"
SERVICE_FILE="systemd/cloakprobe.service"

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
            echo "x86_64-unknown-linux-gnu"
            ;;
        aarch64|arm64)
            echo "aarch64-unknown-linux-gnu"
            ;;
        armv7l)
            echo "armv7-unknown-linux-gnueabihf"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
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
    local download_url="https://github.com/${repo}/releases/download/${version}/${BINARY_NAME}-${arch}.tar.gz"
    
    log_info "Downloading release ${version} for ${arch}..."
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
    
    # Extract archive to temp directory
    local temp_extract="/tmp/cloakprobe_extract"
    mkdir -p "${temp_extract}"
    tar -xzf /tmp/cloakprobe.tar.gz -C "${temp_extract}"
    
    # Copy binary
    if [[ -f "${temp_extract}/${BINARY_NAME}" ]]; then
        cp "${temp_extract}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
        log_info "Binary installed"
    else
        log_error "Binary not found in archive"
        exit 1
    fi
    
    # Copy ASN database if it exists
    if [[ -f "${temp_extract}/data/asn_db.bin" ]]; then
        cp "${temp_extract}/data/asn_db.bin" "${INSTALL_DIR}/data/asn_db.bin"
        log_info "ASN database installed"
    else
        log_warn "ASN database not found in archive"
    fi
    
    # Copy service file if it exists
    if [[ -f "${temp_extract}/${SERVICE_FILE}" ]]; then
        cp "${temp_extract}/${SERVICE_FILE}" "${INSTALL_DIR}/${SERVICE_FILE}"
        log_info "Service file installed"
    fi
    
    # Copy builder binaries if they exist
    if [[ -f "${temp_extract}/${BUILDER_BINARY}" ]]; then
        cp "${temp_extract}/${BUILDER_BINARY}" "${INSTALL_DIR}/${BUILDER_BINARY}"
        chmod +x "${INSTALL_DIR}/${BUILDER_BINARY}"
        log_info "asn_builder binary installed"
    fi
    
    if [[ -f "${temp_extract}/${RIPE_BUILDER_BINARY}" ]]; then
        cp "${temp_extract}/${RIPE_BUILDER_BINARY}" "${INSTALL_DIR}/${RIPE_BUILDER_BINARY}"
        chmod +x "${INSTALL_DIR}/${RIPE_BUILDER_BINARY}"
        log_info "ripe_builder binary installed"
    fi
    
    # Copy update scripts if they exist
    if [[ -f "${temp_extract}/scripts/update_asn_db.sh" ]]; then
        cp "${temp_extract}/scripts/update_asn_db.sh" "${INSTALL_DIR}/scripts/update_asn_db.sh"
        chmod +x "${INSTALL_DIR}/scripts/update_asn_db.sh"
        log_info "ASN update script installed"
    fi
    
    if [[ -f "${temp_extract}/scripts/update_ripe_db.sh" ]]; then
        cp "${temp_extract}/scripts/update_ripe_db.sh" "${INSTALL_DIR}/scripts/update_ripe_db.sh"
        chmod +x "${INSTALL_DIR}/scripts/update_ripe_db.sh"
        log_info "RIPE organization update script installed"
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
    chmod 755 "${INSTALL_DIR}"
    chmod 755 "${INSTALL_DIR}/data"
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
        cp "${service_path}" "/etc/systemd/system/${SERVICE_FILE}"
        systemctl daemon-reload
        log_info "Service installed"
    else
        log_error "Service file not found: ${service_path}"
        exit 1
    fi
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
    
    # Check if ASN database was installed
    if [[ -f "${INSTALL_DIR}/data/asn_db.bin" ]]; then
        echo "✅ ASN database is already included in the release"
    else
        echo "⚠️  ASN database not found"
        echo "   1. Download ASN database:"
        echo "      ${INSTALL_DIR}/scripts/update_asn_db.sh"
        echo ""
    fi
    
    echo "Next steps:"
    if [[ ! -f "${INSTALL_DIR}/data/asn_db.bin" ]]; then
        echo "  1. Download ASN database (if not already done):"
        echo "     ${INSTALL_DIR}/scripts/update_asn_db.sh"
        echo ""
        echo "  2. (Optional) Download RIPE organization database:"
        echo "     ${INSTALL_DIR}/scripts/update_ripe_db.sh"
        echo ""
        echo "  3. Configure environment variables (if needed):"
    else
        echo "  1. (Optional) Download RIPE organization database:"
        echo "     ${INSTALL_DIR}/scripts/update_ripe_db.sh"
        echo ""
        echo "  2. Configure environment variables (if needed):"
    fi
    echo "     Edit /etc/systemd/system/${SERVICE_FILE}"
    echo ""
    echo "     Note: Starting with v0.1.1, databases are automatically detected"
    echo "     in the data/ directory if environment variables are not set."
    echo ""
    if [[ ! -f "${INSTALL_DIR}/data/asn_db.bin" ]]; then
        echo "  4. Start the service:"
        echo "     sudo systemctl start ${SERVICE_FILE}"
        echo ""
        echo "  5. Check status:"
        echo "     sudo systemctl status ${SERVICE_FILE}"
        echo ""
        echo "  6. View logs:"
        echo "     sudo journalctl -u ${SERVICE_FILE} -f"
        echo ""
        echo "  7. Enable auto-start on boot:"
        echo "     sudo systemctl enable ${SERVICE_FILE}"
    else
        echo "  3. Start the service:"
        echo "     sudo systemctl start ${SERVICE_FILE}"
        echo ""
        echo "  4. Check status:"
        echo "     sudo systemctl status ${SERVICE_FILE}"
        echo ""
        echo "  5. View logs:"
        echo "     sudo journalctl -u ${SERVICE_FILE} -f"
        echo ""
        echo "  6. Enable auto-start on boot:"
        echo "     sudo systemctl enable ${SERVICE_FILE}"
    fi
    echo ""
    
    # Check if cron was set up
    echo ""
    echo "Automatic database updates:"
    if command -v crontab &> /dev/null; then
        if crontab -u "${SERVICE_USER}" -l 2>/dev/null | grep -q "${INSTALL_DIR}/scripts/update_asn_db.sh"; then
            echo "✅ ASN database updates configured (daily at 3:00 AM)"
            echo "   View logs: sudo tail -f /var/log/cloakprobe/asn-update.log"
        else
            echo "⚠️  ASN database updates not configured"
        fi
        
        if crontab -u "${SERVICE_USER}" -l 2>/dev/null | grep -q "${INSTALL_DIR}/scripts/update_ripe_db.sh"; then
            echo "✅ RIPE organization database updates configured (daily at 4:00 AM)"
            echo "   View logs: sudo tail -f /var/log/cloakprobe/ripe-update.log"
        else
            echo "⚠️  RIPE organization database updates not configured"
        fi
        
        if ! crontab -u "${SERVICE_USER}" -l 2>/dev/null | grep -q "${INSTALL_DIR}/scripts/update"; then
            echo ""
            echo "   To set up manually:"
            echo "     sudo crontab -u ${SERVICE_USER} -e"
            echo "     Add:"
            echo "       0 3 * * * ${INSTALL_DIR}/scripts/update_asn_db.sh >> /var/log/cloakprobe/asn-update.log 2>&1"
            echo "       0 4 * * * ${INSTALL_DIR}/scripts/update_ripe_db.sh >> /var/log/cloakprobe/ripe-update.log 2>&1"
        fi
    else
        echo "⚠️  crontab not found, automatic updates not configured"
    fi
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

