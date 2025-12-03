#!/bin/bash
set -euo pipefail

# Build Release Script
# This script builds release binaries for multiple architectures and creates the ASN database

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

BINARY_NAME="cloakprobe"
BUILDER_BINARY="asn_builder"
RIPE_BUILDER_BINARY="ripe_builder"
VERSION="${1:-$(git describe --tags --always || echo 'dev')}"
BUILD_DIR="target/release"
RELEASE_DIR="release"
TEMP_DATA_DIR="${RELEASE_DIR}/temp_data"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v gunzip &> /dev/null; then
        log_error "gunzip is required but not installed"
        exit 1
    fi
}

# Build ASN database
build_asn_database() {
    log_info "Building ASN database..."
    
    # Create temp data directory
    mkdir -p "${TEMP_DATA_DIR}"
    
    # Download ip2asn database
    local date=$(date +%Y%m%d)
    local ip2asn_url="https://iptoasn.com/data/ip2asn-combined.tsv.gz"
    local combined_gz="${TEMP_DATA_DIR}/ip2asn-combined-${date}.tsv.gz"
    local combined_tsv="${TEMP_DATA_DIR}/ip2asn-combined-${date}.tsv"
    local asn_db="${TEMP_DATA_DIR}/asn_db.bin"
    
    log_info "Downloading ip2asn database..."
    if ! curl -sSf "${ip2asn_url}" -o "${combined_gz}"; then
        log_error "Failed to download ip2asn database"
        exit 1
    fi
    
    log_info "Decompressing database..."
    gunzip -c "${combined_gz}" > "${combined_tsv}"
    
    # Build builders if not exists
    if [[ ! -f "${BUILD_DIR}/${BUILDER_BINARY}" ]]; then
        log_info "Building asn_builder..."
        cargo build --release --bin "${BUILDER_BINARY}"
    fi
    
    if [[ ! -f "${BUILD_DIR}/${RIPE_BUILDER_BINARY}" ]]; then
        log_info "Building ripe_builder..."
        cargo build --release --bin "${RIPE_BUILDER_BINARY}"
    fi
    
    # Copy builders to release directory for packaging
    if [[ -f "${BUILD_DIR}/${BUILDER_BINARY}" ]]; then
        cp "${BUILD_DIR}/${BUILDER_BINARY}" "${RELEASE_DIR}/${BUILDER_BINARY}"
        log_info "asn_builder binary ready for packaging"
    fi
    
    if [[ -f "${BUILD_DIR}/${RIPE_BUILDER_BINARY}" ]]; then
        cp "${BUILD_DIR}/${RIPE_BUILDER_BINARY}" "${RELEASE_DIR}/${RIPE_BUILDER_BINARY}"
        log_info "ripe_builder binary ready for packaging"
    fi
    
    # Build ASN database
    log_info "Generating ASN database..."
    "${BUILD_DIR}/${BUILDER_BINARY}" "${combined_tsv}" "${asn_db}"
    
    if [[ ! -f "${asn_db}" ]]; then
        log_error "Failed to create ASN database"
        exit 1
    fi
    
    log_info "ASN database created: ${asn_db}"
    log_info "Database size: $(du -h "${asn_db}" | cut -f1)"
}

# Cleanup temp files
cleanup_temp() {
    log_info "Cleaning up temporary files..."
    rm -rf "${TEMP_DATA_DIR}"
}

# Architectures to build
ARCHITECTURES=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
)

# Check if rustup is installed
if ! command -v rustup &> /dev/null; then
    log_warn "rustup not found. Installing targets manually..."
fi

# Check dependencies
check_dependencies

# Create release directory
mkdir -p "${RELEASE_DIR}"

# Build ASN database first (only once, architecture-independent)
build_asn_database

# Build for each architecture
for arch in "${ARCHITECTURES[@]}"; do
    log_info "Building ${BINARY_NAME} for ${arch}..."
    
    # Add target if needed
    if command -v rustup &> /dev/null; then
        rustup target add "${arch}" 2>/dev/null || true
    fi
    
    # Build
    if [[ "${arch}" == "x86_64-unknown-linux-gnu" ]]; then
        # Native build (already built for ASN DB)
        if [[ ! -f "${BUILD_DIR}/${BINARY_NAME}" ]]; then
            cargo build --release
        fi
        cp "${BUILD_DIR}/${BINARY_NAME}" "${RELEASE_DIR}/${BINARY_NAME}-${arch}"
    else
        # Cross-compilation (requires cross)
        if command -v cross &> /dev/null; then
            cross build --release --target "${arch}"
            cp "target/${arch}/release/${BINARY_NAME}" "${RELEASE_DIR}/${BINARY_NAME}-${arch}"
        else
            log_warn "cross not installed, skipping ${arch}"
            log_warn "Install with: cargo install cross --git https://github.com/cross-rs/cross"
            continue
        fi
    fi
    
    # Create release package structure
    log_info "Creating release package for ${arch}..."
    local package_dir="${RELEASE_DIR}/package-${arch}"
    mkdir -p "${package_dir}/data"
    mkdir -p "${package_dir}/scripts"
    
    # Copy binary
    cp "${RELEASE_DIR}/${BINARY_NAME}-${arch}" "${package_dir}/${BINARY_NAME}"
    chmod +x "${package_dir}/${BINARY_NAME}"
    
    # Copy builder binaries (same for all architectures, built on host)
    if [[ -f "${RELEASE_DIR}/${BUILDER_BINARY}" ]]; then
        cp "${RELEASE_DIR}/${BUILDER_BINARY}" "${package_dir}/${BUILDER_BINARY}"
        chmod +x "${package_dir}/${BUILDER_BINARY}"
    fi
    
    if [[ -f "${RELEASE_DIR}/${RIPE_BUILDER_BINARY}" ]]; then
        cp "${RELEASE_DIR}/${RIPE_BUILDER_BINARY}" "${package_dir}/${RIPE_BUILDER_BINARY}"
        chmod +x "${package_dir}/${RIPE_BUILDER_BINARY}"
    fi
    
    # Copy ASN database
    cp "${TEMP_DATA_DIR}/asn_db.bin" "${package_dir}/data/asn_db.bin"
    
    # Copy service file
    if [[ -f "cloakprobe.service" ]]; then
        cp "cloakprobe.service" "${package_dir}/"
    fi
    
    # Copy update scripts
    if [[ -f "scripts/update_asn_db.sh" ]]; then
        cp "scripts/update_asn_db.sh" "${package_dir}/scripts/"
        chmod +x "${package_dir}/scripts/update_asn_db.sh"
    fi
    
    if [[ -f "scripts/update_ripe_db.sh" ]]; then
        cp "scripts/update_ripe_db.sh" "${package_dir}/scripts/"
        chmod +x "${package_dir}/scripts/update_ripe_db.sh"
    fi
    
    # Create tarball
    log_info "Creating tarball for ${arch}..."
    cd "${package_dir}"
    tar -czf "../${BINARY_NAME}-${arch}.tar.gz" .
    cd - > /dev/null
    
    # Cleanup package directory
    rm -rf "${package_dir}"
    
    log_info "Built: ${RELEASE_DIR}/${BINARY_NAME}-${arch}.tar.gz"
done

# Cleanup temp files
cleanup_temp

log_info "Build complete!"
log_info "Release files are in: ${RELEASE_DIR}/"
log_info ""
log_info "Release packages include:"
log_info "  - ${BINARY_NAME} binary"
log_info "  - ASN database (data/asn_db.bin)"
log_info "  - Builder binaries (asn_builder, ripe_builder)"
log_info "  - Systemd service file"
log_info "  - Database update scripts (ASN, RIPE)"
log_info ""
log_info "To create a GitHub release:"
log_info "  gh release create v${VERSION} ${RELEASE_DIR}/*.tar.gz --title \"CloakProbe ${VERSION}\" --notes \"Release ${VERSION}\""
