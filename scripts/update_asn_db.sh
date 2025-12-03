#!/usr/bin/env bash
set -euo pipefail

# ASN DB generator for CloakProbe using ip2asn-combined.tsv.gz
#
# This script:
#   - downloads the latest ip2asn-combined.tsv.gz (IPv4+IPv6 → ASN) from iptoasn.com
#   - decompresses it to data/ip2asn-combined-<DATE>.tsv
#   - runs the Rust asn_builder binary to produce data/asn_db.bin
#
# Cron example:
#   0 3 * * * /opt/cloakprobe/scripts/update_asn_db.sh >> /var/log/cloakprobe-asn-update.log 2>&1

# Determine root directory
# If run from installed location, use that; otherwise use script location
if [[ -d "/opt/cloakprobe" ]] && [[ -f "/opt/cloakprobe/cloakprobe" ]]; then
    ROOT_DIR="/opt/cloakprobe"
else
    ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

DATA_DIR="$ROOT_DIR/data"
mkdir -p "$DATA_DIR"

DATE="$(date +%Y%m%d)"
IP2ASN_URL="https://iptoasn.com/data/ip2asn-combined.tsv.gz"

COMBINED_GZ="${DATA_DIR}/ip2asn-combined-${DATE}.tsv.gz"
COMBINED_TSV="${DATA_DIR}/ip2asn-combined-${DATE}.tsv"

echo "[*] Using ROOT_DIR=${ROOT_DIR}"
echo "[*] Downloading ip2asn-combined.tsv.gz from ${IP2ASN_URL}..."
curl -sSf "${IP2ASN_URL}" -o "${COMBINED_GZ}"

echo "[*] Decompressing to ${COMBINED_TSV}..."
gunzip -c "${COMBINED_GZ}" > "${COMBINED_TSV}"

ASN_DB_BIN="${DATA_DIR}/asn_db.bin"

# Try to find asn_builder binary
BUILDER_BIN=""
if [ -x "${ROOT_DIR}/target/release/asn_builder" ]; then
  BUILDER_BIN="${ROOT_DIR}/target/release/asn_builder"
elif [ -x "${ROOT_DIR}/asn_builder" ]; then
  BUILDER_BIN="${ROOT_DIR}/asn_builder"
elif command -v asn_builder &> /dev/null; then
  BUILDER_BIN="asn_builder"
fi

if [ -n "${BUILDER_BIN}" ] && [ -x "${BUILDER_BIN}" ]; then
  echo "[*] Running ${BUILDER_BIN} ${COMBINED_TSV} ${ASN_DB_BIN}..."
  "${BUILDER_BIN}" "${COMBINED_TSV}" "${ASN_DB_BIN}"
elif command -v cargo &> /dev/null && [ -f "${ROOT_DIR}/Cargo.toml" ]; then
  echo "[*] Running cargo run --bin asn_builder --release ..."
  cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" --bin asn_builder --release -- "${COMBINED_TSV}" "${ASN_DB_BIN}"
else
  echo "[ERROR] asn_builder binary not found and cargo not available"
  echo "[ERROR] Cannot build ASN database"
  exit 1
fi

echo "[*] Files in ${DATA_DIR}:"
ls -lh "${DATA_DIR}"

echo "[*] Done. ASN DB: ${ASN_DB_BIN}"
