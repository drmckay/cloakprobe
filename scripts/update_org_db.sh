#!/usr/bin/env bash
set -euo pipefail

# Multi-RIR org database builder for CloakProbe (ORGS format)
#
# Steps:
#   1) Download and parse all RIR bulk data (scripts/download_rir_orgs.sh)
#      - RIPE, APNIC, AFRINIC, LACNIC: Rust RPSL parser
#      - ARIN: Rust XML parser (if bulk data available) or delegated stats fallback
#   2) Build ORGS binary via org_builder (CSV -> ORGS)
#
# Output:
#   data/orgs_db.bin - Binary ORGS database
#
# Cron example:
#   0 4 * * 0 /opt/cloakprobe/scripts/update_org_db.sh >> /var/log/cloakprobe-org-update.log 2>&1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/data"
mkdir -p "$DATA_DIR"

echo "=========================================="
echo "[*] CloakProbe Multi-RIR Organization DB Builder"
echo "[*] $(date)"
echo "=========================================="
echo ""
echo "[*] ROOT_DIR: ${ROOT_DIR}"
echo "[*] DATA_DIR: ${DATA_DIR}"

CSV_PATH="${DATA_DIR}/orgs_merged.csv"
ORG_DB_BIN="${DATA_DIR}/orgs_db.bin"

# 1) Download + parse all RIR data -> merged CSV
echo ""
echo "[*] Step 1: Download and parse RIR data"
echo "=========================================="
"${ROOT_DIR}/scripts/download_rir_orgs.sh"

# Verify CSV was created
if [ ! -f "${CSV_PATH}" ] || [ ! -s "${CSV_PATH}" ]; then
    echo "[ERROR] Merged CSV not found or empty: ${CSV_PATH}"
    exit 1
fi

CSV_ROWS=$(wc -l < "${CSV_PATH}")
echo ""
echo "[*] Merged CSV: ${CSV_PATH}"
echo "[*] Total rows: ${CSV_ROWS}"

# 2) Build ORGS binary from CSV (with ip2asn fallback for missing ASNs)
echo ""
echo "[*] Step 2: Build ORGS binary database"
echo "=========================================="

BUILDER_BIN="${ROOT_DIR}/target/release/org_builder"
IP2ASN_TSV="${DATA_DIR}/ip2asn-combined.tsv"

if [ ! -x "${BUILDER_BIN}" ]; then
    echo "[*] Building org_builder..."
    cargo build --manifest-path "${ROOT_DIR}/Cargo.toml" --bin org_builder --release
fi

# Check if ip2asn TSV exists for fallback coverage
if [ -f "${IP2ASN_TSV}" ]; then
    echo "[*] Using ip2asn fallback for missing ASNs: ${IP2ASN_TSV}"
    echo "[*] Running: org_builder ${CSV_PATH} ${ORG_DB_BIN} --fallback ${IP2ASN_TSV}"
    "${BUILDER_BIN}" "${CSV_PATH}" "${ORG_DB_BIN}" --fallback "${IP2ASN_TSV}"
else
    echo "[WARN] ip2asn TSV not found at ${IP2ASN_TSV} - some ASNs may not have org data"
    echo "[WARN] Run scripts/update_asn_db.sh first to enable fallback coverage"
    echo "[*] Running: org_builder ${CSV_PATH} ${ORG_DB_BIN}"
    "${BUILDER_BIN}" "${CSV_PATH}" "${ORG_DB_BIN}"
fi

# Verify output
if [ ! -f "${ORG_DB_BIN}" ] || [ ! -s "${ORG_DB_BIN}" ]; then
    echo "[ERROR] ORGS database not created: ${ORG_DB_BIN}"
    exit 1
fi

ORG_DB_SIZE=$(stat -c%s "${ORG_DB_BIN}" 2>/dev/null || stat -f%z "${ORG_DB_BIN}")
echo ""
echo "=========================================="
echo "[*] Summary"
echo "=========================================="
echo "[*] ORGS DB: ${ORG_DB_BIN}"
echo "[*] Size: ${ORG_DB_SIZE} bytes"
echo "[*] CSV rows: ${CSV_ROWS}"
echo "[*] Completed: $(date)"
echo ""

# Optional: cleanup temp files
if [ "${CLEANUP:-0}" = "1" ]; then
    echo "[*] Cleaning up temp files..."
    rm -rf "${DATA_DIR}/orgs_tmp"
fi

echo "[*] Done."
