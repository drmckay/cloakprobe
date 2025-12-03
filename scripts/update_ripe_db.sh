#!/usr/bin/env bash
set -euo pipefail

# RIPE Database downloader and builder for CloakProbe
#
# This script:
#   - downloads the latest RIPE database dumps (aut-num + organisation)
#   - decompresses them
#   - runs the Rust ripe_builder binary to produce data/ripe_db.bin
#
# Cron example:
#   0 4 * * * /opt/cloakprobe/scripts/update_ripe_db.sh >> /var/log/cloakprobe-ripe-update.log 2>&1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/data"
mkdir -p "$DATA_DIR"

DATE="$(date +%Y%m%d)"
RIPE_FTP="ftp://ftp.ripe.net/ripe/dbase/split"

# aut-num file (ASN -> org reference)
AUTNUM_GZ="${DATA_DIR}/ripe.db.aut-num-${DATE}.gz"
AUTNUM_TXT="${DATA_DIR}/ripe.db.aut-num-${DATE}.txt"

# organisation file (org reference -> org name)
ORG_GZ="${DATA_DIR}/ripe.db.organisation-${DATE}.gz"
ORG_TXT="${DATA_DIR}/ripe.db.organisation-${DATE}.txt"

echo "[*] Using ROOT_DIR=${ROOT_DIR}"

# Download aut-num
echo "[*] Downloading ripe.db.aut-num.gz..."
curl -sSf "${RIPE_FTP}/ripe.db.aut-num.gz" -o "${AUTNUM_GZ}"
echo "[*] Decompressing to ${AUTNUM_TXT}..."
gunzip -c "${AUTNUM_GZ}" > "${AUTNUM_TXT}"

# Download organisation
echo "[*] Downloading ripe.db.organisation.gz..."
curl -sSf "${RIPE_FTP}/ripe.db.organisation.gz" -o "${ORG_GZ}"
echo "[*] Decompressing to ${ORG_TXT}..."
gunzip -c "${ORG_GZ}" > "${ORG_TXT}"

RIPE_DB_BIN="${DATA_DIR}/ripe_db.bin"

BUILDER_BIN="${ROOT_DIR}/target/release/ripe_builder"

if [ -x "${BUILDER_BIN}" ]; then
  echo "[*] Running ${BUILDER_BIN} ${AUTNUM_TXT} ${ORG_TXT} ${RIPE_DB_BIN}..."
  "${BUILDER_BIN}" "${AUTNUM_TXT}" "${ORG_TXT}" "${RIPE_DB_BIN}"
else
  echo "[*] Running cargo run --bin ripe_builder --release ..."
  cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" --bin ripe_builder --release -- "${AUTNUM_TXT}" "${ORG_TXT}" "${RIPE_DB_BIN}"
fi

# Cleanup old files (keep last 3 days)
echo "[*] Cleaning up old files..."
find "${DATA_DIR}" -name "ripe.db.aut-num-*.txt" -mtime +3 -delete 2>/dev/null || true
find "${DATA_DIR}" -name "ripe.db.aut-num-*.gz" -mtime +3 -delete 2>/dev/null || true
find "${DATA_DIR}" -name "ripe.db.organisation-*.txt" -mtime +3 -delete 2>/dev/null || true
find "${DATA_DIR}" -name "ripe.db.organisation-*.gz" -mtime +3 -delete 2>/dev/null || true

echo "[*] Files in ${DATA_DIR}:"
ls -lh "${DATA_DIR}" | grep -E "(ripe|asn)" || true

echo "[*] Done. RIPE DB: ${RIPE_DB_BIN}"
