#!/usr/bin/env bash
set -euo pipefail

# Download RIR bulk data and produce a merged CSV using Rust parsers:
#   asn,as_name,org_id,org_name,country,rir,org_type,abuse_contact,last_updated
#
# Supported RIRs:
#   - RIPE    (RPSL format: aut-num + organisation)
#   - APNIC   (RPSL format: aut-num + organisation)
#   - AFRINIC (RPSL format: combined database)
#   - LACNIC  (RPSL format: combined database)
#   - ARIN    (XML format: asns.xml + orgs.xml + pocs.xml - requires registration)
#
# Output:
#   data/orgs_merged.csv
#
# Note: This is a best-effort collector; some fields may be empty.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/data"
TMP_DIR="$DATA_DIR/orgs_tmp"

mkdir -p "$DATA_DIR" "$TMP_DIR"

DATE="$(date +%Y%m%d)"
MERGED_CSV="${DATA_DIR}/orgs_merged.csv"

echo "[*] Output CSV: ${MERGED_CSV}"

# Build Rust parsers if not available
RPSL_BUILDER="${ROOT_DIR}/target/release/org_builder_rpsl"
ARIN_BUILDER="${ROOT_DIR}/target/release/org_builder_arin"

build_parser() {
    local name="$1"
    local bin="${ROOT_DIR}/target/release/${name}"
    if [ ! -x "${bin}" ]; then
        echo "[*] Building ${name}..."
        cargo build --manifest-path "${ROOT_DIR}/Cargo.toml" --bin "${name}" --release
    fi
}

build_parser "org_builder_rpsl"
build_parser "org_builder_arin"

# Clear output CSV (write header later after all data collected)
: > "${MERGED_CSV}"

#############################
# RIPE NCC
#############################
echo ""
echo "=============================="
echo "[*] RIPE NCC"
echo "=============================="
RIPE_FTP="ftp://ftp.ripe.net/ripe/dbase/split"
RIPE_AUTNUM_GZ="${TMP_DIR}/ripe.db.aut-num-${DATE}.gz"
RIPE_ORG_GZ="${TMP_DIR}/ripe.db.organisation-${DATE}.gz"
RIPE_ROLE_GZ="${TMP_DIR}/ripe.db.role-${DATE}.gz"

echo "[*] Downloading RIPE aut-num..."
curl -sSf "${RIPE_FTP}/ripe.db.aut-num.gz" -o "${RIPE_AUTNUM_GZ}"

echo "[*] Downloading RIPE organisation..."
curl -sSf "${RIPE_FTP}/ripe.db.organisation.gz" -o "${RIPE_ORG_GZ}"

echo "[*] Downloading RIPE role (for abuse contact resolution)..."
curl -sSf "${RIPE_FTP}/ripe.db.role.gz" -o "${RIPE_ROLE_GZ}" || {
    echo "[WARN] RIPE role download failed, continuing without role resolution..."
    RIPE_ROLE_GZ=""
}

echo "[*] Parsing RIPE data..."
if [ -n "${RIPE_ROLE_GZ}" ] && [ -f "${RIPE_ROLE_GZ}" ] && [ -s "${RIPE_ROLE_GZ}" ]; then
    "${RPSL_BUILDER}" --aut-num "${RIPE_AUTNUM_GZ}" --organisation "${RIPE_ORG_GZ}" --role "${RIPE_ROLE_GZ}" --rir RIPE >> "${MERGED_CSV}"
else
    "${RPSL_BUILDER}" --aut-num "${RIPE_AUTNUM_GZ}" --organisation "${RIPE_ORG_GZ}" --rir RIPE >> "${MERGED_CSV}"
fi

#############################
# APNIC
#############################
echo ""
echo "=============================="
echo "[*] APNIC"
echo "=============================="
APNIC_FTP="ftp://ftp.apnic.net/apnic/whois"
APNIC_AUTNUM_GZ="${TMP_DIR}/apnic.db.aut-num-${DATE}.gz"
APNIC_ORG_GZ="${TMP_DIR}/apnic.db.organisation-${DATE}.gz"
APNIC_ROLE_GZ="${TMP_DIR}/apnic.db.role-${DATE}.gz"

echo "[*] Downloading APNIC aut-num..."
curl -sSf "${APNIC_FTP}/apnic.db.aut-num.gz" -o "${APNIC_AUTNUM_GZ}" || {
    echo "[WARN] APNIC aut-num download failed, trying alternative..."
    curl -sSf "https://ftp.apnic.net/apnic/whois/apnic.db.aut-num.gz" -o "${APNIC_AUTNUM_GZ}" || true
}

echo "[*] Downloading APNIC organisation..."
curl -sSf "${APNIC_FTP}/apnic.db.organisation.gz" -o "${APNIC_ORG_GZ}" || {
    echo "[WARN] APNIC organisation download failed, trying alternative..."
    curl -sSf "https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz" -o "${APNIC_ORG_GZ}" || true
}

echo "[*] Downloading APNIC role (for abuse contact resolution)..."
curl -sSf "${APNIC_FTP}/apnic.db.role.gz" -o "${APNIC_ROLE_GZ}" || {
    echo "[WARN] APNIC role download failed, trying alternative..."
    curl -sSf "https://ftp.apnic.net/apnic/whois/apnic.db.role.gz" -o "${APNIC_ROLE_GZ}" || {
        echo "[WARN] APNIC role not available, continuing without role resolution..."
        APNIC_ROLE_GZ=""
    }
}

if [ -f "${APNIC_AUTNUM_GZ}" ] && [ -s "${APNIC_AUTNUM_GZ}" ]; then
    echo "[*] Parsing APNIC data..."
    if [ -n "${APNIC_ROLE_GZ}" ] && [ -f "${APNIC_ROLE_GZ}" ] && [ -s "${APNIC_ROLE_GZ}" ]; then
        "${RPSL_BUILDER}" --aut-num "${APNIC_AUTNUM_GZ}" --organisation "${APNIC_ORG_GZ}" --role "${APNIC_ROLE_GZ}" --rir APNIC >> "${MERGED_CSV}" || {
            echo "[WARN] APNIC parsing failed, continuing..."
        }
    else
        "${RPSL_BUILDER}" --aut-num "${APNIC_AUTNUM_GZ}" --organisation "${APNIC_ORG_GZ}" --rir APNIC >> "${MERGED_CSV}" || {
            echo "[WARN] APNIC parsing failed, continuing..."
        }
    fi
else
    echo "[WARN] APNIC data not available, skipping..."
fi

#############################
# AFRINIC
#############################
echo ""
echo "=============================="
echo "[*] AFRINIC"
echo "=============================="
AFRINIC_FTP="ftp://ftp.afrinic.net/pub/dbase"
AFRINIC_DB_GZ="${TMP_DIR}/afrinic.db-${DATE}.gz"

echo "[*] Downloading AFRINIC database..."
curl -sSf "${AFRINIC_FTP}/afrinic.db.gz" -o "${AFRINIC_DB_GZ}" || {
    echo "[WARN] AFRINIC download failed, trying alternative..."
    curl -sSfL "https://ftp.afrinic.net/pub/dbase/afrinic.db.gz" -o "${AFRINIC_DB_GZ}" || true
}

if [ -f "${AFRINIC_DB_GZ}" ] && [ -s "${AFRINIC_DB_GZ}" ]; then
    echo "[*] Parsing AFRINIC data (combined database)..."
    "${RPSL_BUILDER}" --combined "${AFRINIC_DB_GZ}" --rir AFRINIC >> "${MERGED_CSV}" || {
        echo "[WARN] AFRINIC parsing failed, continuing..."
    }
else
    echo "[WARN] AFRINIC data not available, skipping..."
fi

#############################
# LACNIC
#############################
echo ""
echo "=============================="
echo "[*] LACNIC"
echo "=============================="
LACNIC_FTP="ftp://ftp.lacnic.net/lacnic/dbase"
LACNIC_DB_GZ="${TMP_DIR}/lacnic.db-${DATE}.gz"

echo "[*] Downloading LACNIC database..."
curl -sSf "${LACNIC_FTP}/lacnic.db.gz" -o "${LACNIC_DB_GZ}" || {
    echo "[WARN] LACNIC download failed, trying alternative..."
    curl -sSfL "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz" -o "${LACNIC_DB_GZ}" || true
}

if [ -f "${LACNIC_DB_GZ}" ] && [ -s "${LACNIC_DB_GZ}" ]; then
    echo "[*] Parsing LACNIC data (combined database)..."
    "${RPSL_BUILDER}" --combined "${LACNIC_DB_GZ}" --rir LACNIC >> "${MERGED_CSV}" || {
        echo "[WARN] LACNIC parsing failed, continuing..."
    }
else
    echo "[WARN] LACNIC data not available, skipping..."
fi

#############################
# ARIN (requires manual download or registration)
#############################
echo ""
echo "=============================="
echo "[*] ARIN"
echo "=============================="
ARIN_ASNS="${TMP_DIR}/arin-asns.xml"
ARIN_ORGS="${TMP_DIR}/arin-orgs.xml"
ARIN_POCS="${TMP_DIR}/arin-pocs.xml"

# Check if ARIN bulk files exist (user must download manually)
if [ -f "${ARIN_ASNS}" ] && [ -f "${ARIN_ORGS}" ]; then
    echo "[*] Found ARIN bulk data files"
    echo "[*] Parsing ARIN data..."
    
    if [ -f "${ARIN_POCS}" ]; then
        "${ARIN_BUILDER}" --asns "${ARIN_ASNS}" --orgs "${ARIN_ORGS}" --pocs "${ARIN_POCS}" >> "${MERGED_CSV}" || {
            echo "[WARN] ARIN parsing failed, continuing..."
        }
    else
        "${ARIN_BUILDER}" --asns "${ARIN_ASNS}" --orgs "${ARIN_ORGS}" >> "${MERGED_CSV}" || {
            echo "[WARN] ARIN parsing failed, continuing..."
        }
    fi
else
    echo "[*] ARIN bulk data not found."
    echo "[*] To include ARIN data, download from:"
    echo "    https://www.arin.net/resources/registry/whois/bulk/"
    echo "[*] Place files in: ${TMP_DIR}/"
    echo "    - arin-asns.xml"
    echo "    - arin-orgs.xml"
    echo "    - arin-pocs.xml (optional)"
    echo "[*] Falling back to delegated stats for ARIN..."
    
    # Download ARIN delegated stats as fallback
    ARIN_DELEG="${TMP_DIR}/delegated-arin.txt"
    echo "[*] Downloading ARIN delegated stats..."
    curl -sSfL "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest" -o "${ARIN_DELEG}" || true
    
    if [ -f "${ARIN_DELEG}" ] && [ -s "${ARIN_DELEG}" ]; then
        echo "[*] Parsing ARIN delegated stats..."
        # Parse delegated stats format: registry|cc|type|start|value|date|status|...
        grep "|asn|" "${ARIN_DELEG}" | while IFS='|' read -r registry cc rtype start _value date _status rest; do
            # Only include ASN records
            if [ "$rtype" = "asn" ] && [ -n "$start" ]; then
                echo "${start},,,,$cc,ARIN,,,${date}"
            fi
        done >> "${MERGED_CSV}"
    fi
fi

#############################
# Fallback: Delegated stats for missing RIRs
#############################
echo ""
echo "=============================="
echo "[*] Supplementing with delegated stats (country info for missing entries)"
echo "=============================="

DELEG_DIR="${TMP_DIR}/delegated"
mkdir -p "${DELEG_DIR}"

# Count existing ASNs to avoid duplicates
EXISTING_ASNS=$(cut -d',' -f1 "${MERGED_CSV}" 2>/dev/null | sort -u | wc -l)
echo "[*] Currently have ${EXISTING_ASNS} ASN entries"

fetch_deleg() {
    local rir="$1"
    local url="$2"
    local out="${DELEG_DIR}/delegated-${rir}.txt"
    echo "[*] Downloading delegated stats: ${rir}..."
    curl -sSfL "${url}" -o "${out}" || {
        echo "[WARN] Failed to download ${rir} delegated stats"
        return 1
    }
}

# Download delegated stats for all RIRs
fetch_deleg "ripencc" "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest" || true
fetch_deleg "apnic"   "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest" || true
fetch_deleg "afrinic" "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest" || true
fetch_deleg "lacnic"  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest" || true
fetch_deleg "arin"    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest" || true

# Create a set of existing ASNs for quick lookup
echo "[*] Building existing ASN index..."
EXISTING_ASN_FILE="${TMP_DIR}/existing_asns.txt"
cut -d',' -f1 "${MERGED_CSV}" 2>/dev/null | sort -n -u > "${EXISTING_ASN_FILE}"

# Parse delegated stats and add missing entries
echo "[*] Adding missing ASNs from delegated stats..."
ADDED_COUNT=0

for deleg_file in "${DELEG_DIR}"/delegated-*.txt; do
    if [ ! -f "$deleg_file" ]; then
        continue
    fi
    
    rir=$(basename "$deleg_file" | sed 's/delegated-\(.*\)\.txt/\1/' | tr '[:lower:]' '[:upper:]')
    
    while IFS='|' read -r registry cc rtype start _value date _status rest; do
        # Skip non-ASN records and comments
        if [ "$rtype" != "asn" ] || [ -z "$start" ] || [[ "$registry" == \#* ]]; then
            continue
        fi
        
        # Check if ASN already exists
        if grep -q "^${start}$" "${EXISTING_ASN_FILE}" 2>/dev/null; then
            continue
        fi
        
        # Add to merged CSV
        echo "${start},,,,$cc,${rir},,,${date}" >> "${MERGED_CSV}"
        echo "${start}" >> "${EXISTING_ASN_FILE}"
        ADDED_COUNT=$((ADDED_COUNT + 1))
    done < "$deleg_file"
done

echo "[*] Added ${ADDED_COUNT} ASN entries from delegated stats"

#############################
# Summary
#############################
echo ""
echo "=============================="
echo "[*] Summary"
echo "=============================="
TOTAL_ROWS=$(wc -l < "${MERGED_CSV}")
echo "[*] Total ASN entries: ${TOTAL_ROWS}"
echo "[*] Output: ${MERGED_CSV}"

# Breakdown by RIR
echo "[*] Breakdown by RIR:"
for rir in RIPE APNIC AFRINIC LACNIC ARIN RIPENCC; do
    count=$(grep -c ",${rir}," "${MERGED_CSV}" 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ]; then
        echo "    - ${rir}: ${count}"
    fi
done

echo ""
echo "[*] Done."
