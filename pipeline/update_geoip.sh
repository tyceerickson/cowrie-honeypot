#!/bin/bash
# update_geoip.sh — MaxMind GeoLite2 Database Updater
# =====================================================
# Downloads fresh GeoLite2-City and GeoLite2-ASN databases from MaxMind.
# Runs weekly via cron every Monday at 06:00 UTC.
#
# Deployed on: Ubuntu Server (192.168.10.4)
# Cron: 0 6 * * 1 terickson /opt/geoip/update_db.sh >> /var/log/geoip-update.log 2>&1
#
# Requirements:
#   - Free MaxMind account: https://www.maxmind.com/en/geolite2/signup
#   - Account ID and License Key set below
#   - curl installed (pre-installed on Ubuntu)
#
# Output:
#   /opt/geoip/GeoLite2-City.mmdb  (63MB)
#   /opt/geoip/GeoLite2-ASN.mmdb   (12MB)

set -euo pipefail

# ============================================================
# Configuration — set these values after creating MaxMind account
# ============================================================
ACCOUNT_ID="1350638"
LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"   # Set as environment variable or replace here
GEOIP_DIR="/opt/geoip"
LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')]"

# ============================================================
# Validation
# ============================================================
if [[ -z "$LICENSE_KEY" ]]; then
    echo "$LOG_PREFIX ERROR: MAXMIND_LICENSE_KEY environment variable not set"
    echo "$LOG_PREFIX Set it with: export MAXMIND_LICENSE_KEY=your_key_here"
    echo "$LOG_PREFIX Or edit this script and replace the LICENSE_KEY value directly"
    exit 1
fi

if [[ ! -d "$GEOIP_DIR" ]]; then
    echo "$LOG_PREFIX Creating GeoIP directory: $GEOIP_DIR"
    mkdir -p "$GEOIP_DIR"
fi

cd "$GEOIP_DIR"

# ============================================================
# Download function
# ============================================================
download_db() {
    local edition="$1"
    local output_file="${edition}.tar.gz"
    local mmdb_file="${edition}.mmdb"

    echo "$LOG_PREFIX Downloading $edition..."

    # Download with redirect following
    if curl -sS -L \
        -u "${ACCOUNT_ID}:${LICENSE_KEY}" \
        "https://download.maxmind.com/geoip/databases/${edition}/download?suffix=tar.gz" \
        -o "$output_file"; then

        # Verify it's a valid gzip file
        if ! gzip -t "$output_file" 2>/dev/null; then
            echo "$LOG_PREFIX ERROR: Downloaded file is not valid gzip — check license key"
            rm -f "$output_file"
            return 1
        fi

        # Extract the .mmdb file
        tar -xzf "$output_file"
        mv -f ${edition}_*/${mmdb_file} .

        # Cleanup
        rm -rf "${edition}_*" "$output_file"

        local size
        size=$(du -sh "$mmdb_file" | cut -f1)
        echo "$LOG_PREFIX OK: $mmdb_file updated ($size)"
        return 0
    else
        echo "$LOG_PREFIX ERROR: Failed to download $edition"
        return 1
    fi
}

# ============================================================
# Main
# ============================================================
echo "$LOG_PREFIX Starting GeoIP database update..."

ERRORS=0

download_db "GeoLite2-City"  || ERRORS=$((ERRORS + 1))
download_db "GeoLite2-ASN"   || ERRORS=$((ERRORS + 1))

if [[ $ERRORS -eq 0 ]]; then
    echo "$LOG_PREFIX All databases updated successfully"
    echo "$LOG_PREFIX Files in $GEOIP_DIR:"
    ls -lh "$GEOIP_DIR"/*.mmdb 2>/dev/null || echo "$LOG_PREFIX No .mmdb files found"
    exit 0
else
    echo "$LOG_PREFIX WARNING: $ERRORS database(s) failed to update"
    exit 1
fi
