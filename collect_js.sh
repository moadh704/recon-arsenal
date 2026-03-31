#!/bin/bash

# ----------------------------
# JS Collector for Recon Arsenal
# Usage: ./collect_js.sh <domain> [results_base_dir]
# Example: ./collect_js.sh bild.de ~/bugbounty/results
# ----------------------------

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Help message
if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 <domain> [results_base_dir]"
    echo "  <domain>          Target domain (e.g., bild.de)"
    echo "  [results_base_dir] Optional base directory for results (default: ~/bugbounty/results)"
    exit 0
fi

# Check for required tools
for tool in katana gau waybackurls; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}[!] Error: $tool not found. Please run setup.sh first.${NC}"
        exit 1
    fi
done

# Arguments
DOMAIN="$1"
BASE_DIR="${2:-$HOME/bugbounty/results}"
TARGET_DIR="$BASE_DIR/$DOMAIN"
LIVE_URLS_FILE="$TARGET_DIR/hosts/live_urls.txt"
JS_OUTPUT_DIR="$TARGET_DIR/js"
JS_OUTPUT_FILE="$JS_OUTPUT_DIR/js_files.txt"
TEMP_DIR=$(mktemp -d)

echo -e "${GREEN}[+] Starting JS collection for $DOMAIN${NC}"
echo -e "${YELLOW}[+] Results will be saved to $JS_OUTPUT_FILE${NC}"

# Create output directory
mkdir -p "$JS_OUTPUT_DIR"

# Function to collect URLs from a source
collect() {
    local source_name="$1"
    local command="$2"
    echo -e "${GREEN}[+] Running $source_name...${NC}"
    eval "$command" 2>/dev/null || true
}

# Step 1: Katana (crawl from live URLs if available, else from domain)
if [[ -f "$LIVE_URLS_FILE" ]]; then
    echo -e "${YELLOW}[+] Using existing live URLs from $LIVE_URLS_FILE${NC}"
    KATANA_CMD="cat '$LIVE_URLS_FILE' | katana -jc -silent -d 5"
else
    echo -e "${YELLOW}[!] No live URLs file found. Using subdomain discovery for $DOMAIN...${NC}"
    # Optionally run subfinder to get subdomains (adjust as needed)
    subfinder -d "$DOMAIN" -silent > "$TEMP_DIR/subdomains.txt" 2>/dev/null || true
    if [[ ! -s "$TEMP_DIR/subdomains.txt" ]]; then
        echo -e "${YELLOW}[!] No subdomains found. Falling back to domain only.${NC}"
        echo "$DOMAIN" > "$TEMP_DIR/subdomains.txt"
    fi
    KATANA_CMD="cat '$TEMP_DIR/subdomains.txt' | katana -jc -silent -d 5"
fi

# Step 2: GAU (get all URLs from multiple sources)
GAU_CMD="gau --subs '$DOMAIN'"

# Step 3: Waybackurls (just Wayback Machine)
WAYBACK_CMD="waybackurls '$DOMAIN'"

# Optional: hakrawler if installed
if command -v hakrawler &> /dev/null; then
    if [[ -f "$LIVE_URLS_FILE" ]]; then
        HAKRAWLER_CMD="cat '$LIVE_URLS_FILE' | hakrawler -depth 2 -plain"
    else
        HAKRAWLER_CMD="echo '$DOMAIN' | hakrawler -depth 2 -plain"
    fi
else
    HAKRAWLER_CMD=""
fi

# Collect all URLs and filter for .js files
echo -e "${GREEN}[+] Collecting and filtering JS URLs...${NC}"

# Combine all sources
{
    collect "Katana" "$KATANA_CMD"
    collect "GAU" "$GAU_CMD"
    collect "Waybackurls" "$WAYBACK_CMD"
    if [[ -n "$HAKRAWLER_CMD" ]]; then
        collect "Hakrawler" "$HAKRAWLER_CMD"
    fi
} | grep -E '\.js($|\?)' | sort -u > "$TEMP_DIR/js_raw.txt"

# Convert protocol‑relative URLs (//example.com) to https://
sed -i 's|^//|https://|' "$TEMP_DIR/js_raw.txt"

# Remove any remaining `src=` prefix if present (just in case)
sed -i 's/^src=//' "$TEMP_DIR/js_raw.txt"

# Count and save
COUNT=$(wc -l < "$TEMP_DIR/js_raw.txt")
cp "$TEMP_DIR/js_raw.txt" "$JS_OUTPUT_FILE"

echo -e "${GREEN}[+] Done! Found $COUNT unique JS URLs.${NC}"
echo -e "${GREEN}[+] Output saved to $JS_OUTPUT_FILE${NC}"

# Optional: Show first few lines
if [[ $COUNT -gt 0 ]]; then
    echo -e "${YELLOW}[+] First 5 URLs:${NC}"
    head -n 5 "$JS_OUTPUT_FILE"
fi

# Clean up
rm -rf "$TEMP_DIR"