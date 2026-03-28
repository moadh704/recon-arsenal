#!/bin/bash
# ============================================================
#  1_RECON.SH — Full Recon Pipeline
#  Usage: ./1_recon.sh <domain> [output_dir]
#  Example: ./1_recon.sh example.com ./results
# ============================================================

set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━${NC}"; }
die()     { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# ── Args ──────────────────────────────────────────────────
[[ $# -lt 1 ]] && die "Usage: $0 <domain> [output_dir]"
DOMAIN="$1"
OUT="${2:-./results/$DOMAIN}"
THREADS=50
TIMEOUT=10

mkdir -p "$OUT"/{subdomains,hosts,ports,screenshots,js,endpoints,vulns}

START=$(date +%s)
echo -e "${BOLD}╔══════════════════════════════════════╗"
echo -e "║  Bug Bounty Recon — $DOMAIN"
echo -e "╚══════════════════════════════════════╝${NC}"
info "Output dir: $OUT"
info "Started: $(date)"

# ══════════════════════════════════════
# STEP 1 — SUBDOMAIN ENUMERATION
# ══════════════════════════════════════
section "STEP 1: Subdomain Enumeration"

# Subfinder (passive)
info "Running subfinder..."
subfinder -d "$DOMAIN" -silent -o "$OUT/subdomains/subfinder.txt" 2>/dev/null || warn "subfinder failed"

# Amass passive (if installed)
if command -v amass &>/dev/null; then
  info "Running amass (passive)..."
  amass enum -passive -d "$DOMAIN" -o "$OUT/subdomains/amass.txt" 2>/dev/null || warn "amass failed"
fi

# Certificate transparency (crt.sh)
info "Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' \
  | sort -u > "$OUT/subdomains/crtsh.txt" || warn "crt.sh query failed"

# DNS brute force
info "DNS brute forcing..."
dnsx -d "$DOMAIN" \
  -w ~/wordlists/subdomains-top1million-20000.txt \
  -silent -o "$OUT/subdomains/bruteforce.txt" 2>/dev/null || warn "dnsx bruteforce failed"

# Combine and deduplicate
info "Merging subdomain results..."
cat "$OUT"/subdomains/*.txt 2>/dev/null \
  | sort -u \
  | grep -E "^[a-zA-Z0-9._-]+\.$DOMAIN$" \
  > "$OUT/subdomains/all_subdomains.txt"

TOTAL_SUBS=$(wc -l < "$OUT/subdomains/all_subdomains.txt")
info "Total unique subdomains: ${BOLD}$TOTAL_SUBS${NC}"

# ══════════════════════════════════════
# STEP 2 — HTTP PROBING
# ══════════════════════════════════════
section "STEP 2: HTTP Probing (find live hosts)"

info "Probing subdomains with httpx..."
httpx \
  -l "$OUT/subdomains/all_subdomains.txt" \
  -silent \
  -threads "$THREADS" \
  -timeout "$TIMEOUT" \
  -status-code \
  -title \
  -tech-detect \
  -follow-redirects \
  -o "$OUT/hosts/live_hosts_full.txt" \
  -json -o "$OUT/hosts/live_hosts.json" 2>/dev/null || warn "httpx failed"

# Extract just the URLs
jq -r '.url' "$OUT/hosts/live_hosts.json" 2>/dev/null \
  | sort -u > "$OUT/hosts/live_urls.txt"

LIVE=$(wc -l < "$OUT/hosts/live_urls.txt")
info "Live hosts found: ${BOLD}$LIVE${NC}"

# Group by status code for quick overview
info "Status code summary:"
jq -r '.status_code' "$OUT/hosts/live_hosts.json" 2>/dev/null \
  | sort | uniq -c | sort -rn \
  | awk '{printf "    HTTP %s — %s hosts\n", $2, $1}'

# ══════════════════════════════════════
# STEP 3 — PORT SCANNING
# ══════════════════════════════════════
section "STEP 3: Port Scanning"

info "Running naabu port scan on live hosts..."
# Extract just hostnames for port scanning
jq -r '.host' "$OUT/hosts/live_hosts.json" 2>/dev/null \
  | sort -u > "$OUT/ports/hosts_for_portscan.txt"

naabu \
  -l "$OUT/ports/hosts_for_portscan.txt" \
  -top-ports 1000 \
  -silent \
  -o "$OUT/ports/open_ports.txt" 2>/dev/null || warn "naabu failed"

# Flag interesting ports
info "Interesting ports found:"
grep -E ":(21|22|23|25|110|143|445|1433|3306|3389|5432|6379|8080|8443|9200|27017)" \
  "$OUT/ports/open_ports.txt" 2>/dev/null \
  | tee "$OUT/ports/interesting_ports.txt" \
  || info "  None found"

# ══════════════════════════════════════
# STEP 4 — SCREENSHOTS
# ══════════════════════════════════════
section "STEP 4: Screenshots"

if command -v gowitness &>/dev/null; then
  info "Taking screenshots with gowitness..."
  gowitness file \
    -f "$OUT/hosts/live_urls.txt" \
    --screenshot-path "$OUT/screenshots" \
    --threads 10 2>/dev/null || warn "gowitness failed"
elif command -v aquatone &>/dev/null; then
  info "Taking screenshots with aquatone..."
  cat "$OUT/hosts/live_urls.txt" \
    | aquatone -out "$OUT/screenshots" -threads 10 2>/dev/null || warn "aquatone failed"
else
  warn "No screenshot tool found (install gowitness or aquatone)"
fi

# ══════════════════════════════════════
# STEP 5 — ENDPOINT DISCOVERY
# ══════════════════════════════════════
section "STEP 5: Endpoint Discovery"

# Wayback Machine / GAU
info "Fetching historical URLs (gau + waybackurls)..."
cat "$OUT/hosts/live_urls.txt" | while read url; do
  host=$(echo "$url" | awk -F/ '{print $3}')
  gau "$host" 2>/dev/null
  waybackurls "$host" 2>/dev/null
done | sort -u > "$OUT/endpoints/historical_urls.txt"

HIST=$(wc -l < "$OUT/endpoints/historical_urls.txt")
info "Historical URLs: ${BOLD}$HIST${NC}"

# Katana crawler
info "Crawling live hosts with katana..."
katana \
  -l "$OUT/hosts/live_urls.txt" \
  -depth 3 \
  -jc \
  -silent \
  -o "$OUT/endpoints/crawled_urls.txt" 2>/dev/null || warn "katana failed"

# Combine endpoints
cat "$OUT/endpoints/historical_urls.txt" \
    "$OUT/endpoints/crawled_urls.txt" 2>/dev/null \
  | sort -u > "$OUT/endpoints/all_urls.txt"

ALL_EP=$(wc -l < "$OUT/endpoints/all_urls.txt")
info "Total endpoints: ${BOLD}$ALL_EP${NC}"

# Filter URLs with parameters (juicy for fuzzing)
grep "?" "$OUT/endpoints/all_urls.txt" \
  | sort -u > "$OUT/endpoints/urls_with_params.txt"

PARAMS=$(wc -l < "$OUT/endpoints/urls_with_params.txt")
info "URLs with parameters: ${BOLD}$PARAMS${NC}"

# ══════════════════════════════════════
# STEP 6 — JS FILE EXTRACTION
# ══════════════════════════════════════
section "STEP 6: JS File Collection"

info "Extracting JS files..."
grep -E "\.js(\?|$)" "$OUT/endpoints/all_urls.txt" \
  | sort -u > "$OUT/js/js_files.txt"

JS_COUNT=$(wc -l < "$OUT/js/js_files.txt")
info "JS files found: ${BOLD}$JS_COUNT${NC}"
info "Run 3_js_analyzer.py on $OUT/js/js_files.txt for deep analysis"

# ══════════════════════════════════════
# SUMMARY REPORT
# ══════════════════════════════════════
section "RECON SUMMARY"

END=$(date +%s)
ELAPSED=$((END - START))
MINS=$((ELAPSED / 60))
SECS=$((ELAPSED % 60))

cat > "$OUT/recon_summary.txt" << EOF
╔══════════════════════════════════════════════╗
║         RECON SUMMARY — $DOMAIN
╚══════════════════════════════════════════════╝
Date        : $(date)
Duration    : ${MINS}m ${SECS}s

Subdomains  : $TOTAL_SUBS
Live Hosts  : $LIVE
Endpoints   : $ALL_EP
  w/ Params : $PARAMS
JS Files    : $JS_COUNT

Output Dir  : $OUT
EOF

cat "$OUT/recon_summary.txt"
info "Recon complete! Next: run 2_scan.sh and 3_js_analyzer.py"
