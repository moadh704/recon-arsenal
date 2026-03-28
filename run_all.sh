#!/bin/bash
# ============================================================
#  RUN_ALL.SH — Full Bug Bounty Pipeline
#  Usage: ./run_all.sh <domain> [--notify discord_webhook_url]
#
#  Runs ALL scripts in sequence:
#   1_recon.sh → 2_scan.sh → 3_js_analyzer.py →
#   4_param_discovery.py → 6_takeover.py → 7_report.py
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}══════════════════════════════${NC}"; 
            echo -e "${CYAN}${BOLD}  $1${NC}";
            echo -e "${CYAN}${BOLD}══════════════════════════════${NC}\n"; }
die()     { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# ── Parse args ────────────────────────────────────────────
[[ $# -lt 1 ]] && die "Usage: $0 <domain> [--notify <discord_webhook>] [--skip-scan] [--only-recon]"

DOMAIN=""
DISCORD_WEBHOOK=""
SKIP_SCAN=false
ONLY_RECON=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --notify)  DISCORD_WEBHOOK="$2"; shift 2;;
    --skip-scan) SKIP_SCAN=true; shift;;
    --only-recon) ONLY_RECON=true; shift;;
    -*) warn "Unknown flag: $1"; shift;;
    *)  DOMAIN="$1"; shift;;
  esac
done

[[ -z "$DOMAIN" ]] && die "Domain required"

# ── Setup ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="./results/$DOMAIN"
START=$(date +%s)

export PATH=$PATH:$HOME/go/bin

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║  🎯 Bug Bounty Full Pipeline                 ║"
echo "║  Target: $DOMAIN"
echo "║  Started: $(date)"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

mkdir -p "$OUT"
LOG_FILE="$OUT/pipeline.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# ── Notify helper ─────────────────────────────────────────
send_discord() {
  local msg="$1"
  [[ -z "$DISCORD_WEBHOOK" ]] && return
  curl -s -X POST "$DISCORD_WEBHOOK" \
    -H "Content-Type: application/json" \
    -d "{\"content\": \"$msg\"}" > /dev/null
}

send_discord "🚀 Bug bounty pipeline started for \`$DOMAIN\`"

# ══════════════════════════════════════
# STAGE 1: RECONNAISSANCE
# ══════════════════════════════════════
section "STAGE 1: RECONNAISSANCE"
if bash "$SCRIPT_DIR/1_recon.sh" "$DOMAIN" "$OUT"; then
  info "✅ Recon complete"
  SUBS=$(wc -l < "$OUT/subdomains/all_subdomains.txt" 2>/dev/null || echo 0)
  LIVE=$(wc -l < "$OUT/hosts/live_urls.txt" 2>/dev/null || echo 0)
  send_discord "✅ Recon done for \`$DOMAIN\`: ${SUBS} subdomains, ${LIVE} live hosts"
else
  warn "Recon had errors (continuing)"
fi

[[ "$ONLY_RECON" == true ]] && { info "Only recon requested. Done!"; exit 0; }

# ══════════════════════════════════════
# STAGE 2: VULNERABILITY SCANNING
# ══════════════════════════════════════
if [[ "$SKIP_SCAN" == false ]]; then
  section "STAGE 2: VULNERABILITY SCANNING"
  if bash "$SCRIPT_DIR/2_scan.sh" "$DOMAIN" "$OUT"; then
    info "✅ Scanning complete"
    NUCLEI=$(cat "$OUT/vulns/nuclei/"*.txt 2>/dev/null | wc -l || echo 0)
    send_discord "✅ Scan done for \`$DOMAIN\`: ${NUCLEI} nuclei findings"
  else
    warn "Scan had errors (continuing)"
  fi
fi

# ══════════════════════════════════════
# STAGE 3: JS ANALYSIS
# ══════════════════════════════════════
section "STAGE 3: JS SECRET & ENDPOINT ANALYSIS"
JS_OUT="$OUT/js/js_analysis"
if [[ -f "$OUT/js/js_files.txt" ]]; then
  if python3 "$SCRIPT_DIR/3_js_analyzer.py" \
      "$OUT/js/js_files.txt" \
      --out "$JS_OUT" \
      --base-url "https://$DOMAIN"; then
    SECRETS=$(python3 -c "import json; d=json.load(open('$JS_OUT/secrets.json')); print(len(d))" 2>/dev/null || echo 0)
    ENDPOINTS=$(wc -l < "$JS_OUT/endpoints.txt" 2>/dev/null || echo 0)
    info "✅ JS analysis complete: $SECRETS secrets, $ENDPOINTS endpoints"
    [[ "$SECRETS" -gt 0 ]] && send_discord "🔑 \`$DOMAIN\`: Found ${SECRETS} exposed secrets in JS files!"
  else
    warn "JS analysis had errors"
  fi
else
  warn "No JS files found to analyze"
fi

# ══════════════════════════════════════
# STAGE 4: PARAMETER DISCOVERY
# ══════════════════════════════════════
section "STAGE 4: PARAMETER DISCOVERY"
PARAM_OUT="$OUT/param_discovery"
if [[ -f "$OUT/hosts/live_urls.txt" ]]; then
  if python3 "$SCRIPT_DIR/4_param_discovery.py" \
      "$OUT/hosts/live_urls.txt" \
      --out "$PARAM_OUT" \
      --threads 15 \
      --top 50; then
    API_HITS=$(python3 -c "import json; d=json.load(open('$PARAM_OUT/api_paths.json')); print(len([x for x in d if x['status']==200]))" 2>/dev/null || echo 0)
    info "✅ Param discovery complete: $API_HITS accessible API paths"
    [[ "$API_HITS" -gt 0 ]] && send_discord "🔍 \`$DOMAIN\`: Found ${API_HITS} accessible API paths!"
  else
    warn "Param discovery had errors"
  fi
fi

# ══════════════════════════════════════
# STAGE 5: SUBDOMAIN TAKEOVER
# ══════════════════════════════════════
section "STAGE 5: SUBDOMAIN TAKEOVER CHECKS"
TAKEOVER_OUT="$OUT/takeover"
if [[ -f "$OUT/subdomains/all_subdomains.txt" ]]; then
  if python3 "$SCRIPT_DIR/6_takeover.py" \
      "$OUT/subdomains/all_subdomains.txt" \
      --out "$TAKEOVER_OUT" \
      --threads 30; then
    VULN=$(python3 -c "import json; d=json.load(open('$TAKEOVER_OUT/takeover_findings.json')); print(len(d))" 2>/dev/null || echo 0)
    info "✅ Takeover check complete: $VULN vulnerable subdomains"
    [[ "$VULN" -gt 0 ]] && send_discord "🎯 \`$DOMAIN\`: Found ${VULN} subdomain takeover(s)!!!"
  else
    warn "Takeover check had errors"
  fi
fi

# ══════════════════════════════════════
# STAGE 6: GENERATE REPORT
# ══════════════════════════════════════
section "STAGE 6: GENERATING REPORT"
REPORT="$OUT/bug_bounty_report_$DOMAIN.md"
python3 "$SCRIPT_DIR/7_report.py" \
  --domain "$DOMAIN" \
  --results "$OUT" \
  --out "$REPORT" && info "✅ Report generated: $REPORT"

# ══════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════
END=$(date +%s)
ELAPSED=$((END - START))
MINS=$((ELAPSED / 60))
SECS=$((ELAPSED % 60))

section "PIPELINE COMPLETE"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║         FINAL PIPELINE SUMMARY               ║"
echo "╠══════════════════════════════════════════════╣"
echo "║ Target     : $DOMAIN"
echo "║ Duration   : ${MINS}m ${SECS}s"
echo "║ Subdomains : $(wc -l < "$OUT/subdomains/all_subdomains.txt" 2>/dev/null || echo 0)"
echo "║ Live Hosts : $(wc -l < "$OUT/hosts/live_urls.txt" 2>/dev/null || echo 0)"
echo "║ Endpoints  : $(wc -l < "$OUT/endpoints/all_urls.txt" 2>/dev/null || echo 0)"
echo "║ Nuclei     : $(cat "$OUT/vulns/nuclei/"*.txt 2>/dev/null | wc -l || echo 0)"
echo "║ JS Secrets : $(python3 -c "import json; d=json.load(open('$JS_OUT/secrets.json')); print(len(d))" 2>/dev/null || echo 0)"
echo "║ Takeovers  : $(python3 -c "import json; d=json.load(open('$TAKEOVER_OUT/takeover_findings.json')); print(len(d))" 2>/dev/null || echo 0)"
echo "║ Log        : $LOG_FILE"
echo "║ Report     : $REPORT"
echo "╚══════════════════════════════════════════════╝"
echo ""

send_discord "✅ Pipeline complete for \`$DOMAIN\` (${MINS}m ${SECS}s). Check report!"
info "Done! Review: $REPORT"
