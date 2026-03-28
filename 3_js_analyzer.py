#!/usr/bin/env python3
"""
3_JS_ANALYZER.PY — JS File Secret & Endpoint Extractor
Usage: python3 3_js_analyzer.py <js_files_list.txt> [output_dir]
       python3 3_js_analyzer.py --url https://example.com --single
"""

import re
import sys
import json
import os
import argparse
import requests
import jsbeautifier
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from datetime import datetime

# ── Colors ────────────────────────────────────────────────
G='\033[92m'; Y='\033[93m'; R='\033[91m'; C='\033[96m'; B='\033[1m'; N='\033[0m'
def info(m):    print(f"{G}[+]{N} {m}")
def warn(m):    print(f"{Y}[!]{N} {m}")
def found(m):   print(f"{R}[!!! FOUND !!!]{N} {m}")
def section(m): print(f"\n{C}{B}━━━ {m} ━━━{N}")

# ══════════════════════════════════════════════════════════
# SECRET PATTERNS
# ══════════════════════════════════════════════════════════
SECRET_PATTERNS = {
    # API Keys
    "AWS Access Key":          r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":          r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']',
    "AWS MFA":                 r'(?i)aws.{0,20}mfa.{0,20}["\']([0-9]{6})["\']',
    "Google API Key":          r'AIza[0-9A-Za-z_\-]{35}',
    "Google OAuth":            r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Firebase URL":            r'https://[a-z0-9-]+\.firebaseio\.com',
    "Firebase Key":            r'(?i)firebase.{0,10}["\']([A-Za-z0-9_-]{39})["\']',
    "GitHub Token":            r'gh[pousr]_[A-Za-z0-9_]{36,}',
    "GitHub OAuth":            r'github.{0,10}["\']([a-f0-9]{40})["\']',
    "Stripe Secret Key":       r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe Publishable Key":  r'pk_live_[0-9a-zA-Z]{24,}',
    "Stripe Test Key":         r'sk_test_[0-9a-zA-Z]{24,}',
    "Twilio Account SID":      r'AC[a-z0-9]{32}',
    "Twilio Auth Token":       r'(?i)twilio.{0,20}["\']([a-f0-9]{32})["\']',
    "Slack Token":             r'xox[baprs]-[0-9A-Za-z\-]{10,}',
    "Slack Webhook":           r'https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+',
    "Discord Token":           r'(?i)discord.{0,10}["\']([MN][A-Za-z0-9]{23,})["\']',
    "Discord Webhook":         r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
    "Mailgun API Key":         r'key-[0-9a-zA-Z]{32}',
    "SendGrid API Key":        r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    "Mailchimp API Key":       r'[0-9a-f]{32}-us[0-9]{1,2}',
    "Heroku API Key":          r'(?i)heroku.{0,20}["\']([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})["\']',
    "Shopify Token":           r'shpat_[A-Za-z0-9]{32}',
    "PayPal Client ID":        r'(?i)paypal.{0,20}client.{0,10}["\']([A-Za-z0-9_-]{80,})["\']',
    "JWT Token":               r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
    "Private Key":             r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    "Basic Auth (base64)":     r'(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{20,}',
    "Bearer Token":            r'(?i)bearer\s+[A-Za-z0-9_\-\.=]{30,}',
    "Generic Secret":          r'(?i)(secret|password|passwd|pwd|token|apikey|api_key)\s*[:=]\s*["\']([A-Za-z0-9@#$%^&*()_+=\-]{8,})["\']',
    "Generic API Key":         r'(?i)(api[_-]?key|app[_-]?key|access[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
    "Database Connection":     r'(?i)(mongodb|mysql|postgres|redis|sqlite):\/\/[^\s"\'<>]+',
    "SMTP Credentials":        r'(?i)smtp.{0,30}(password|pass|pwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']',
    "S3 Bucket":               r's3\.amazonaws\.com/[a-z0-9._-]+|[a-z0-9._-]+\.s3\.amazonaws\.com',
    "Google Cloud Storage":    r'storage\.googleapis\.com/[a-z0-9._-]+',
    "Internal IP":             r'\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b',
}

# ══════════════════════════════════════════════════════════
# ENDPOINT PATTERNS
# ══════════════════════════════════════════════════════════
ENDPOINT_PATTERNS = [
    r'(?:"|\'|`)(/(?:api|v\d|rest|graphql|admin|auth|login|oauth|user|users|account|data|internal|private|backend)[^"\'`\s<>]*)',
    r'(?:"|\'|`)([a-zA-Z]{2,10}://[^"\'`\s<>]{10,})',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'XMLHttpRequest.*?open\(["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']',
    r'(?:url|endpoint|path|route)\s*[:=]\s*["\']([/][^"\']{3,})["\']',
    r'(?:api_url|apiUrl|API_URL|baseURL|BASE_URL)\s*[:=]\s*["\']([^"\']{10,})["\']',
    r'\.get\(["\']([/][^"\']{3,})["\']',
    r'\.post\(["\']([/][^"\']{3,})["\']',
    r'\.put\(["\']([/][^"\']{3,})["\']',
    r'\.delete\(["\']([/][^"\']{3,})["\']',
    r'(?:href|src|action)\s*=\s*["\']([^"\']{5,})["\']',
]

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; BugBountyBot/1.0)',
    'Accept': '*/*'
}

# ══════════════════════════════════════════════════════════
# CORE FUNCTIONS
# ══════════════════════════════════════════════════════════

def beautify_js(code: str) -> str:
    """Beautify minified JS for better pattern matching."""
    try:
        return jsbeautifier.beautify(code)
    except Exception:
        return code

def fetch_js(url: str, timeout: int = 10) -> str | None:
    """Fetch JS file content."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        if r.status_code == 200:
            return r.text
    except Exception as e:
        warn(f"Failed to fetch {url}: {e}")
    return None

def extract_secrets(code: str, filename: str = "") -> list[dict]:
    """Scan code for secrets using all patterns."""
    findings = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, code, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            value = match if isinstance(match, str) else match[-1]
            findings.append({
                "type":     secret_type,
                "value":    value[:200],  # truncate for safety
                "file":     filename,
                "pattern":  pattern[:60]
            })
    return findings

def extract_endpoints(code: str, base_url: str = "") -> list[str]:
    """Extract API endpoints and URLs from JS code."""
    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        matches = re.findall(pattern, code, re.IGNORECASE)
        for match in matches:
            ep = match.strip().rstrip('/')
            if ep and len(ep) > 2:
                # Make absolute if relative
                if ep.startswith('/') and base_url:
                    ep = urljoin(base_url, ep)
                endpoints.add(ep)
    # Filter noise
    filtered = {
        ep for ep in endpoints
        if not any(skip in ep for skip in [
            '.png', '.jpg', '.gif', '.ico', '.css', '.woff',
            'localhost', '127.0.0.1', '///', '{{', '#{', '<'
        ])
    }
    return sorted(filtered)

def extract_subdomains(code: str, domain: str) -> list[str]:
    """Find subdomain references in JS."""
    pattern = rf'["\']https?://([a-zA-Z0-9._-]+\.{re.escape(domain)})["\']'
    matches = re.findall(pattern, code, re.IGNORECASE)
    return sorted(set(matches))

def analyze_js_file(url_or_path: str, base_url: str = "", outdir: str = ".") -> dict:
    """Full analysis of a single JS file."""
    # Fetch or read
    if url_or_path.startswith('http'):
        code = fetch_js(url_or_path)
        filename = url_or_path
    else:
        try:
            code = Path(url_or_path).read_text(errors='ignore')
            filename = url_or_path
        except Exception:
            return {}

    if not code:
        return {}

    # Beautify
    beautified = beautify_js(code)

    # Analyze
    secrets   = extract_secrets(beautified, filename)
    endpoints = extract_endpoints(beautified, base_url)
    
    result = {
        "file":      filename,
        "size_kb":   round(len(code) / 1024, 2),
        "secrets":   secrets,
        "endpoints": endpoints,
    }

    # Print secrets immediately
    for s in secrets:
        found(f"[{s['type']}] in {os.path.basename(filename)}: {s['value'][:80]}")

    return result

# ══════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='JS Secret & Endpoint Analyzer')
    parser.add_argument('input',          nargs='?', help='File containing JS URLs (one per line)')
    parser.add_argument('--url',          help='Single JS URL to analyze')
    parser.add_argument('--domain',       help='Target domain for subdomain extraction')
    parser.add_argument('--out',          default='./js_analysis', help='Output directory')
    parser.add_argument('--threads',      type=int, default=10, help='Concurrent threads')
    parser.add_argument('--base-url',     default='', help='Base URL for relative paths')
    args = parser.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    import urllib3; urllib3.disable_warnings()

    # Collect URLs
    urls = []
    if args.url:
        urls = [args.url]
    elif args.input:
        urls = [u.strip() for u in Path(args.input).read_text().splitlines() if u.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    section(f"Analyzing {len(urls)} JS files")

    all_results = []
    all_secrets   = []
    all_endpoints = set()

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(analyze_js_file, url, args.base_url, str(outdir)): url
            for url in urls
        }
        for i, fut in enumerate(as_completed(futures), 1):
            url = futures[fut]
            print(f"\r  Progress: {i}/{len(urls)} — {os.path.basename(url)[:40]:<40}", end='')
            try:
                result = fut.result()
                if result:
                    all_results.append(result)
                    all_secrets.extend(result.get('secrets', []))
                    all_endpoints.update(result.get('endpoints', []))
            except Exception as e:
                warn(f"\nError on {url}: {e}")

    print()  # newline after progress

    # ── Write Outputs ─────────────────────────────────────
    section("Writing Results")

    # Secrets
    secrets_file = outdir / "secrets.json"
    with open(secrets_file, 'w') as f:
        json.dump(all_secrets, f, indent=2)

    # Secrets as text
    secrets_txt = outdir / "secrets.txt"
    with open(secrets_txt, 'w') as f:
        for s in all_secrets:
            f.write(f"[{s['type']}] {s['value']}\n  File: {s['file']}\n\n")

    # Endpoints
    endpoints_file = outdir / "endpoints.txt"
    with open(endpoints_file, 'w') as f:
        f.write('\n'.join(sorted(all_endpoints)))

    # Full report
    report_file = outdir / "js_report.json"
    with open(report_file, 'w') as f:
        json.dump({
            "scan_date":     datetime.now().isoformat(),
            "files_analyzed": len(all_results),
            "total_secrets":  len(all_secrets),
            "total_endpoints": len(all_endpoints),
            "results":        all_results
        }, f, indent=2)

    # ── Summary ────────────────────────────────────────────
    section("Summary")

    print(f"  Files analyzed  : {len(all_results)}")
    print(f"  Secrets found   : {len(all_secrets)}")
    print(f"  Endpoints found : {len(all_endpoints)}")
    print()

    if all_secrets:
        print(f"  Secret types found:")
        from collections import Counter
        for stype, count in Counter(s['type'] for s in all_secrets).most_common():
            print(f"    {count:>4}x  {stype}")

    print()
    info(f"Results saved to: {outdir}/")
    info(f"  Secrets  → {secrets_txt}")
    info(f"  Endpoints → {endpoints_file}")
    info(f"  Full report → {report_file}")

if __name__ == '__main__':
    main()
