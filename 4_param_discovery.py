#!/usr/bin/env python3
"""
4_PARAM_DISCOVERY.PY — Hidden Parameter & API Endpoint Fuzzer
Usage: python3 4_param_discovery.py <live_urls.txt> [--out ./results]
"""

import sys
import json
import argparse
import requests
import subprocess
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
import urllib3; urllib3.disable_warnings()

G='\033[92m'; Y='\033[93m'; R='\033[91m'; C='\033[96m'; B='\033[1m'; N='\033[0m'
def info(m):    print(f"{G}[+]{N} {m}")
def warn(m):    print(f"{Y}[!]{N} {m}")
def found(m):   print(f"{R}[FOUND]{N} {m}")
def section(m): print(f"\n{C}{B}━━━ {m} ━━━{N}")

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; BugBountyBot/1.0)'}

# ── Common hidden parameters to fuzz ─────────────────────
PARAM_WORDLIST = [
    # Debug / dev
    "debug", "test", "dev", "staging", "verbose", "trace", "log",
    "admin", "superuser", "internal", "secret", "preview",
    # Auth bypass
    "token", "api_key", "apikey", "key", "access_token", "auth",
    "authorization", "api_token", "user_token", "session", "jwt",
    # SSRF / redirect
    "url", "redirect", "next", "return", "callback", "forward",
    "dest", "destination", "go", "redir", "redirect_to", "return_url",
    "target", "ref", "returnTo", "continue", "returnUrl",
    # File inclusion
    "file", "page", "path", "filepath", "filename", "doc",
    "document", "template", "view", "include", "load", "read",
    # IDOR
    "id", "user_id", "uid", "userId", "account_id", "order_id",
    "invoice_id", "item_id", "record_id", "ref", "reference",
    # Info disclosure
    "config", "conf", "settings", "env", "environment", "mode",
    "format", "output", "type", "lang", "language", "locale",
    # SQL injection bait
    "sort", "order", "orderby", "order_by", "column", "filter",
    "search", "q", "query", "keyword", "s", "term",
    # Command injection bait
    "cmd", "exec", "execute", "run", "command", "ping", "host",
]

# ── API endpoint patterns to try ─────────────────────────
API_PATHS = [
    # Swagger / OpenAPI
    "/swagger.json", "/swagger/v2/swagger.json", "/api-docs",
    "/openapi.json", "/v2/api-docs", "/swagger-ui.html",
    "/api/swagger.json", "/swagger/index.html",
    # Health / info endpoints
    "/health", "/healthz", "/ping", "/status", "/info",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    # Debug / admin
    "/debug", "/debug/vars", "/debug/pprof",
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/console", "/management", "/manager",
    # API versioning
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/graphql", "/graphiql",
    # Exposed files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.json", "/config.yaml", "/config.yml",
    "/.git/config", "/.git/HEAD",
    "/backup.zip", "/backup.sql", "/dump.sql",
    "/phpinfo.php", "/info.php", "/test.php",
    "/wp-config.php.bak", "/wp-config.php~",
    # Cloud metadata
    "/latest/meta-data/", "/metadata/v1/",
]

def baseline_response(url: str) -> dict:
    """Get baseline response for comparison."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=8, verify=False, allow_redirects=True)
        return {
            "status": r.status_code,
            "length": len(r.content),
            "words":  len(r.text.split()),
        }
    except Exception:
        return {"status": 0, "length": 0, "words": 0}

def fuzz_parameters(url: str, baseline: dict, params: list[str]) -> list[dict]:
    """Try adding hidden parameters to a URL."""
    findings = []
    for param in params:
        test_url = f"{url}{'&' if '?' in url else '?'}{param}=1"
        try:
            r = requests.get(test_url, headers=HEADERS, timeout=6, verify=False)
            # Significant change = interesting
            diff_len = abs(len(r.content) - baseline['length'])
            if (r.status_code != baseline['status'] or diff_len > 200):
                findings.append({
                    "url":        test_url,
                    "param":      param,
                    "status":     r.status_code,
                    "length":     len(r.content),
                    "diff_len":   diff_len,
                    "baseline_status": baseline['status'],
                })
                found(f"Param: {param} on {url} → {r.status_code} (diff: {diff_len})")
        except Exception:
            pass
    return findings

def check_api_paths(base_url: str) -> list[dict]:
    """Check for exposed API endpoints and files."""
    findings = []
    parsed   = urlparse(base_url)
    root     = f"{parsed.scheme}://{parsed.netloc}"

    for path in API_PATHS:
        url = urljoin(root, path)
        try:
            r = requests.get(url, headers=HEADERS, timeout=6, verify=False, allow_redirects=True)
            if r.status_code in (200, 201, 403, 401):
                is_json = 'json' in r.headers.get('content-type', '')
                finding = {
                    "url":     url,
                    "status":  r.status_code,
                    "length":  len(r.content),
                    "is_json": is_json,
                }
                findings.append(finding)
                if r.status_code == 200:
                    found(f"[HTTP 200] {url} ({len(r.content)} bytes{', JSON' if is_json else ''})")
                else:
                    info(f"[HTTP {r.status_code}] {url}")
        except Exception:
            pass
    return findings

def run_arjun(url: str, outdir: str) -> list[str]:
    """Run arjun for deep parameter discovery."""
    if not any(subprocess.call(['which', 'arjun'], capture_output=True).returncode == 0
               for _ in [1]):
        # Try as Python module
        out_file = os.path.join(outdir, "arjun.json")
        cmd = [
            'python3', '-m', 'arjun',
            '-u', url,
            '-oJ', out_file,
            '--stable'
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if os.path.exists(out_file):
                data = json.loads(Path(out_file).read_text())
                params = data.get(url, {}).get('params', [])
                if params:
                    info(f"Arjun found params for {url}: {params}")
                return params
        except Exception as e:
            warn(f"Arjun failed: {e}")
    return []

def process_url(url: str, outdir: str) -> dict:
    """Full parameter discovery on a single URL."""
    info(f"Processing: {url}")
    baseline  = baseline_response(url)
    param_hits = fuzz_parameters(url, baseline, PARAM_WORDLIST)
    api_hits   = check_api_paths(url)
    arjun_params = run_arjun(url, outdir)

    return {
        "url":          url,
        "param_hits":   param_hits,
        "api_hits":     api_hits,
        "arjun_params": arjun_params,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input',     help='File with live URLs (one per line)')
    parser.add_argument('--out',     default='./param_discovery', help='Output dir')
    parser.add_argument('--threads', type=int, default=10)
    parser.add_argument('--top',     type=int, default=50, help='Limit URLs processed')
    args = parser.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    urls = [u.strip() for u in Path(args.input).read_text().splitlines() if u.strip()][:args.top]
    info(f"Processing {len(urls)} URLs with {args.threads} threads")

    all_results  = []
    all_api_hits = []
    all_param_hits = []

    section("API Path Discovery")
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(process_url, url, str(outdir)): url for url in urls}
        for fut in as_completed(futures):
            try:
                result = fut.result()
                all_results.append(result)
                all_api_hits.extend(result['api_hits'])
                all_param_hits.extend(result['param_hits'])
            except Exception as e:
                warn(f"Error: {e}")

    # Write results
    section("Writing Results")

    api_file = outdir / "api_paths.json"
    api_file.write_text(json.dumps(all_api_hits, indent=2))

    params_file = outdir / "hidden_params.json"
    params_file.write_text(json.dumps(all_param_hits, indent=2))

    # Human-readable
    summary_file = outdir / "param_summary.txt"
    with open(summary_file, 'w') as f:
        f.write("=== API PATHS FOUND ===\n\n")
        for h in all_api_hits:
            f.write(f"[{h['status']}] {h['url']} ({h['length']} bytes)\n")
        f.write("\n=== HIDDEN PARAMS FOUND ===\n\n")
        for h in all_param_hits:
            f.write(f"[diff:{h['diff_len']}] {h['url']} | param={h['param']}\n")

    print()
    info(f"API paths found   : {len(all_api_hits)}")
    info(f"HTTP 200 hits     : {sum(1 for h in all_api_hits if h['status'] == 200)}")
    info(f"Hidden params     : {len(all_param_hits)}")
    info(f"Results → {outdir}/")

if __name__ == '__main__':
    main()
