#!/usr/bin/env python3
"""
6_TAKEOVER.PY — Subdomain Takeover Checker
Usage: python3 6_takeover.py <subdomains.txt> [--out ./results]

Checks for:
  - Dangling DNS CNAMEs pointing to unclaimed services
  - Expired S3 buckets, GitHub pages, Heroku apps, etc.
"""

import re
import sys
import json
import socket
import argparse
import requests
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3; urllib3.disable_warnings()

G='\033[92m'; Y='\033[93m'; R='\033[91m'; C='\033[96m'; B='\033[1m'; N='\033[0m'
def info(m):  print(f"{G}[+]{N} {m}")
def warn(m):  print(f"{Y}[!]{N} {m}")
def found(m): print(f"{R}[🎯 TAKEOVER]{N} {m}")

# ── Fingerprints for unclaimed services ──────────────────
FINGERPRINTS = {
    "GitHub Pages": {
        "cname":   [".github.io"],
        "body":    ["There isn't a GitHub Pages site here"],
        "status":  [404],
    },
    "AWS S3": {
        "cname":   [".s3.amazonaws.com", "s3-website"],
        "body":    ["NoSuchBucket", "The specified bucket does not exist"],
        "status":  [404, 403],
    },
    "Heroku": {
        "cname":   [".herokuapp.com", ".herokudns.com"],
        "body":    ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "status":  [404],
    },
    "Netlify": {
        "cname":   [".netlify.app", ".netlify.com"],
        "body":    ["Not found - Request ID"],
        "status":  [404],
    },
    "Vercel": {
        "cname":   [".vercel.app", "cname.vercel-dns.com"],
        "body":    ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "status":  [404],
    },
    "Shopify": {
        "cname":   [".myshopify.com", "shops.myshopify.com"],
        "body":    ["Sorry, this shop is currently unavailable"],
        "status":  [404],
    },
    "Fastly": {
        "cname":   [".fastly.net"],
        "body":    ["Fastly error: unknown domain"],
        "status":  [404],
    },
    "Ghost": {
        "cname":   [".ghost.io"],
        "body":    ["The thing you were looking for is no longer here"],
        "status":  [404],
    },
    "Tumblr": {
        "cname":   [".tumblr.com"],
        "body":    ["Whatever you were looking for doesn't currently exist at this address"],
        "status":  [404],
    },
    "WordPress.com": {
        "cname":   [".wordpress.com"],
        "body":    ["Do you want to register"],
        "status":  [404],
    },
    "Zendesk": {
        "cname":   [".zendesk.com"],
        "body":    ["Help Center Closed"],
        "status":  [404],
    },
    "Squarespace": {
        "cname":   [".squarespace.com"],
        "body":    ["No Such Account"],
        "status":  [404],
    },
    "JetBrains Space": {
        "cname":   [".jetbrains.space"],
        "body":    ["is not a registered InCloud YouTrack"],
        "status":  [404],
    },
    "Azure": {
        "cname":   [".azurewebsites.net", ".blob.core.windows.net", ".cloudapp.net"],
        "body":    ["404 Web Site not found"],
        "status":  [404],
    },
    "Pantheon": {
        "cname":   [".pantheonsite.io"],
        "body":    ["The gods are wise, but do not know of the site"],
        "status":  [404],
    },
    "Cargo Collective": {
        "cname":   [".cargocollective.com"],
        "body":    ["If you're moving your domain away from Cargo"],
        "status":  [404],
    },
    "Surge.sh": {
        "cname":   [".surge.sh"],
        "body":    ["project not found"],
        "status":  [404],
    },
    "Firebase": {
        "cname":   [".firebaseapp.com", ".web.app"],
        "body":    ["Site Not Found"],
        "status":  [404],
    },
    "Bitbucket": {
        "cname":   [".bitbucket.io"],
        "body":    ["Repository not found"],
        "status":  [404],
    },
}

def get_cname(domain: str) -> str | None:
    """Resolve CNAME for a domain."""
    try:
        result = subprocess.run(
            ['dig', '+short', 'CNAME', domain],
            capture_output=True, text=True, timeout=10
        )
        cname = result.stdout.strip().rstrip('.')
        return cname if cname else None
    except Exception:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'CNAME')
            return str(answers[0].target).rstrip('.')
        except Exception:
            return None

def check_nxdomain(domain: str) -> bool:
    """Check if domain resolves (False = NXDOMAIN = interesting)."""
    try:
        socket.gethostbyname(domain)
        return False  # Resolves
    except socket.gaierror:
        return True   # NXDOMAIN

def check_takeover(subdomain: str) -> dict | None:
    """Check a single subdomain for takeover potential."""
    subdomain = subdomain.strip()
    if not subdomain:
        return None

    result = {
        "subdomain": subdomain,
        "cname":     None,
        "service":   None,
        "vulnerable": False,
        "evidence":  []
    }

    # Get CNAME
    cname = get_cname(subdomain)
    result["cname"] = cname

    # Try HTTP
    body      = ""
    status    = 0
    for scheme in ['https', 'http']:
        try:
            r = requests.get(
                f"{scheme}://{subdomain}",
                timeout=8, verify=False,
                headers={'User-Agent': 'Mozilla/5.0'},
                allow_redirects=True
            )
            body   = r.text
            status = r.status_code
            break
        except Exception:
            continue

    # Match fingerprints
    for service, fp in FINGERPRINTS.items():
        matched = False

        # CNAME match
        if cname:
            for c in fp.get("cname", []):
                if c.lower() in cname.lower():
                    matched = True
                    result["evidence"].append(f"CNAME matches {service}: {cname}")
                    break

        # Body match
        for sig in fp.get("body", []):
            if sig.lower() in body.lower():
                matched = True
                result["evidence"].append(f"Body signature: '{sig[:50]}'")
                break

        if matched and status in fp.get("status", [404]):
            result["service"]   = service
            result["vulnerable"] = True
            result["status"]    = status
            found(f"{subdomain} → [{service}] CNAME={cname} HTTP={status}")
            return result

    # Dangling CNAME with NXDOMAIN on target
    if cname and check_nxdomain(cname):
        result["service"]   = "Unknown (dangling CNAME)"
        result["vulnerable"] = True
        result["evidence"].append(f"CNAME {cname} returns NXDOMAIN")
        found(f"{subdomain} → DANGLING CNAME: {cname} (NXDOMAIN)")
        return result

    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input',      help='File with subdomains (one per line)')
    parser.add_argument('--out',      default='./takeover_results', help='Output dir')
    parser.add_argument('--threads',  type=int, default=30, help='Threads')
    args = parser.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    subdomains = [s.strip() for s in Path(args.input).read_text().splitlines() if s.strip()]
    info(f"Checking {len(subdomains)} subdomains for takeover...")

    vulnerable = []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_takeover, sub): sub for sub in subdomains}
        for i, fut in enumerate(as_completed(futures), 1):
            print(f"\r  Progress: {i}/{len(subdomains)}", end='', flush=True)
            try:
                result = fut.result()
                if result and result.get('vulnerable'):
                    vulnerable.append(result)
            except Exception as e:
                pass

    print()  # newline

    # Write results
    out_json = outdir / "takeover_findings.json"
    out_txt  = outdir / "takeover_findings.txt"

    out_json.write_text(json.dumps(vulnerable, indent=2))
    with open(out_txt, 'w') as f:
        for v in vulnerable:
            f.write(f"[VULNERABLE] {v['subdomain']}\n")
            f.write(f"  Service : {v['service']}\n")
            f.write(f"  CNAME   : {v.get('cname', 'N/A')}\n")
            for e in v.get('evidence', []):
                f.write(f"  Evidence: {e}\n")
            f.write("\n")

    print()
    info(f"Total checked   : {len(subdomains)}")
    info(f"Vulnerable found: {len(vulnerable)}")
    if vulnerable:
        info(f"Results → {out_txt}")

if __name__ == '__main__':
    main()
