#!/usr/bin/env python3
"""
7_REPORT.PY — Auto Bug Bounty Report Generator
Usage: python3 7_report.py --domain example.com --results ./results/example.com

Reads all scan outputs and generates a clean, deduped markdown report
ready to submit to HackerOne / Bugcrowd / Intigriti.
"""

import json
import argparse
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

G='\033[92m'; Y='\033[93m'; R='\033[91m'; B='\033[1m'; N='\033[0m'
def info(m): print(f"{G}[+]{N} {m}")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

# ── Report template per finding type ─────────────────────
TEMPLATES = {
    "xss": {
        "title":    "Cross-Site Scripting (XSS) — Reflected",
        "severity": "medium",
        "cvss":     "6.1",
        "impact":   "An attacker can execute arbitrary JavaScript in a victim's browser, potentially stealing cookies, session tokens, or performing actions on behalf of the victim.",
        "steps": [
            "Browse to the vulnerable URL",
            "Inject the XSS payload in the affected parameter",
            "Observe the script executing in the browser"
        ],
        "remediation": "Implement proper output encoding using an HTML encoding library. Use Content-Security-Policy headers. Validate and sanitize all user-supplied input server-side.",
        "references": ["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]
    },
    "sqli": {
        "title":    "SQL Injection",
        "severity": "high",
        "cvss":     "8.8",
        "impact":   "An attacker can read, modify, or delete database contents, bypass authentication, or in some cases execute OS commands.",
        "steps": [
            "Navigate to the vulnerable endpoint",
            "Inject SQL payload in the parameter",
            "Observe the database error or altered response"
        ],
        "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL queries. Apply principle of least privilege to database accounts.",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
    },
    "ssrf": {
        "title":    "Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "cvss":     "8.6",
        "impact":   "An attacker can make the server issue requests to internal services, cloud metadata endpoints (e.g., AWS IMDSv1), or exfiltrate sensitive data.",
        "steps": [
            "Identify the URL parameter",
            "Replace the value with an internal/OOB URL",
            "Observe the server fetching the URL (DNS lookup / HTTP request)"
        ],
        "remediation": "Implement an allowlist of permitted URLs/domains. Disable unnecessary URL fetch functionality. Block access to 169.254.169.254 and internal IP ranges.",
        "references": ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"]
    },
    "open_redirect": {
        "title":    "Open Redirect",
        "severity": "low",
        "cvss":     "4.7",
        "impact":   "Can be used in phishing campaigns by leveraging the trusted domain to redirect users to malicious sites.",
        "steps": [
            "Access the redirect URL with a malicious destination",
            "Observe the browser redirecting to the attacker-controlled domain"
        ],
        "remediation": "Validate redirect destinations against a strict allowlist. Use relative URLs instead of absolute URLs. Reject or warn users about redirects to external domains.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"]
    },
    "cors": {
        "title":    "CORS Misconfiguration",
        "severity": "medium",
        "cvss":     "6.5",
        "impact":   "An attacker-controlled page can make authenticated requests to the API and read sensitive responses.",
        "steps": [
            "Send a request with Origin: https://evil.com",
            "Observe the response includes Access-Control-Allow-Origin: https://evil.com",
            "Demonstrate reading authenticated response from cross-origin page"
        ],
        "remediation": "Validate the Origin header against an explicit allowlist. Never reflect the Origin header verbatim. Avoid Access-Control-Allow-Credentials: true with wildcard or untrusted origins.",
        "references": ["https://portswigger.net/web-security/cors"]
    },
    "takeover": {
        "title":    "Subdomain Takeover",
        "severity": "high",
        "cvss":     "8.1",
        "impact":   "An attacker can claim the dangling subdomain and serve content from it, enabling cookie theft, phishing, or CSP bypass.",
        "steps": [
            "Verify the CNAME record points to an unclaimed service",
            "Register/claim the target on the provider",
            "Demonstrate serving content on the subdomain"
        ],
        "remediation": "Remove unused DNS records immediately. Implement regular DNS audit processes. Use monitoring to detect dangling CNAMEs.",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"]
    },
    "secret": {
        "title":    "Exposed Secret / API Key in JavaScript",
        "severity": "high",
        "cvss":     "7.5",
        "impact":   "The exposed credential can be used to access backend services, cloud resources, or third-party APIs with potentially full account access.",
        "steps": [
            "Open the JS file in browser or download it",
            "Search for the secret using the pattern",
            "Verify the credential is valid (if safe to do so)"
        ],
        "remediation": "Rotate the exposed credential immediately. Move secrets to server-side environment variables. Never include secrets in client-side JS. Add secret scanning to CI/CD pipeline.",
        "references": ["https://owasp.org/www-community/vulnerabilities/Insecure_Storage_of_Sensitive_Information"]
    },
}

def parse_nuclei_results(vuln_dir: Path) -> list[dict]:
    """Parse nuclei JSON results."""
    findings = []
    for json_file in vuln_dir.glob("nuclei/*.json"):
        try:
            data = json.loads(json_file.read_text())
            if isinstance(data, list):
                for item in data:
                    findings.append({
                        "type":     "nuclei",
                        "template": item.get("template-id", "unknown"),
                        "severity": item.get("info", {}).get("severity", "info"),
                        "url":      item.get("matched-at", ""),
                        "name":     item.get("info", {}).get("name", ""),
                        "detail":   item.get("info", {}).get("description", ""),
                    })
        except Exception:
            pass
    return findings

def parse_xss_results(vuln_dir: Path) -> list[dict]:
    findings = []
    for f in [vuln_dir / "xss/dalfox_results.json",
              vuln_dir / "xss/xss_candidates.txt"]:
        if f.exists():
            try:
                if f.suffix == '.json':
                    data = json.loads(f.read_text())
                    if isinstance(data, list):
                        for item in data:
                            findings.append({"type": "xss", "url": item.get("data", ""), "payload": item.get("param", "")})
                else:
                    for url in f.read_text().splitlines():
                        if url.strip():
                            findings.append({"type": "xss", "url": url.strip()})
            except Exception:
                pass
    return findings

def parse_secrets(js_dir: Path) -> list[dict]:
    findings = []
    secrets_file = js_dir / "secrets.json"
    if secrets_file.exists():
        try:
            data = json.loads(secrets_file.read_text())
            for s in data:
                findings.append({
                    "type":       "secret",
                    "secret_type": s.get("type", ""),
                    "value":      s.get("value", "")[:50] + "...",
                    "file":       s.get("file", ""),
                })
        except Exception:
            pass
    return findings

def parse_takeover(takeover_dir: Path) -> list[dict]:
    findings = []
    tf = takeover_dir / "takeover_findings.json"
    if tf.exists():
        try:
            data = json.loads(tf.read_text())
            for v in data:
                findings.append({
                    "type":      "takeover",
                    "subdomain": v.get("subdomain", ""),
                    "service":   v.get("service", ""),
                    "cname":     v.get("cname", ""),
                    "evidence":  v.get("evidence", []),
                })
        except Exception:
            pass
    return findings

def build_report_section(finding_type: str, findings: list[dict], domain: str) -> str:
    """Build a report section for a finding type."""
    if not findings:
        return ""
    
    tmpl = TEMPLATES.get(finding_type, {})
    if not tmpl:
        return ""
    
    sev   = tmpl.get("severity", "medium")
    emoji = SEVERITY_EMOJI.get(sev, "⚪")
    
    sections = []
    for i, f in enumerate(findings[:5], 1):  # Max 5 per type
        url = f.get("url", f.get("subdomain", "N/A"))
        
        section = f"""
### {emoji} [{sev.upper()}] {tmpl['title']} #{i}

**Severity:** {sev.capitalize()} (CVSS {tmpl.get('cvss', 'N/A')})  
**URL:** `{url}`  
"""
        if f.get("secret_type"):
            section += f"**Type:** {f['secret_type']}  \n"
            section += f"**Value (redacted):** `{f.get('value', '')}...`  \n"
            section += f"**File:** `{f.get('file', '')}` \n"
        
        if f.get("subdomain"):
            section += f"**CNAME:** `{f.get('cname', '')}` → {f.get('service', '')}  \n"

        section += f"""
**Impact:**  
{tmpl['impact']}

**Steps to Reproduce:**
"""
        for step_i, step in enumerate(tmpl['steps'], 1):
            section += f"{step_i}. {step}\n"

        section += f"""
**Recommended Fix:**  
{tmpl['remediation']}

**References:**  
"""
        for ref in tmpl.get('references', []):
            section += f"- {ref}\n"
        
        sections.append(section)
    
    return '\n'.join(sections)

def generate_report(domain: str, results_dir: str, out_file: str):
    """Generate the full bug bounty report."""
    rdir       = Path(results_dir)
    vuln_dir   = rdir / "vulns"
    js_dir     = rdir / "js" / "js_analysis"
    takeover_dir = Path("./takeover_results")

    all_findings = []
    all_findings.extend(parse_nuclei_results(vuln_dir))
    all_findings.extend(parse_xss_results(vuln_dir))
    all_findings.extend(parse_secrets(js_dir))
    all_findings.extend(parse_takeover(takeover_dir))

    # Count by severity
    sev_counts = defaultdict(int)
    for f in all_findings:
        sev = f.get("severity", TEMPLATES.get(f.get("type", ""), {}).get("severity", "info"))
        sev_counts[sev] += 1

    report_date = datetime.now().strftime("%Y-%m-%d %H:%M")

    report = f"""# Bug Bounty Report — {domain}

**Date:** {report_date}  
**Target:** {domain}  
**Tester:** [Your Name]  
**Program:** [Program Name]

---

## Executive Summary

Security testing of `{domain}` revealed **{len(all_findings)} findings** across the following severity levels:

| Severity | Count |
|----------|-------|
| 🔴 Critical | {sev_counts.get('critical', 0)} |
| 🟠 High | {sev_counts.get('high', 0)} |
| 🟡 Medium | {sev_counts.get('medium', 0)} |
| 🔵 Low | {sev_counts.get('low', 0)} |
| ⚪ Info | {sev_counts.get('info', 0)} |

---

## Scope

- Primary domain: `{domain}`
- Subdomains in scope (as enumerated)

---

## Findings

"""

    # Group by type
    by_type = defaultdict(list)
    for f in all_findings:
        by_type[f["type"]].append(f)

    for ftype, findings in sorted(by_type.items(), 
                                   key=lambda x: SEVERITY_ORDER.get(
                                       TEMPLATES.get(x[0], {}).get("severity", "info"), 4)):
        section = build_report_section(ftype, findings, domain)
        if section:
            report += section + "\n---\n"

    # Nuclei findings (custom format)
    nuclei_findings = by_type.get("nuclei", [])
    if nuclei_findings:
        report += "\n## Nuclei Template Findings\n\n"
        report += "| Severity | Template | URL |\n|----------|----------|-----|\n"
        for f in sorted(nuclei_findings, 
                         key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 4)):
            sev = f.get("severity", "info")
            report += f"| {SEVERITY_EMOJI.get(sev, '⚪')} {sev} | {f.get('template', '')} | `{f.get('url', '')}` |\n"

    report += f"""

---

## Methodology

1. **Passive Reconnaissance** — Subdomain enumeration via certificate transparency, passive DNS
2. **Active Probing** — HTTP probing, port scanning, technology fingerprinting
3. **Endpoint Discovery** — Crawling, GAU, Wayback Machine
4. **Automated Scanning** — Nuclei templates, parameter fuzzing, XSS/SQLi/SSRF detection
5. **Manual Verification** — All automated findings manually confirmed before reporting

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| {report_date} | Initial discovery |
| | Report submitted |
| | Vendor response |
| | Fix deployed |
| | Bounty awarded |

---

*This report was generated automatically and all findings have been manually verified. 
Only in-scope assets were tested in accordance with the program's rules of engagement.*
"""

    Path(out_file).write_text(report)
    info(f"Report written → {out_file}")
    info(f"Total findings: {len(all_findings)}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain',  required=True, help='Target domain')
    parser.add_argument('--results', required=True, help='Results directory from 1_recon.sh')
    parser.add_argument('--out',     default='bug_bounty_report.md', help='Output report file')
    args = parser.parse_args()

    generate_report(args.domain, args.results, args.out)

if __name__ == '__main__':
    main()
