# 🎯 Bug Bounty Automation Toolkit

A full end-to-end automation toolkit covering every phase of bug bounty hunting — from recon to report generation.

---

## 📁 Scripts Overview

| Script | Purpose |
|--------|---------|
| `setup.sh` | Install all tools (run once) |
| `1_recon.sh` | Subdomain enum, HTTP probing, port scan, screenshots, endpoint discovery |
| `2_scan.sh` | Nuclei, XSS, SQLi, SSRF, Open Redirect, LFI, CORS, Headers |
| `3_js_analyzer.py` | Extract secrets + API endpoints from JS files |
| `4_param_discovery.py` | Find hidden params, exposed API paths, fuzzing |
| `5_monitor.py` | Continuous monitoring — alerts on new assets/changes |
| `6_takeover.py` | Subdomain takeover detection (30+ service fingerprints) |
| `7_report.py` | Auto-generate markdown bug report from scan results |
| `run_all.sh` | **Master pipeline** — runs everything in sequence |

---

## ⚡ Quick Start

### 1. Install tools (once)
```bash
chmod +x setup.sh
sudo ./setup.sh
```

### 2. Run the full pipeline on a target
```bash
chmod +x *.sh
./run_all.sh example.com
```

### 3. Run with Discord notifications
```bash
./run_all.sh example.com --notify https://discord.com/api/webhooks/YOUR/WEBHOOK
```

### 4. Just recon (no scanning)
```bash
./run_all.sh example.com --only-recon
```

---

## 🔧 Individual Script Usage

### Recon
```bash
./1_recon.sh example.com ./results/example.com
```

### Vulnerability Scan (run after recon)
```bash
./2_scan.sh example.com ./results/example.com
```

### JS Analysis
```bash
# Analyze a list of JS file URLs
python3 3_js_analyzer.py results/example.com/js/js_files.txt

# Analyze single JS URL
python3 3_js_analyzer.py --url https://example.com/app.js
```

### Parameter Discovery
```bash
python3 4_param_discovery.py results/example.com/hosts/live_urls.txt --threads 20
```

### Continuous Monitoring (runs in background)
```bash
# Configure first
python3 5_monitor.py --domain example.com --discord https://hooks.discord.com/...

# Run once
python3 5_monitor.py --domain example.com --once

# Add tech stack for CVE monitoring  
python3 5_monitor.py --domain example.com --tech nginx wordpress php --interval 60
```

### Subdomain Takeover
```bash
python3 6_takeover.py results/example.com/subdomains/all_subdomains.txt
```

### Generate Report
```bash
python3 7_report.py --domain example.com --results ./results/example.com
```

---

## 📂 Output Structure

```
results/
└── example.com/
    ├── subdomains/
    │   ├── all_subdomains.txt     # All unique subdomains
    │   ├── subfinder.txt
    │   └── crtsh.txt
    ├── hosts/
    │   ├── live_urls.txt          # Live HTTP hosts
    │   └── live_hosts.json        # With tech/status info
    ├── ports/
    │   ├── open_ports.txt
    │   └── interesting_ports.txt  # FTP, SSH, RDP, Redis, etc.
    ├── endpoints/
    │   ├── all_urls.txt
    │   └── urls_with_params.txt   # For fuzzing
    ├── js/
    │   ├── js_files.txt
    │   └── js_analysis/
    │       ├── secrets.json       # 🔑 Exposed secrets
    │       ├── secrets.txt
    │       └── endpoints.txt
    ├── vulns/
    │   ├── nuclei/                # Nuclei findings
    │   ├── xss/                   # XSS candidates + confirmed
    │   ├── sqli/                  # SQLi candidates
    │   ├── ssrf/                  # SSRF candidates
    │   ├── open_redirect/
    │   ├── lfi/
    │   ├── cors/
    │   └── headers/
    ├── takeover/
    │   └── takeover_findings.json
    ├── recon_summary.txt
    ├── pipeline.log
    └── bug_bounty_report_example.com.md  # 📄 Final report
```

---

## 🔔 Notification Setup

Edit `monitor_config.json` (auto-generated on first run):

```json
{
  "domain": "example.com",
  "discord_webhook": "https://discord.com/api/webhooks/...",
  "slack_webhook": "https://hooks.slack.com/services/...",
  "telegram_token": "YOUR_BOT_TOKEN",
  "telegram_chat_id": "YOUR_CHAT_ID",
  "interval_minutes": 60,
  "tech_stack": ["nginx", "wordpress", "apache"]
}
```

---

## 🛠️ Required Tools (auto-installed by setup.sh)

**Go tools:** subfinder, httpx, nuclei, dnsx, naabu, katana, gau, waybackurls, ffuf, dalfox, anew, gf, qsreplace

**Python:** requests, jsbeautifier, arjun, rich, dnspython

**System:** nmap, curl, jq, dig

---

## ⚠️ Legal Notice

Only use on targets you are **authorized** to test.  
Always respect the program's **Rules of Engagement**.  
Never test out of scope assets.  
This toolkit is for **authorized bug bounty hunting only**.
