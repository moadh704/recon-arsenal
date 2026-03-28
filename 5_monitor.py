#!/usr/bin/env python3
"""
5_MONITOR.PY — Continuous Asset & Change Monitor
Usage: python3 5_monitor.py --domain example.com [--notify discord]
       python3 5_monitor.py --config monitor_config.json

Runs continuously, alerting on:
  - New subdomains
  - New JS files or changes in existing ones
  - New endpoints appearing
  - New open ports
  - CVEs matching target tech stack
"""

import json
import time
import hashlib
import subprocess
import argparse
import requests
import re
import os
import smtplib
import ssl
from pathlib import Path
from datetime import datetime
from email.message import EmailMessage
import urllib3; urllib3.disable_warnings()

G='\033[92m'; Y='\033[93m'; R='\033[91m'; C='\033[96m'; B='\033[1m'; N='\033[0m'
def info(m):  print(f"{G}[+]{N} [{datetime.now().strftime('%H:%M:%S')}] {m}")
def warn(m):  print(f"{Y}[!]{N} [{datetime.now().strftime('%H:%M:%S')}] {m}")
def alert(m): print(f"{R}[🚨 ALERT]{N} [{datetime.now().strftime('%H:%M:%S')}] {m}")

# ══════════════════════════════════════════════════════════
# NOTIFICATION BACKENDS
# ══════════════════════════════════════════════════════════

def notify_discord(webhook_url: str, message: str, title: str = "🚨 Bug Bounty Alert"):
    """Send Discord webhook notification."""
    if not webhook_url:
        return
    payload = {
        "embeds": [{
            "title":       title,
            "description": message[:2000],
            "color":       15158332,  # Red
            "timestamp":   datetime.utcnow().isoformat(),
            "footer":      {"text": "Bug Bounty Monitor"}
        }]
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=5)
        r.raise_for_status()
    except Exception as e:
        warn(f"Discord notify failed: {e}")

def notify_slack(webhook_url: str, message: str):
    """Send Slack webhook notification."""
    if not webhook_url:
        return
    try:
        requests.post(webhook_url, json={"text": f"🚨 *Bug Bounty Alert*\n{message}"}, timeout=5)
    except Exception as e:
        warn(f"Slack notify failed: {e}")

def notify_telegram(bot_token: str, chat_id: str, message: str):
    """Send Telegram bot notification."""
    if not bot_token or not chat_id:
        return
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        requests.post(url, json={
            "chat_id": chat_id,
            "text": f"🚨 Bug Bounty Alert\n\n{message}",
            "parse_mode": "Markdown"
        }, timeout=5)
    except Exception as e:
        warn(f"Telegram notify failed: {e}")

def notify_email(config: dict, subject: str, body: str):
    """Send email notification."""
    smtp_cfg = config.get('email', {})
    if not smtp_cfg.get('enabled'):
        return
    try:
        msg = EmailMessage()
        msg['Subject'] = f"[Bug Bounty] {subject}"
        msg['From']    = smtp_cfg['from']
        msg['To']      = smtp_cfg['to']
        msg.set_content(body)
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_cfg['host'], smtp_cfg.get('port', 465), context=ctx) as s:
            s.login(smtp_cfg['user'], smtp_cfg['password'])
            s.send_message(msg)
    except Exception as e:
        warn(f"Email notify failed: {e}")

def notify_all(config: dict, message: str, title: str = "Bug Bounty Alert"):
    """Fire all configured notification channels."""
    alert(message)
    if config.get('discord_webhook'):
        notify_discord(config['discord_webhook'], message, title)
    if config.get('slack_webhook'):
        notify_slack(config['slack_webhook'], message)
    if config.get('telegram_token') and config.get('telegram_chat_id'):
        notify_telegram(config['telegram_token'], config['telegram_chat_id'], message)
    notify_email(config, title, message)

# ══════════════════════════════════════════════════════════
# MONITORING FUNCTIONS
# ══════════════════════════════════════════════════════════

def get_subdomains(domain: str) -> set[str]:
    """Run fast passive subdomain enum."""
    subs = set()
    
    # Subfinder
    try:
        result = subprocess.run(
            ['subfinder', '-d', domain, '-silent'],
            capture_output=True, text=True, timeout=120
        )
        subs.update(result.stdout.strip().splitlines())
    except Exception as e:
        warn(f"subfinder failed: {e}")
    
    # crt.sh
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20, verify=False
        )
        data = r.json()
        for entry in data:
            name = entry.get('name_value', '').replace('*.', '')
            if domain in name:
                subs.add(name.strip())
    except Exception as e:
        warn(f"crt.sh failed: {e}")

    return subs

def get_js_hashes(urls: list[str]) -> dict[str, str]:
    """Fetch JS files and compute their content hashes."""
    hashes = {}
    for url in urls:
        try:
            r = requests.get(url, timeout=10, verify=False, headers={
                'User-Agent': 'Mozilla/5.0'
            })
            if r.status_code == 200:
                hashes[url] = hashlib.md5(r.content).hexdigest()
        except Exception:
            pass
    return hashes

def get_live_hosts(subdomains: set[str]) -> set[str]:
    """Probe subdomains to find live HTTP hosts."""
    live = set()
    sub_list = '\n'.join(subdomains)
    try:
        result = subprocess.run(
            ['httpx', '-silent', '-status-code'],
            input=sub_list, capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.splitlines():
            if ' [200]' in line or ' [301]' in line or ' [302]' in line:
                url = line.split()[0]
                live.add(url)
    except Exception as e:
        warn(f"httpx failed: {e}")
    return live

def get_js_files_from_host(url: str) -> set[str]:
    """Extract JS file URLs from a live host."""
    js_files = set()
    try:
        r = requests.get(url, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text)
        for js in js_urls:
            if js.startswith('http'):
                js_files.add(js)
            else:
                from urllib.parse import urljoin
                js_files.add(urljoin(url, js))
    except Exception:
        pass
    return js_files

def check_cve_for_tech(tech_stack: list[str]) -> list[dict]:
    """Check NVD for recent CVEs matching the tech stack."""
    cves = []
    for tech in tech_stack:
        try:
            r = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech}&resultsPerPage=5",
                timeout=15
            )
            data = r.json()
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', '')
                desc = cve.get('descriptions', [{}])[0].get('value', '')
                metrics = cve.get('metrics', {})
                cvss = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                if float(cvss) >= 7.0:  # Only high/critical
                    cves.append({
                        "cve_id":  cve_id,
                        "tech":    tech,
                        "cvss":    cvss,
                        "summary": desc[:200]
                    })
        except Exception:
            pass
    return cves

# ══════════════════════════════════════════════════════════
# STATE MANAGEMENT
# ══════════════════════════════════════════════════════════

def load_state(state_file: str) -> dict:
    """Load previous monitoring state."""
    if Path(state_file).exists():
        return json.loads(Path(state_file).read_text())
    return {
        "subdomains": [],
        "live_hosts": [],
        "js_hashes":  {},
        "last_check": None,
    }

def save_state(state_file: str, state: dict):
    """Save monitoring state."""
    Path(state_file).write_text(json.dumps(state, indent=2, default=str))

# ══════════════════════════════════════════════════════════
# MAIN MONITOR LOOP
# ══════════════════════════════════════════════════════════

def run_check(domain: str, state: dict, config: dict) -> dict:
    """Run a full monitoring check and alert on changes."""
    info(f"Running check for {domain}...")
    changes = []

    # ── Subdomains ──────────────────────────────────────
    info("Checking subdomains...")
    current_subs = get_subdomains(domain)
    prev_subs    = set(state.get('subdomains', []))
    new_subs     = current_subs - prev_subs

    if new_subs:
        msg = f"🆕 *New subdomains* for {domain}:\n" + '\n'.join(f"  • {s}" for s in sorted(new_subs))
        notify_all(config, msg, "New Subdomains Found")
        changes.append({"type": "new_subdomains", "count": len(new_subs), "items": list(new_subs)})

    state['subdomains'] = list(current_subs)

    # ── Live hosts ──────────────────────────────────────
    if new_subs:
        info("Probing new subdomains...")
        new_live = get_live_hosts(new_subs)
        if new_live:
            msg = f"🌐 *New live hosts* found:\n" + '\n'.join(f"  • {h}" for h in sorted(new_live))
            notify_all(config, msg, "New Live Hosts")
            changes.append({"type": "new_live_hosts", "items": list(new_live)})
            state.setdefault('live_hosts', [])
            state['live_hosts'].extend(list(new_live))

    # ── JS file changes ─────────────────────────────────
    info("Checking JS files for changes...")
    all_live = set(state.get('live_hosts', []))
    all_js   = set()
    for host in list(all_live)[:20]:  # Limit scope
        all_js.update(get_js_files_from_host(host))

    current_hashes = get_js_hashes(list(all_js))
    prev_hashes    = state.get('js_hashes', {})

    changed_js = []
    new_js     = []
    for url, h in current_hashes.items():
        if url not in prev_hashes:
            new_js.append(url)
        elif prev_hashes[url] != h:
            changed_js.append(url)

    if new_js:
        msg = f"📄 *New JS files* detected:\n" + '\n'.join(f"  • {u}" for u in new_js[:10])
        notify_all(config, msg, "New JS Files")
        changes.append({"type": "new_js_files", "items": new_js})

    if changed_js:
        msg = f"✏️ *JS files changed* (may have new endpoints/secrets):\n" + \
              '\n'.join(f"  • {u}" for u in changed_js[:10])
        notify_all(config, msg, "JS Files Changed")
        changes.append({"type": "changed_js_files", "items": changed_js})

    state['js_hashes'] = current_hashes

    # ── CVE Monitoring ───────────────────────────────────
    tech_stack = config.get('tech_stack', [])
    if tech_stack and state.get('cve_check_interval', 0) % 6 == 0:  # Every 6 checks
        info("Checking CVEs for tech stack...")
        cves = check_cve_for_tech(tech_stack)
        prev_cves = set(state.get('seen_cves', []))
        new_cves  = [c for c in cves if c['cve_id'] not in prev_cves]
        if new_cves:
            msg = f"⚠️ *New CVEs* matching your tech stack:\n"
            for c in new_cves:
                msg += f"  • {c['cve_id']} (CVSS: {c['cvss']}) — {c['tech']}\n    {c['summary']}\n"
            notify_all(config, msg, "New CVEs Detected")
            state.setdefault('seen_cves', [])
            state['seen_cves'].extend([c['cve_id'] for c in new_cves])

    state['cve_check_interval'] = state.get('cve_check_interval', 0) + 1
    state['last_check'] = datetime.now().isoformat()

    if not changes:
        info(f"No changes detected. Next check in {config.get('interval_minutes', 60)} min")
    
    return state

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain',           help='Target domain')
    parser.add_argument('--config',           default='monitor_config.json', help='Config file')
    parser.add_argument('--discord',          help='Discord webhook URL')
    parser.add_argument('--slack',            help='Slack webhook URL')
    parser.add_argument('--telegram-token',   help='Telegram bot token')
    parser.add_argument('--telegram-chat',    help='Telegram chat ID')
    parser.add_argument('--interval',         type=int, default=60, help='Check interval (minutes)')
    parser.add_argument('--tech',             nargs='+', default=[], help='Tech stack (e.g. nginx wordpress)')
    parser.add_argument('--state',            default='monitor_state.json', help='State file')
    parser.add_argument('--once',             action='store_true', help='Run once and exit')
    args = parser.parse_args()

    # Load or build config
    config = {}
    if Path(args.config).exists():
        config = json.loads(Path(args.config).read_text())

    # CLI args override config
    if args.domain:           config['domain']          = args.domain
    if args.discord:          config['discord_webhook'] = args.discord
    if args.slack:            config['slack_webhook']   = args.slack
    if args.telegram_token:   config['telegram_token']  = args.telegram_token
    if args.telegram_chat:    config['telegram_chat_id']= args.telegram_chat
    if args.tech:             config['tech_stack']      = args.tech
    config['interval_minutes'] = args.interval

    domain = config.get('domain')
    if not domain:
        print("Error: --domain required")
        sys.exit(1)

    # Save config template if not exists
    if not Path(args.config).exists():
        sample = {
            "domain":           domain,
            "discord_webhook":  "https://discord.com/api/webhooks/YOUR/WEBHOOK",
            "slack_webhook":    "",
            "telegram_token":   "",
            "telegram_chat_id": "",
            "interval_minutes": 60,
            "tech_stack":       ["nginx", "apache", "wordpress"],
            "email": {
                "enabled":  False,
                "host":     "smtp.gmail.com",
                "port":     465,
                "user":     "you@gmail.com",
                "password": "app_password",
                "from":     "you@gmail.com",
                "to":       "you@gmail.com"
            }
        }
        Path(args.config).write_text(json.dumps(sample, indent=2))
        info(f"Config template saved → {args.config} (edit it with your webhook URLs)")

    info(f"Starting monitor for: {domain}")
    info(f"Check interval: {config['interval_minutes']} minutes")
    info(f"State file: {args.state}")

    while True:
        state = load_state(args.state)
        state = run_check(domain, state, config)
        save_state(args.state, state)

        if args.once:
            break

        interval_secs = config['interval_minutes'] * 60
        info(f"Sleeping {config['interval_minutes']} minutes until next check...")
        time.sleep(interval_secs)

if __name__ == '__main__':
    main()
