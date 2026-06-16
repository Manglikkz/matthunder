"""
attackrank - Attack Surface Ranker.

Inspired by:
  - shuvonsec/claude-bug-bounty recon-ranker agent
  - Claude-BugHunter ranked surface output
  - ChatGPT: Prioritization step (Admin > API > File Upload > GraphQL)
  - Grok: "Two-Eye" approach (deep dive on interesting targets)

Ranks live subdomains by attack value based on naming patterns,
technology detected, and response characteristics.

Usage:
  python matthunder_cli.py attackrank example.com
"""

import os
import re
import shutil
import subprocess
from typing import Optional

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, finish_scan, log, normalize_domain,
    open_db, utc_now_iso,
)

import httpx


# Priority scoring (higher = more interesting)
PRIORITY_PATTERNS = [
    # Critical (10 points)
    (r'(admin|administrator|manage|management|dashboard|console)', 10, "Admin panel"),
    (r'(api|graphql|gql|rest|soap|grpc)', 8, "API endpoint"),
    (r'(auth|login|signin|sso|oauth|saml|cas)', 8, "Auth endpoint"),
    (r'(upload|file|import|export|download)', 7, "File operation"),
    (r'(payment|pay|checkout|billing|invoice|transaction|stripe|paypal)', 7, "Payment flow"),
    (r'(internal|intranet|private|corp|corporate)', 7, "Internal asset"),

    # High (5 points)
    (r'(dev|development|test|testing|staging|stage|beta|alpha|qa|uat|sandbox)', 5, "Dev/Staging"),
    (r'(debug|trace|monitor|status|health|metrics|prometheus|grafana)', 5, "Debug/Monitor"),
    (r'(db|database|mysql|postgres|mongo|redis|elastic|phpmyadmin|adminer)', 5, "Database"),
    (r'(jenkins|gitlab|github|bitbucket|ci|cd|build|deploy|k8s|kubernetes|docker)', 5, "CI/CD"),
    (r'(vpn|remote|rdp|ssh|telnet|vnc)', 5, "Remote access"),
    (r'(mail|smtp|imap|pop3|webmail|exchange|owa)', 5, "Email"),
    (r'(backup|bak|old|archive|snapshot|dump)', 5, "Backup/Archive"),
    (r'(config|cfg|conf|settings|env|configuration)', 5, "Config"),

    # Medium (3 points)
    (r'(cdn|static|assets|media|img|images|files)', 3, "Static/CDN"),
    (r'(blog|news|docs|documentation|wiki|help|support|kb)', 3, "Docs/Content"),
    (r'(search|find|query)', 3, "Search"),
    (r'(proxy|gateway|load|balancer|lb)', 3, "Proxy/Gateway"),
    (r'(mobile|app|android|ios|m\.)', 3, "Mobile"),

    # Low (1 point)
    (r'(www|web|site|main|home|root)', 1, "Main site"),
    (r'(static|cdn|assets)', 1, "Static"),
]


def _score_host(host: str) -> tuple[int, str]:
    """Score a hostname by attack value."""
    max_score = 0
    best_reason = "General"

    for pattern, score, reason in PRIORITY_PATTERNS:
        if re.search(pattern, host, re.I):
            if score > max_score:
                max_score = score
                best_reason = reason

    return max_score, best_reason


def _resolve(name: str) -> Optional[str]:
    return shutil.which(name)


def _get_live_hosts(domain: str, sub_file: str) -> list[str]:
    """Get live hosts from subdomain file using httpx."""
    httpx_bin = _resolve("httpx")
    if not httpx_bin:
        go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", "httpx")
        if os.path.exists(go_bin):
            httpx_bin = go_bin
    if not httpx_bin or not os.path.exists(sub_file):
        # Fallback: just read the file
        if os.path.exists(sub_file):
            with open(sub_file) as f:
                return [l.strip() for l in f if l.strip()]
        return []

    try:
        proc = subprocess.run(
            [httpx_bin, "-l", sub_file, "-silent", "-title", "-status-code"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=180,
        )
        hosts = []
        for line in proc.stdout.splitlines():
            parts = line.split()
            if parts:
                host = parts[0].replace("https://", "").replace("http://", "").split("/")[0]
                if host not in hosts:
                    hosts.append(host)
        return hosts
    except Exception:
        return []


def run(domain: str) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'attackrank', ?, ?, 'running', ?)",
        (domain, "priority-scoring", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"Attack surface ranking started - domain: {domain}")

    # Load subdomains
    sub_file = os.path.join("subdomain", f"{domain}.txt")
    hosts = _get_live_hosts(domain, sub_file)

    if not hosts:
        # Try to generate
        subfinder = _resolve("subfinder")
        if subfinder:
            try:
                proc = subprocess.run(
                    [subfinder, "-d", domain, "-silent"],
                    capture_output=True, encoding="utf-8", errors="replace", timeout=60,
                )
                hosts = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            except Exception:
                pass

    log(con, scan_id, f"Ranking {len(hosts)} hosts")

    # Score and rank
    ranked = []
    for host in hosts:
        score, reason = _score_host(host)
        ranked.append({"host": host, "score": score, "reason": reason})

    ranked.sort(key=lambda x: -x["score"])

    # Print ranked surface
    print(f"\n  \033[1m  Attack Surface Ranking — {domain}\033[0m")
    print(f"  {'─'*55}")

    # Group by tier
    critical = [r for r in ranked if r["score"] >= 7]
    high = [r for r in ranked if 4 <= r["score"] < 7]
    medium = [r for r in ranked if 2 <= r["score"] < 4]
    low = [r for r in ranked if r["score"] < 2]

    if critical:
        print(f"\n  \033[91m  CRITICAL (score ≥7) — Test FIRST\033[0m")
        for r in critical[:10]:
            print(f"    \033[91m[★]\033[0m {r['host']:<40} {r['reason']}")
            con.execute(
                "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, "rank_critical", r["host"], "critical",
                 f"score={r['score']} type={r['reason']}", utc_now_iso()),
            )

    if high:
        print(f"\n  \033[93m  HIGH (score 4-6) — Test second\033[0m")
        for r in high[:10]:
            print(f"    \033[93m[!]\033[0m {r['host']:<40} {r['reason']}")

    if medium:
        print(f"\n  \033[96m  MEDIUM (score 2-3) — Test if time allows\033[0m")
        for r in medium[:10]:
            print(f"    \033[96m[i]\033[0m {r['host']:<40} {r['reason']}")

    if low:
        print(f"\n  \033[90m  LOW (score 0-1) — Skip unless nothing else\033[0m")
        for r in low[:5]:
            print(f"    \033[90m[-]\033[0m {r['host']:<40} {r['reason']}")
        if len(low) > 5:
            print(f"    \033[90m    ... and {len(low)-5} more\033[0m")

    print(f"\n  {'─'*55}")
    print(f"  Total: {len(ranked)} hosts | Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)} | Low: {len(low)}")
    print()

    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(hosts), total_links=len(ranked))
    con.close()

    return {
        "scan_id": scan_id,
        "scanner": "attackrank",
        "domain": domain,
        "total": len(ranked),
        "critical": len(critical),
        "high": len(high),
        "medium": len(medium),
        "low": len(low),
        "top_targets": [r["host"] for r in critical[:5]],
        "findings": len(critical) + len(high),
    }


SCANNER_REGISTRY["attackrank"] = run
SCANNER_REGISTRY["rank"] = run
