"""
gfpatterns - GF-style URL pattern filtering.

Inspired by:
  - Claude flow: gf patterns (filter URL by vuln type)
  - tomnomnom/gf tool
  - shuvonsec/claude-bug-bounty security-arsenal

Filters crawled URLs into vulnerability-specific categories using regex patterns.
Helps prioritize which URLs to test for specific vuln classes.

Usage:
  python matthunder_cli.py gfpatterns example.com
"""

import re
from urllib.parse import urlparse, parse_qs

from . import SCANNER_REGISTRY
from .common import (
    crawl_domain, finish_scan, log, normalize_domain, open_db, utc_now_iso,
)


# GF-style patterns (regex → category)
GF_PATTERNS = {
    "sqli": [
        re.compile(r'[?&](id|uid|pid|cat|cid|item|page|user|order|sort|type|search|query|keyword|name|file|table|column|limit|offset|row|count|num|ref|lang|country|city|state|zip|year|month|day)=', re.I),
        re.compile(r'\.(php|asp|aspx|jsp|cgi)\?', re.I),
        re.compile(r'(union|select|insert|update|delete|drop|concat|char|substr)\b', re.I),
    ],
    "xss": [
        re.compile(r'[?&](q|s|search|query|keyword|text|msg|message|comment|name|title|content|body|input|value|data|desc|description|info|note|subject|ref|url|page|callback|jsonp)=', re.I),
        re.compile(r'(javascript:|data:|vbscript:)', re.I),
    ],
    "ssrf": [
        re.compile(r'[?&](url|uri|link|src|href|dest|redirect|redirect_uri|redirect_url|return|return_url|next|next_url|callback|callback_url|target|feed|host|hostname|proxy|proxy_url|image|img|icon|avatar|logo|banner|background|file|path|page|load|fetch|goto|out|view|show|display|open|source|reference|ref|site|website|web|domain|dns|ip|addr|address)=', re.I),
        re.compile(r'(169\.254\.169\.254|metadata\.google|localhost|127\.0\.0\.1|0\.0\.0\.0|\[::\])', re.I),
    ],
    "lfi": [
        re.compile(r'[?&](file|path|dir|folder|include|require|page|template|document|pdf|doc|log|config|conf|cfg|ini|env|secret|key|backup|dump|sql|db|data|read|load|show|view|display|cat|cmd|exec|run|command|shell|bash|sh|powershell|ps|bat|cmd)=', re.I),
        re.compile(r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)', re.I),
    ],
    "idor": [
        re.compile(r'[?&](id|uid|user_id|account|account_id|profile|profile_id|order|order_id|invoice|invoice_id|transaction|transaction_id|payment|payment_id|document|doc_id|file|file_id|message|msg_id|ticket|ticket_id|comment|comment_id|post|post_id|member|member_id|patient|student|employee)=\d+', re.I),
        re.compile(r'/(user|account|profile|order|invoice|document|file|message|ticket|member|patient|student|employee)/\d+', re.I),
    ],
    "redirect": [
        re.compile(r'[?&](url|redirect|redirect_uri|redirect_url|return|return_url|return_to|next|next_url|go|goto|target|dest|destination|out|view|show|link|ref|forward|to|continue|checkout_url|returnPath|return_path)=', re.I),
        re.compile(r'(https?://|//|\\\\)', re.I),
    ],
    "rce": [
        re.compile(r'[?&](cmd|command|exec|execute|run|shell|bash|sh|powershell|ps|bat|cmd|ping|nslookup|dig|traceroute|wget|curl|eval|assert|system|passthru|popen|proc_open|pcntl_exec|python|perl|ruby|php|node|java)=', re.I),
        re.compile(r'(;|\||`|\$\(|\$\{)', re.I),
    ],
    "ssti": [
        re.compile(r'[?&](template|tpl|view|render|page|name|title|content|body|text|msg|message|comment|input|data|desc|description|info|note|subject)=', re.I),
        re.compile(r'(\{\{|\}\}|<%|%>|\$\{)', re.I),
    ],
    "debug": [
        re.compile(r'(debug|trace|test|dev|staging|beta|internal|admin|console|dashboard|monitor|status|health|info|env|config|settings|log|logs)', re.I),
    ],
    "api": [
        re.compile(r'/api/', re.I),
        re.compile(r'/v[0-9]+/', re.I),
        re.compile(r'(graphql|swagger|openapi|rest|soap|grpc)', re.I),
    ],
    "secrets": [
        re.compile(r'[?&](key|token|secret|api_key|apikey|api-key|access_token|auth_token|bearer|password|passwd|pwd|credential|private|secret_key)=', re.I),
        re.compile(r'(AKIA|gh[pousr]_|glpat-|xox[baprs]-|sk_(test|live)_)', re.I),
    ],
}


def run(domain: str, max_pages: int = 50) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'gfpatterns', ?, ?, 'running', ?)",
        (domain, "regex-filter", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"GF patterns scan started - domain: {domain}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    # Collect all URLs (from pages + historical)
    all_urls = set()
    for page_url, _ in pages:
        all_urls.add(page_url)

    # Also try gau for historical URLs
    import shutil
    import subprocess
    gau = shutil.which("gau")
    if gau:
        try:
            proc = subprocess.run([gau, "--subs", domain], capture_output=True, text=True, timeout=60)
            for line in proc.stdout.splitlines():
                url = line.strip()
                if url:
                    all_urls.add(url)
        except Exception:
            pass

    log(con, scan_id, f"Total URLs to filter: {len(all_urls)}")

    # Apply patterns
    categorized: dict[str, list[str]] = {cat: [] for cat in GF_PATTERNS}
    for url in all_urls:
        for category, patterns in GF_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(url):
                    if url not in categorized[category]:
                        categorized[category].append(url)
                    break

    # Store and report
    total = 0
    print(f"\n  \033[1m  GF Patterns — {domain}\033[0m")
    for category, urls in sorted(categorized.items(), key=lambda x: -len(x[1])):
        if urls:
            total += len(urls)
            status = f"\033[92m{len(urls)}\033[0m" if len(urls) > 0 else f"\033[90m{len(urls)}\033[0m"
            print(f"  {status} {category}")
            con.execute(
                "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, f"gf_{category}", domain, "found",
                 f"{len(urls)} URLs matching {category} pattern", utc_now_iso()),
            )

    if not any(categorized.values()):
        print(f"  \033[90m[-]\033[0m No pattern matches found")

    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(all_urls), total_links=total)
    con.close()

    return {
        "scan_id": scan_id,
        "scanner": "gfpatterns",
        "domain": domain,
        "total_urls": len(all_urls),
        "categorized": {k: len(v) for k, v in categorized.items() if v},
        "total": total,
    }


SCANNER_REGISTRY["gfpatterns"] = run
SCANNER_REGISTRY["gf"] = run
