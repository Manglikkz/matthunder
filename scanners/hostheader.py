"""
hostheader - Host Header Injection scanner.

Tests for host header injection via:
- Password reset poisoning
- Cache poisoning
- Virtual host routing bypass
- SSRF via Host header

Usage:
  python matthunder_cli.py hostheader example.com
"""

import re
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    finish_scan, log, normalize_domain, open_db, utc_now_iso,
)


# ── Host Header Variations ────────────────────────────────────────────────

HOST_PAYLOADS = [
    ("evil.com", "direct_injection"),
    ("evil.com:80", "port_injection"),
    ("evil.com:443", "port_injection_443"),
    ("evil.com:8080", "port_injection_8080"),
    ("evil.com%0d%0aX-Injected:true", "crlf_injection"),
    ("evil.com%0aX-Injected:true", "lf_injection"),
    ("evil.com\\r\\nX-Injected:true", "crlf_backslash"),
    (".evil.com", "dot_prefix"),
    ("evil.com%00", "null_byte"),
    ("evil.com%09", "tab_injection"),
    ("127.0.0.1", "localhost_ip"),
    ("[::1]", "ipv6_loopback"),
    ("0x7f000001", "hex_ip"),
    ("2130706433", "decimal_ip"),
    ("0177.0.0.1", "octal_ip"),
]

# ── X-Forwarded-Host Variations ──────────────────────────────────────────

FORWARDED_HOST_PAYLOADS = [
    "evil.com",
    "evil.com:80",
    "evil.com:443",
    "evil.com:8080",
]


def _load_pipeline_urls() -> list[str]:
    url_file = os.environ.get("MT_PIPELINE_URLS", "")
    if url_file and os.path.exists(url_file):
        with open(url_file, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip().startswith("http")]
    return []


def _probe_host_header(url: str, client: httpx.Client, domain: str) -> list[dict]:
    """Test Host header injection on a URL."""
    findings = []

    for payload, payload_type in HOST_PAYLOADS:
        headers = {
            "User-Agent": USER_AGENT,
            "Host": payload,
        }
        try:
            r = client.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
        except Exception:
            continue

        body = r.text or ""
        loc = r.headers.get("Location", "")

        # Check 1: Host reflected in response body
        if payload.split(":")[0] in body and "evil.com" in body:
            findings.append({
                "url": url,
                "payload": f"Host: {payload}",
                "evidence": "host_reflected_in_body",
                "type": payload_type,
                "status": r.status_code,
            })
            break  # One finding per URL is enough

        # Check 2: Host reflected in Location header (redirect to attacker)
        if "evil.com" in loc.lower():
            findings.append({
                "url": url,
                "payload": f"Host: {payload}",
                "evidence": f"redirect_to_{loc}",
                "type": f"{payload_type}_redirect",
                "status": r.status_code,
            })
            break

        # Check 3: CRLF injection via Host header
        if "x-injected" in {k.lower(): v for k, v in r.headers.items()}:
            findings.append({
                "url": url,
                "payload": f"Host: {payload}",
                "evidence": "crlf_header_injection",
                "type": "crlf_injection",
                "status": r.status_code,
            })
            break

        # Check 4: Status code anomaly (200 when should be 301/302/404)
        if r.status_code == 200:
            # Get baseline with normal host
            try:
                bl = client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
                if bl.status_code != 200:
                    # Possible virtual host routing bypass
                    if payload.split(":")[0] not in ("127.0.0.1", "[::1]", "0x7f000001", "2130706433", "0177.0.0.1"):
                        findings.append({
                            "url": url,
                            "payload": f"Host: {payload}",
                            "evidence": f"vhost_bypass_{r.status_code}_vs_{bl.status_code}",
                            "type": "virtual_host_bypass",
                            "status": r.status_code,
                        })
            except Exception:
                pass

    return findings


def _probe_x_forwarded_host(url: str, client: httpx.Client, domain: str) -> list[dict]:
    """Test X-Forwarded-Host header injection."""
    findings = []

    for payload in FORWARDED_HOST_PAYLOADS:
        headers = {
            "User-Agent": USER_AGENT,
            "X-Forwarded-Host": payload,
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
        }
        try:
            r = client.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
        except Exception:
            continue

        body = r.text or ""
        loc = r.headers.get("Location", "")

        # Check if X-Forwarded-Host is used in response
        if "evil.com" in loc.lower():
            findings.append({
                "url": url,
                "payload": f"X-Forwarded-Host: {payload}",
                "evidence": f"redirect_to_{loc}",
                "type": "x_forwarded_host_redirect",
                "status": r.status_code,
            })
            break

        if payload in body or "evil.com" in body:
            findings.append({
                "url": url,
                "payload": f"X-Forwarded-Host: {payload}",
                "evidence": "x_forwarded_host_reflected",
                "type": "x_forwarded_host_reflected",
                "status": r.status_code,
            })
            break

    return findings


def _probe_cache_poisoning(url: str, client: httpx.Client, domain: str) -> list[dict]:
    """Test for web cache poisoning via host header."""
    findings = []

    # Send poisoned request
    poison_headers = {
        "User-Agent": USER_AGENT,
        "Host": "evil.com",
        "X-Forwarded-Host": "evil.com",
    }
    try:
        r1 = client.get(url, headers=poison_headers, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
    except Exception:
        return []

    # Check if response is cacheable
    cache_control = r1.headers.get("Cache-Control", "")
    if "no-store" in cache_control.lower() or "private" in cache_control.lower():
        return []

    age = r1.headers.get("Age", "")
    if age and int(age) > 0:
        # Response is cached — check if poisoned content is served
        try:
            r2 = client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
            if "evil.com" in (r2.text or ""):
                findings.append({
                    "url": url,
                    "payload": "Host: evil.com + X-Forwarded-Host: evil.com",
                    "evidence": "cache_poisoned_content",
                    "type": "cache_poisoning",
                    "status": r2.status_code,
                })
        except Exception:
            pass

    return findings


def run(domain: str, max_pages: int = 20) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'hostheader', ?, ?, 'running', ?)",
        (domain, "host+xfwd+cache", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"Host Header Injection scan started - domain: {domain}")

    # Crawl for pages to test
    pipeline_urls = _load_pipeline_urls()
    if pipeline_urls:
        log(con, scan_id, f"Using {len(pipeline_urls)} pre-discovered URLs from pipeline")
        pages = [(u, "") for u in pipeline_urls[:30]]
    else:
        pages = crawl_domain(domain, max_pages=max_pages)
        log(con, scan_id, f"Crawled {len(pages)} pages")

    # Always test the main URL
    test_urls = list(set([url for url, _ in pages[:30]]))
    if f"https://{domain}" not in test_urls:
        test_urls.insert(0, f"https://{domain}")
    if f"http://{domain}" not in test_urls:
        test_urls.insert(1, f"http://{domain}")

    findings: list[dict] = []

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=False, timeout=DEFAULT_TIMEOUT) as client:
        for url in test_urls:
            # Host header injection
            results = _probe_host_header(url, client, domain)
            for r in results:
                log(con, scan_id, f"Host header injection: {url} type={r['type']}")
            findings.extend(results)

            # X-Forwarded-Host injection
            results = _probe_x_forwarded_host(url, client, domain)
            for r in results:
                log(con, scan_id, f"X-Forwarded-Host injection: {url} type={r['type']}")
            findings.extend(results)

            # Cache poisoning (slower, run less often)
            results = _probe_cache_poisoning(url, client, domain)
            for r in results:
                log(con, scan_id, f"Cache poisoning: {url}")
            findings.extend(results)

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f["url"], f["type"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    log(con, scan_id, f"Found {len(unique)} host header injection findings")

    for f in unique:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"hostheader_{f['type']}", f["url"], "vulnerable",
             f"payload={f['payload']} evidence={f['evidence']}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(test_urls), total_links=len(unique))
    con.close()
    return {"scan_id": scan_id, "scanner": "hostheader", "domain": domain, "pages": len(test_urls), "findings": len(unique)}


SCANNER_REGISTRY["hostheader"] = run
SCANNER_REGISTRY["host"] = run
