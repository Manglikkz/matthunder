"""
openredirect - Open Redirect scanner.

Tests URLs for open redirect vulnerabilities by injecting redirect payloads
into URL parameters and checking if the server follows to external domains.

Usage:
  python matthunder_cli.py openredirect example.com
"""

import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, crawl_domain,
    finish_scan, log, normalize_domain, open_db, utc_now_iso,
    merge_crawled_and_fallback, FALLBACK_PARAMS, FALLBACK_ENDPOINTS,
)


REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com@{}".format,
    "https://{}@evil.com".format,
    "https://evil.com#{}".format,
    "/%2f/evil.com",
    "///evil.com",
    # Protocol-relative
    "//evil.com",
    # Backslash tricks
    "https://evil.com\\@target.com",
    # Tab/newline injection
    "https://evil.com\t.target.com",
    "https://evil.com%09.target.com",
    "https://evil.com%0a.target.com",
    # Double URL encoding
    "https:%2f%2fevil.com",
    "https%3a%2f%2fevil.com",
]

PARAM_NAMES = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "return_to", "next", "next_url", "go", "goto", "target", "dest",
    "destination", "redir", "redirect_to", "checkout_url", "continue",
    "returnPath", "return_path", "to", "out", "view", "dir", "show",
    "page", "link", "ref", "reference", "site", "website", "html",
]


def _load_pipeline_urls() -> list[str]:
    """Load pre-discovered URLs from pipeline Phase 3."""
    url_file = os.environ.get("MT_PIPELINE_URLS", "")
    if url_file and os.path.exists(url_file):
        with open(url_file, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip().startswith("http")]
    return []


def _check_redirect(url: str, param: str, client: httpx.Client, domain: str) -> dict:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return {"vulnerable": False}

    for payload in REDIRECT_PAYLOADS:
        if callable(payload):
            payload = payload(domain)
        test_qs = dict(qs)
        test_qs[param] = [payload]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308):
                if "evil.com" in loc.lower():
                    return {
                        "vulnerable": True,
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "redirect_to": loc,
                        "status": r.status_code,
                    }
            # Also check meta refresh and JS redirect in body
            if r.status_code == 200 and "evil.com" in r.text.lower():
                return {
                    "vulnerable": True,
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "redirect_to": "body-reflection",
                    "status": r.status_code,
                }
        except Exception:
            continue

    return {"vulnerable": False}


def run(domain: str, max_pages: int = 50) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'openredirect', ?, ?, 'running', ?)",
        (domain, "param-fuzz", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"Open Redirect scan started - domain: {domain}")

    # Load pipeline URLs if available
    pipeline_urls = _load_pipeline_urls()
    if pipeline_urls:
        log(con, scan_id, f"Using {len(pipeline_urls)} pre-discovered URLs from pipeline")
        targets = merge_crawled_and_fallback(pipeline_urls, domain, "openredirect", max_pages)
    else:
        pages = crawl_domain(domain, max_pages=max_pages)
        log(con, scan_id, f"Crawled {len(pages)} pages")
        targets = []
        seen = set()
        for page_url, html in pages:
            parsed = urlparse(page_url)
            params = list(parse_qs(parsed.query).keys())
            for param in params:
                key = (page_url.split("?")[0], param)
                if key not in seen:
                    seen.add(key)
                    targets.append((page_url, param))
        # Add fallback endpoints
        base_urls = [f"https://{domain}", f"http://{domain}"]
        for base in base_urls:
            for endpoint in FALLBACK_ENDPOINTS:
                full = f"{base}{endpoint}"
                for param in FALLBACK_PARAMS["openredirect"][:6]:
                    key = (full, param)
                    if key not in seen:
                        seen.add(key)
                        targets.append((full, param))

    log(con, scan_id, f"Testing {len(targets)} URL+param targets")

    findings: list[dict] = []

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=False, timeout=DEFAULT_TIMEOUT) as client:
        for url, param in targets[:200]:
            result = _check_redirect(url, param, client, domain)
            if result.get("vulnerable"):
                findings.append(result)
                log(con, scan_id, f"Open Redirect: {url} param={param}")

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "open_redirect", f["url"], "vulnerable",
             f"param={f['param']} redirect_to={f['redirect_to']}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(targets), total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "openredirect", "domain": domain, "pages": len(targets), "findings": len(findings)}


SCANNER_REGISTRY["openredirect"] = run
SCANNER_REGISTRY["oredir"] = run
