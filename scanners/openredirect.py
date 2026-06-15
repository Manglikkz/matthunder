"""
openredirect - Open Redirect scanner.

Tests URLs for open redirect vulnerabilities by injecting redirect payloads
into URL parameters and checking if the server follows to external domains.

Usage:
  python matthunder_cli.py openredirect example.com
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, crawl_domain,
    finish_scan, log, normalize_domain, open_db, utc_now_iso,
)


REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%00.{}".format,
    "https://evil.com@{}".format,
    "https://{}@evil.com".format,
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https://evil.com#{}".format,
    "/%2f/evil.com",
    "///evil.com",
    "https://evil.com%23.{}".format,
]

PARAM_NAMES = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "return_to", "next", "next_url", "go", "goto", "target", "dest",
    "destination", "redir", "redirect_to", "checkout_url", "continue",
    "returnPath", "return_path", "to", "out", "view", "dir", "show",
    "page", "link", "ref", "reference", "site", "website", "html",
]


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


def run(domain: str, max_pages: int = 30) -> dict:
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

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    findings: list[dict] = []

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=False, timeout=DEFAULT_TIMEOUT) as client:
        for page_url, html in pages:
            parsed = urlparse(page_url)
            params = list(parse_qs(parsed.query).keys())
            if not params:
                continue
            for param in params:
                result = _check_redirect(page_url, param, client, domain)
                if result.get("vulnerable"):
                    findings.append(result)
                    log(con, scan_id, f"Open Redirect: {page_url} param={param}")

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "open_redirect", f["url"], "vulnerable",
             f"param={f['param']} redirect_to={f['redirect_to']}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "openredirect", "domain": domain, "pages": len(pages), "findings": len(findings)}


SCANNER_REGISTRY["openredirect"] = run
SCANNER_REGISTRY["oredir"] = run
