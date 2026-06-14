"""
CORS - Cross-Origin Resource Sharing misconfiguration scanner.

Probes each in-scope page with malicious Origin headers and inspects
Access-Control-Allow-* response headers. Inspired by Corsy patterns.

Detects:
  - Reflected arbitrary origin + credentials
  - Null origin accepted
  - Wildcard ACAO with credentials
  - Subdomain-regex bypasses
"""

from urllib.parse import urlparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    finish_scan, log, normalize_domain, open_db, utc_now_iso,
)


PROBE_ORIGINS = [
    "https://evil.com",
    "https://attacker.io",
    "null",
    "https://sub.evil.com",
]


def _classify(acao: str, acac: str, origin_sent: str) -> str:
    acao_l = (acao or "").strip()
    acac_l = (acac or "").strip().lower()
    origin_l = (origin_sent or "").strip().lower()
    if not acao_l:
        return "no_acao"
    if acao_l == "*":
        if acac_l == "true":
            return "wildcard_with_credentials"
        return "wildcard"
    if acao_l.lower() == origin_l:
        if acac_l == "true":
            return "reflected_with_credentials"
        return "reflected"
    if acao_l == "null" and origin_l == "null":
        if acac_l == "true":
            return "null_with_credentials"
        return "null_origin"
    if origin_l.endswith(acao_l.lstrip("*").lstrip(".")):
        if acac_l == "true":
            return "regex_bypass_with_credentials"
        return "regex_bypass"
    return "ok"


def run(domain: str, max_pages: int = 20) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'cors', ?, ?, 'running', ?)",
        (domain, "default", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"CORS scan started - domain: {domain}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    findings: list[dict] = []
    tested = 0
    with httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        for page_url, _ in pages:
            for origin in PROBE_ORIGINS:
                headers = {"Origin": origin}
                try:
                    r = client.get(page_url, headers=headers, timeout=DEFAULT_TIMEOUT)
                except Exception:
                    continue
                tested += 1
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "")
                verdict = _classify(acao, acac, origin)
                if verdict in ("reflected_with_credentials", "null_with_credentials",
                               "wildcard_with_credentials", "regex_bypass_with_credentials",
                               "reflected", "null_origin", "regex_bypass"):
                    findings.append({
                        "url": page_url,
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "verdict": verdict,
                    })

    seen = set()
    unique = []
    for f in findings:
        key = (f["url"], f["origin"], f["verdict"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    log(con, scan_id, f"Found {len(unique)} CORS findings in {tested} probes")

    for f in unique:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"cors_{f['verdict']}", f["url"], "vulnerable", f"origin={f['origin']} acao={f['acao']} acac={f['acac']}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(unique))
    con.close()
    return {"scan_id": scan_id, "scanner": "cors", "domain": domain, "pages": len(pages), "probes": tested, "findings": len(unique)}


SCANNER_REGISTRY["cors"] = run
