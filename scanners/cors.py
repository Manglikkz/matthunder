"""
cors - Cross-Origin Resource Sharing misconfiguration scanner.

Probes each in-scope page with malicious Origin headers and inspects
Access-Control-Allow-* response headers. Inspired by Corsy patterns.

Detects:
  - Reflected arbitrary origin + credentials
  - Null origin accepted
  - Wildcard ACAO with credentials
  - Subdomain-regex bypasses
"""

import os
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
    "http://evil.com",
    "https://target.com.evil.com",
    "https://evil.com%60.target.com",
    "https://evil%0a.com",
    "https://evil.com%0d%0a.origin",
    "https://target.com%60.evil.com",
]


def _classify(acao: str, acac: str, origin_sent: str, vary_origin: str = "") -> str:
    acao_l = (acao or "").strip()
    acac_l = (acac or "").strip().lower()
    origin_l = (origin_sent or "").strip().lower()
    vary_l = (vary_origin or "").strip().lower()
    if not acao_l:
        return "no_acao"
    if acao_l == "*":
        if acac_l == "true":
            return "wildcard_with_credentials"
        return "wildcard"
    if acao_l == "null" and origin_l == "null":
        if acac_l == "true":
            return "null_with_credentials"
        return "null_origin"
    if acao_l.lower() == origin_l:
        if acac_l == "true":
            return "reflected_with_credentials"
        # Check if Vary: Origin is set — without it, CDN/cache may serve reflected origin
        if vary_l and "origin" in vary_l:
            return "reflected_dynamic"
        return "reflected"
    # Subdomain regex bypass: check if ACAO matches a wildcard pattern for the origin
    # e.g., ACAO=*.example.com, origin=https://sub.example.com
    if origin_l.startswith("https://") or origin_l.startswith("http://"):
        origin_host = origin_l.split("//", 1)[1].split("/")[0]
        acao_host = acao_l.split("//", 1)[1].split("/")[0] if "//" in acao_l else acao_l
        if acao_host.startswith("*."):
            # Wildcard subdomain pattern — check if origin matches
            suffix = acao_host[1:]  # .example.com
            if origin_host.endswith(suffix):
                if acac_l == "true":
                    return "regex_bypass_with_credentials"
                return "regex_bypass"
        # Domain confusion: evil.com.target.com accepted as same-origin
        if origin_host.endswith("." + acao_host):
            if acac_l == "true":
                return "domain_confusion_with_credentials"
            return "domain_confusion"
        # Protocol mismatch: http:// accepted when https:// expected
        if acac_l == "true" and acao_l:
            acao_no_proto = acao_l.replace("https://", "http://")
            origin_no_proto = origin_l.replace("https://", "http://")
            if acao_no_proto == origin_no_proto and acao_l != origin_l:
                return "protocol_mismatch_with_credentials"
    return "ok"


def _load_pipeline_urls() -> list[str]:
    """Load pre-discovered URLs from pipeline Phase 3."""
    url_file = os.environ.get("MT_PIPELINE_URLS", "")
    if url_file and os.path.exists(url_file):
        with open(url_file, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip().startswith("http")]
    return []


def run(domain: str, max_pages: int = 30) -> dict:
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

    # Load pipeline URLs if available
    pipeline_urls = _load_pipeline_urls()
    pages = []
    if pipeline_urls:
        log(con, scan_id, f"Using {len(pipeline_urls)} pre-discovered URLs from pipeline")
        seen = set()
        for u in pipeline_urls:
            if u not in seen:
                seen.add(u)
                pages.append((u, ""))
    else:
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
                vary = r.headers.get("vary", "")
                verdict = _classify(acao, acac, origin, vary)
                if verdict in ("reflected_with_credentials", "null_with_credentials",
                               "wildcard_with_credentials", "regex_bypass_with_credentials",
                               "domain_confusion_with_credentials", "protocol_mismatch_with_credentials",
                               "reflected_dynamic", "null_origin", "regex_bypass", "domain_confusion"):
                    findings.append({
                        "url": page_url,
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "verdict": verdict,
                    })
                # Also test preflight (OPTIONS) for endpoints that may only set CORS there
                if verdict in ("no_acao", "ok"):
                    try:
                        preflight_headers = {
                            "Origin": origin,
                            "Access-Control-Request-Method": "GET",
                            "Access-Control-Request-Headers": "Authorization",
                        }
                        r2 = client.options(page_url, headers=preflight_headers, timeout=DEFAULT_TIMEOUT)
                        pre_acao = r2.headers.get("access-control-allow-origin", "")
                        pre_acac = r2.headers.get("access-control-allow-credentials", "")
                        pre_vary = r2.headers.get("vary", "")
                        pre_verdict = _classify(pre_acao, pre_acac, origin, pre_vary)
                        if pre_verdict in ("reflected_with_credentials", "null_with_credentials",
                                            "wildcard_with_credentials", "regex_bypass_with_credentials",
                                            "domain_confusion_with_credentials", "protocol_mismatch_with_credentials",
                                            "reflected_dynamic", "null_origin", "regex_bypass", "domain_confusion"):
                            findings.append({
                                "url": page_url,
                                "origin": origin,
                                "acao": pre_acao,
                                "acac": pre_acac,
                                "verdict": f"preflight_{pre_verdict}",
                            })
                    except Exception:
                        pass

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
