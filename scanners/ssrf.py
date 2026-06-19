"""
ssrf - Server-Side Request Forgery scanner.

Probes URLs for SSRF by injecting internal/external URLs into parameters
and checking response differences. Uses OOB detection via Interactsh when available.

Usage:
  python matthunder_cli.py ssrf example.com
"""

import os
import re
import time
import uuid
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    extract_anchors, finish_scan, host_in_scope, log, normalize_domain,
    open_db, utc_now_iso, is_dynamic_param, FALLBACK_PARAMS, FALLBACK_ENDPOINTS,
)

# ── SSRF Payloads ────────────────────────────────────────────────────────

# Internal targets (for detection, not exploitation)
INTERNAL_TARGETS = [
    ("http://127.0.0.1", "localhost"),
    ("http://127.0.0.1:80", "localhost"),
    ("http://127.0.0.1:443", "localhost"),
    ("http://127.0.0.1:8080", "localhost"),
    ("http://127.0.0.1:8443", "localhost"),
    ("http://127.0.0.1:3000", "localhost"),
    ("http://127.0.0.1:6379", "redis"),
    ("http://127.0.0.1:3306", "mysql"),
    ("http://127.0.0.1:5432", "postgres"),
    ("http://127.0.0.1:27017", "mongodb"),
    ("http://[::1]", "ipv6_loopback"),
    ("http://0.0.0.0", "zero_address"),
    ("http://169.254.169.254", "aws_metadata"),
    ("http://metadata.google.internal", "gcp_metadata"),
    ("http://169.254.169.254/metadata/v1/", "digitalocean_metadata"),
    ("http://169.254.169.254/latest/meta-data/", "aws_metadata_path"),
]

# SSRF indicators in response
SSRF_INDICATORS = {
    "localhost": [
        r"<html>", r"<title>.*404.*</title>", r"Index of /",
        r"Welcome to nginx", r"Apache.*Server at",
        r"HTTP/\d.\d\s+200", r"\{.*\"status\".*\}",
    ],
    "redis": [
        r"-ERR", r"-WRONGTYPE", r"\+OK", r"\$\d+",
        r"redis_version", r"ERR unknown command",
    ],
    "mysql": [
        r"mysql", r"SQL syntax", r"Access denied",
        r"Can't connect to MySQL", r"mysql_fetch",
    ],
    "postgres": [
        r"PostgreSQL", r"pg_hba.conf", r"FATAL.*no pg_hba.conf",
        r"could not connect", r"connection refused",
    ],
    "mongodb": [
        r"MongoDB", r"ok.*0", r"Connection refused",
        r"wire protocol",
    ],
    "aws_metadata": [
        r"ami-id", r"instance-id", r"instance-type",
        r"local-ipv4", r"security-groups", r"iam.*info",
    ],
    "gcp_metadata": [
        r"computeMetadata", r"instance/", r"project/",
    ],
}

# OOB canary domains
OOB_DOMAINS = [
    "interact.sh",
    "oast.fun",
    "oast.pro",
    "oast.live",
    "burpcollaborator.net",
]


def _load_pipeline_urls() -> list[str]:
    url_file = os.environ.get("MT_PIPELINE_URLS", "")
    if url_file and os.path.exists(url_file):
        with open(url_file, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip().startswith("http")]
    return []


def _check_oob_domain(url: str) -> Optional[str]:
    """Extract OOB domain from URL if present."""
    for domain in OOB_DOMAINS:
        if domain in url.lower():
            return domain
    return None


def _probe_ssrf_get(url: str, param: str, client: httpx.Client, canary: str = None) -> dict:
    """Test GET parameter for SSRF."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return {"vulnerable": False}

    # Determine probe targets
    targets = list(INTERNAL_TARGETS)
    if canary:
        targets.append((f"http://{canary}", "oob"))

    for target_url, target_type in targets:
        test_qs = dict(qs)
        test_qs[param] = [target_url]
        test_url = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))

        try:
            r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
        except Exception:
            continue

        body = r.text or ""
        # Check for SSRF indicators
        for indicator_type, patterns in SSRF_INDICATORS.items():
            if target_type == indicator_type or target_type == "localhost":
                for pattern in patterns:
                    if re.search(pattern, body, re.I):
                        return {
                            "vulnerable": True,
                            "url": url,
                            "param": param,
                            "payload": target_url,
                            "evidence": pattern,
                            "type": f"error_leak_{target_type}",
                            "status": r.status_code,
                        }

        # Check for status code anomalies (SSRF might cause 500/502/503)
        if r.status_code in (500, 502, 503, 504) and target_type in ("localhost", "redis", "mysql", "postgres", "mongodb"):
            # Baseline comparison
            try:
                baseline_qs = dict(qs)
                baseline_qs[param] = ["1"]
                baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_qs, doseq=True)))
                bl = client.get(baseline_url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
                if bl.status_code not in (500, 502, 503, 504):
                    return {
                        "vulnerable": True,
                        "url": url,
                        "param": param,
                        "payload": target_url,
                        "evidence": f"status_{r.status_code}_vs_{bl.status_code}",
                        "type": f"blind_ssrf_{target_type}",
                        "status": r.status_code,
                    }
            except Exception:
                pass

        # Check response time anomaly (blind SSRF via timing)
        if target_type in ("localhost", "redis", "mysql", "postgres", "mongodb"):
            try:
                start = time.monotonic()
                r_time = client.get(test_url, timeout=10, follow_redirects=False)
                elapsed = time.monotonic() - start
                if elapsed > 3:
                    # Compare with baseline
                    baseline_qs = dict(qs)
                    baseline_qs[param] = ["1"]
                    baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_qs, doseq=True)))
                    start2 = time.monotonic()
                    client.get(baseline_url, timeout=10, follow_redirects=False)
                    elapsed2 = time.monotonic() - start2
                    if elapsed - elapsed2 > 2:
                        return {
                            "vulnerable": True,
                            "url": url,
                            "param": param,
                            "payload": target_url,
                            "evidence": f"timing_{elapsed:.1f}s_vs_{elapsed2:.1f}s",
                            "type": f"blind_ssrf_timing_{target_type}",
                            "status": r_time.status_code,
                        }
            except Exception:
                pass

    return {"vulnerable": False}


def _probe_ssrf_post(url: str, param: str, client: httpx.Client, canary: str = None) -> dict:
    """Test POST body parameter for SSRF."""
    targets = list(INTERNAL_TARGETS)
    if canary:
        targets.append((f"http://{canary}", "oob"))

    for target_url, target_type in targets:
        try:
            r = client.post(url, data={param: target_url}, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
        except Exception:
            continue

        body = r.text or ""
        for indicator_type, patterns in SSRF_INDICATORS.items():
            if target_type == indicator_type or target_type == "localhost":
                for pattern in patterns:
                    if re.search(pattern, body, re.I):
                        return {
                            "vulnerable": True,
                            "url": url,
                            "param": param,
                            "payload": target_url,
                            "evidence": pattern,
                            "type": f"post_ssrf_{target_type}",
                            "status": r.status_code,
                        }

    return {"vulnerable": False}


def run(domain: str, max_pages: int = 30) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'ssrf', ?, ?, 'running', ?)",
        (domain, "internal+oob", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"SSRF scan started - domain: {domain}")

    # Generate OOB canary
    canary = f"ssrf-{uuid.uuid4().hex[:12]}.interact.sh"
    log(con, scan_id, f"OOB canary: {canary}")

    # Crawl for URLs
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

    # Extract URL+param targets
    targets = []
    seen = set()
    for page_url, html in pages:
        parsed = urlparse(page_url)
        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        for param in params:
            key = (page_url.split("?")[0], param)
            if key not in seen:
                seen.add(key)
                targets.append((page_url, param))

    # Add fallback endpoints with SSRF-prone params
    ssrf_params = ["url", "uri", "path", "src", "dest", "redirect", "load",
                   "fetch", "image_url", "avatar", "feed", "host", "site",
                   "file", "document", "page", "api_url", "webhook", "callback"]
    base_urls = [f"https://{domain}", f"http://{domain}"]
    for base in base_urls:
        for endpoint in FALLBACK_ENDPOINTS[:10]:
            full = f"{base}{endpoint}"
            for param in ssrf_params[:8]:
                key = (full, param)
                if key not in seen:
                    seen.add(key)
                    targets.append((full, param))

    log(con, scan_id, f"Testing {len(targets)} URL+param targets")

    findings: list[dict] = []
    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=False, timeout=DEFAULT_TIMEOUT) as client:
        for url, param in targets[:150]:
            # GET probe
            result = _probe_ssrf_get(url, param, client, canary)
            if result.get("vulnerable"):
                findings.append(result)
                log(con, scan_id, f"SSRF GET: {url} param={param} type={result.get('type')}")
                continue

            # POST probe
            result = _probe_ssrf_post(url, param, client, canary)
            if result.get("vulnerable"):
                findings.append(result)
                log(con, scan_id, f"SSRF POST: {url} param={param} type={result.get('type')}")

    log(con, scan_id, f"Found {len(findings)} SSRF findings")

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"ssrf_{f.get('type', 'unknown')}", f.get("url", ""), "vulnerable",
             f"param={f.get('param', '')} payload={f.get('payload', '')} evidence={f.get('evidence', '')}",
             utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(targets), total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "ssrf", "domain": domain, "pages": len(targets), "findings": len(findings)}


SCANNER_REGISTRY["ssrf"] = run
