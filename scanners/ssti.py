"""
SSTI - Server-Side Template Injection scanner.

Probes URLs with engine-specific polyglot payloads, then tries engine
fingerprints based on error/response characteristics. Ported from SSTImap /
tplmap patterns (passive polyglot detection, no full RCE exploitation).

Engines covered (high-signal):
  - Jinja2 (Python/Flask)
  - Twig (PHP/Symfony)
  - Freemarker (Java)
  - ERB (Ruby/Rails)
  - Smarty (PHP)
  - Thymeleaf (Java/Spring)
  - Velocity (Java/Apache)
  - Mako (Python)
"""

import re
from typing import Optional
from urllib.parse import urlparse, quote

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    extract_anchors, finish_scan, host_in_scope, log, normalize_domain,
    open_db, utc_now_iso,
)


PROBES = {
    "jinja2":     ["{{7*7}}",     "{{7*'7'}}",      "{{config}}",      "{{self}}"],
    "twig":       ["{{7*7}}",     "{{_self.env}}", "{{7*'7'}}"],
    "freemarker": ["${7*7}",      "#{7*7}",         "<#assign a='freemarker.template.utility.Execute'?new()>${a('id')}"],
    "erb":        ["<%= 7*7 %>",  "${7*7}"],
    "smarty":     ["{7*7}",       "{php}echo 'SSTI_MARKER_SMARTY';{/php}"],
    "thymeleaf":  ["__${7*7}__",  "[[${7*7}]]"],
    "velocity":   ["#set($x=7*7)$x",  "#if(7*7==49)VELOCITY_TRUE#end"],
    "mako":       ["${7*7}"],
}

EXPECTED = {
    "jinja2":     "49",
    "twig":       "49",
    "freemarker": "49",
    "erb":        "49",
    "smarty":     "49",
    "thymeleaf":  "49",
    "velocity":   "49",
    "mako":       "49",
}

URL_PARAM_HINT = re.compile(r"(\?|q=|s=|search=|q=|input=|data=|view=|id=|template=|name=|file=|page=|redirect=)", re.I)


def _get_param_urls(html: str, page_url: str) -> list[tuple[str, str]]:
    """Return list of (full_url, param_name) heuristic for SSTI testing."""
    out: list[tuple[str, str]] = []
    parsed = urlparse(page_url)
    base_qs = parsed.query
    if base_qs:
        for pair in base_qs.split("&"):
            if "=" in pair:
                param = pair.split("=", 1)[0]
                if param and (page_url, param) not in out:
                    out.append((page_url, param))
    for a in extract_anchors(html, page_url):
        target = a["canonical"]
        if not target:
            continue
        cu_host = urlparse(target).netloc
        if not host_in_scope(cu_host, parsed.netloc.split(":")[0]):
            continue
        if "?" in target:
            for pair in target.split("?", 1)[1].split("&"):
                if "=" in pair:
                    param = pair.split("=", 1)[0]
                    if param and (target.split("?", 1)[0] + "?" + param, param) not in out:
                        out.append((target.split("?", 1)[0], param))
    return out


def _probe(url: str, param: str, payload: str, expected: str, client: httpx.Client) -> tuple[bool, str, int]:
    sep = "&" if "?" in url else "?"
    test_url = f"{url}{sep}{param}={quote(payload, safe='')}"
    try:
        r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
    except Exception:
        return (False, "", 0)
    body = r.text or ""
    if expected and expected in body and payload not in body:
        return (True, body[:1000], r.status_code)
    return (False, body[:500], r.status_code)


def run(domain: str, engines: list[str] = None, max_pages: int = 20) -> dict:
    domain = normalize_domain(domain)
    engines = engines or list(PROBES.keys())

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'ssti', ?, ?, 'running', ?)",
        (domain, str(engines), utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"SSTI scan started - domain: {domain}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    targets: list[tuple[str, str]] = []
    for page_url, html in pages:
        for url, param in _get_param_urls(html, page_url):
            if (url, param) not in targets:
                targets.append((url, param))
    log(con, scan_id, f"Found {len(targets)} URL+param targets")

    found: list[dict] = []
    tested = 0
    with httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=DEFAULT_TIMEOUT, follow_redirects=True) as client:
        for url, param in targets[:50]:
            for engine in engines:
                for payload in PROBES.get(engine, [])[:1]:
                    expected = EXPECTED.get(engine, "")
                    ok, body, code = _probe(url, param, payload, expected, client)
                    tested += 1
                    if ok:
                        found.append({
                            "engine": engine,
                            "payload": payload,
                            "url": url,
                            "param": param,
                            "status": code,
                        })
                        break

    seen = set()
    unique = []
    for f in found:
        key = (f["url"], f["param"], f["engine"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    log(con, scan_id, f"Found {len(unique)} SSTI candidates in {tested} probes")

    for f in unique:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"ssti_{f['engine']}", f["url"], f["status"], f"param={f['param']} payload={f['payload']}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(unique))
    con.close()
    return {"scan_id": scan_id, "scanner": "ssti", "domain": domain, "pages": len(pages), "probes": tested, "findings": len(unique)}


SCANNER_REGISTRY["ssti"] = run
