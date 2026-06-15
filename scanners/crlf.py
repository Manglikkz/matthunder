"""
crlf - CRLF Injection scanner.

Wraps crlfuzz (Go tool) for CRLF header injection detection.
Falls back to a manual probe if crlfuzz binary is missing.

Usage:
  python matthunder_cli.py crlf example.com
"""

import os
import shutil
import subprocess
from typing import Optional
from urllib.parse import urlparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    finish_scan, log, normalize_domain, open_db, utc_now_iso,
)


def _resolve(name: str) -> Optional[str]:
    gopath_bin = os.path.join(os.path.expanduser("~"), "go", "bin")
    cand = os.path.join(gopath_bin, name + (".exe" if os.name == "nt" else ""))
    if os.path.exists(cand):
        return cand
    return shutil.which(name)


CRLF_PAYLOADS = [
    "%0d%0aX-Injected:true",
    "%0aX-Injected:true",
    "%0dX-Injected:true",
    "%0d%0a%0d%0a<html>injected</html>",
    "%E5%98%8A%E5%98%8Dx-injected:true",
    "\r\nX-Injected:true",
    "%5cr%5cnX-Injected:true",
    "%0d%0aLocation:https://evil.com",
]


def _probe_url(url: str, client: httpx.Client) -> dict:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for payload in CRLF_PAYLOADS:
        test_url = base + "?" + payload if "?" not in base else base + "&" + payload
        try:
            r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            if "x-injected" in headers_lower:
                return {
                    "vulnerable": True,
                    "url": url,
                    "payload": payload,
                    "evidence": "X-Injected header reflected",
                    "status": r.status_code,
                }
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.com" in loc.lower():
                    return {
                        "vulnerable": True,
                        "url": url,
                        "payload": payload,
                        "evidence": f"Redirect to {loc}",
                        "status": r.status_code,
                    }
        except Exception:
            continue

    return {"vulnerable": False}


def run(domain: str, max_pages: int = 20) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'crlf', ?, ?, 'running', ?)",
        (domain, "crlfuzz+manual", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"CRLF scan started - domain: {domain}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    findings: list[dict] = []

    # Manual probe
    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=False, timeout=DEFAULT_TIMEOUT) as client:
        for page_url, _ in pages:
            result = _probe_url(page_url, client)
            if result.get("vulnerable"):
                findings.append(result)
                log(con, scan_id, f"CRLF found: {page_url}")

    # Try crlfuzz if available
    crlfuzz = _resolve("crlfuzz")
    if crlfuzz and pages:
        url_file = f"_matthunder_crlf_{scan_id}.txt"
        with open(url_file, "w", encoding="utf-8") as f:
            for page_url, _ in pages:
                f.write(page_url + "\n")
        log(con, scan_id, "Running crlfuzz...")
        cmd = [crlfuzz, "-l", url_file, "-s", "-x", "-o", f"_matthunder_crlf_{scan_id}_out.txt"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            out_path = f"_matthunder_crlf_{scan_id}_out.txt"
            if os.path.exists(out_path):
                with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in [ff.get("url") for ff in findings]:
                            findings.append({"url": line, "payload": "crlfuzz", "evidence": "crlfuzz detection"})
                os.remove(out_path)
            log(con, scan_id, f"crlfuzz completed, {len(findings)} total findings")
        except subprocess.TimeoutExpired:
            log(con, scan_id, "crlfuzz timed out")
        except FileNotFoundError:
            log(con, scan_id, "crlfuzz binary not found")
        except Exception as e:
            log(con, scan_id, f"crlfuzz error: {e}")
        try:
            os.remove(url_file)
        except OSError:
            pass

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "crlf", f.get("url", ""), "vulnerable",
             f"payload={f.get('payload', '')} evidence={f.get('evidence', '')}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "crlf", "domain": domain, "pages": len(pages), "findings": len(findings)}


SCANNER_REGISTRY["crlf"] = run
