"""
sqli - SQL Injection scanner (sqlmap wrapper).

Wraps sqlmap for automated SQLi detection on crawled URLs with parameters.
Falls back to a lightweight heuristic probe if sqlmap is missing.

Usage:
  python matthunder_cli.py sqli example.com
"""

import json
import os
import shutil
import subprocess
from typing import Optional

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    extract_anchors, finish_scan, host_in_scope, log, normalize_domain,
    open_db, utc_now_iso,
)


def _resolve(name: str) -> Optional[str]:
    gopath_bin = os.path.join(os.path.expanduser("~"), "go", "bin")
    cand = os.path.join(gopath_bin, name + (".exe" if os.name == "nt" else ""))
    if os.path.exists(cand):
        return cand
    return shutil.which(name)


SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1' ORDER BY 1--", "1 UNION SELECT NULL--"]
SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "sqlite3", "pg_query", "postgresql",
    "ORA-", "oracle", "microsoft odbc", "unclosed quotation",
    "syntax error", "unterminated string", "warning: mysql",
    "valid mysql result", "mysqlclient", "sqlstate",
]


def _probe_url(url: str, param: str, client: httpx.Client) -> dict:
    """Send SQLi payloads to a single URL+param and check for error-based SQLi."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return {"vulnerable": False}

    for payload in SQLI_PAYLOADS:
        test_qs = dict(qs)
        test_qs[param] = [payload]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            r = client.get(test_url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            body = r.text.lower()
            for err in SQLI_ERRORS:
                if err in body:
                    return {
                        "vulnerable": True,
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": err,
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
        "VALUES (lower(hex(randomblob(16))), 'sqli', ?, ?, 'running', ?)",
        (domain, "heuristic+sqlmap", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"SQLi scan started - domain: {domain}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    findings: list[dict] = []

    # Heuristic error-based SQLi probe
    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        for page_url, html in pages:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(page_url)
            params = list(parse_qs(parsed.query).keys())
            if not params:
                continue
            for param in params:
                result = _probe_url(page_url, param, client)
                if result.get("vulnerable"):
                    findings.append(result)
                    log(con, scan_id, f"SQLi found: {page_url} param={param} payload={result['payload']}")

    # Try sqlmap if available
    sqlmap = _resolve("sqlmap") or _resolve("sqlmap.py")
    if sqlmap and pages:
        url_file = f"_matthunder_sqli_{scan_id}.txt"
        with open(url_file, "w", encoding="utf-8") as f:
            for page_url, _ in pages:
                if "?" in page_url:
                    f.write(page_url + "\n")
        if os.path.getsize(url_file) > 0:
            log(con, scan_id, "Running sqlmap...")
            cmd = [
                sqlmap, "-m", url_file, "--batch", "--level=1", "--risk=1",
                "--output-dir", f"_matthunder_sqlmap_{scan_id}",
                "--disable-coloring", "--no-logging",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                output = proc.stdout + proc.stderr
                if "is vulnerable" in output or "sqlmap identified" in output:
                    for line in output.splitlines():
                        if "is vulnerable" in line or "Parameter:" in line:
                            findings.append({"type": "sqlmap", "detail": line.strip()})
                log(con, scan_id, f"sqlmap completed, {len(findings)} total findings")
            except subprocess.TimeoutExpired:
                log(con, scan_id, "sqlmap timed out (600s)")
            except FileNotFoundError:
                log(con, scan_id, "sqlmap binary not found")
            except Exception as e:
                log(con, scan_id, f"sqlmap error: {e}")
        try:
            os.remove(url_file)
        except OSError:
            pass
        import shutil as _shutil
        _shutil.rmtree(f"_matthunder_sqlmap_{scan_id}", ignore_errors=True)

    for f in findings:
        detail = f.get("evidence") or f.get("detail", "")
        url = f.get("url", "")
        param = f.get("param", "")
        payload = f.get("payload", "")
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "sqli", url, "vulnerable",
             f"param={param} payload={payload} evidence={detail}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "sqli", "domain": domain, "pages": len(pages), "findings": len(findings)}


SCANNER_REGISTRY["sqli"] = run
