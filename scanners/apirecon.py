"""
apirecon - API endpoint and parameter discovery wrappers.

Wraps kiterunner (API endpoint bruteforce) and arjun (hidden parameter
discovery). Both are Go tools installed via setup script.

If the binary is missing, the scanner degrades gracefully and reports
the missing dependency instead of crashing.

Usage (from matthunder):
  python matthunder_cli.py apirecon example.com
  python matthunder_cli.py params example.com
"""

import json
import os
import shutil
import subprocess
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    resolve_tool,
    USER_AGENT, canonical_url, crawl_domain, extract_anchors, finish_scan,
    host_in_scope, log, normalize_domain, open_db, utc_now_iso,
)


def _resolve(name: str) -> Optional[str]:
    return resolve_tool(name)



def _run(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError as e:
        return -1, "", f"binary not found: {e}"
    except Exception as e:
        return -1, "", f"{type(e).__name__}: {e}"


def run_apirecon(domain: str, wordlist: Optional[str] = None) -> dict:
    """API endpoint discovery using kiterunner."""
    domain = normalize_domain(domain)
    kr = _resolve("kr")
    if not kr:
        return {"scanner": "apirecon", "ok": False, "error": "kiterunner (kr) not installed. Run setup.sh / setup.bat."}

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'apirecon', ?, ?, 'running', ?)",
        (domain, "kiterunner", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"API recon started - domain: {domain}")

    base = f"https://{domain}"
    if not wordlist:
        wordlist = os.path.join(os.path.expanduser("~"), "go", "pkg", "mod", "github.com", "assetnote", "kiterunner", "kb", "http", "http-megapich.json")
        if not os.path.exists(wordlist):
            wordlist = ""
    cmd = [kr, "scan", base, "-A", "apiroutes-210128:20000", "--fail-status-codes", "404,406"]
    if wordlist and os.path.exists(wordlist):
        cmd = [kr, "scan", base, "-w", wordlist]
    log(con, scan_id, f"Running: {' '.join(cmd[:6])}...")
    code, stdout, stderr = _run(cmd, timeout=600)
    log(con, scan_id, f"kiterunner exit {code}")
    if stderr:
        log(con, scan_id, f"stderr: {stderr[:500]}")

    found: list[dict] = []
    for line in (stdout or "").splitlines():
        if not line.strip():
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        cu = canonical_url(j.get("url") or j.get("endpoint", ""))
        if not cu or not host_in_scope(urlparse(cu).netloc, domain):
            continue
        found.append({"url": cu, "status": j.get("status_code", ""), "method": j.get("method", "GET")})

    seen = set()
    unique = []
    for f in found:
        if f["url"] in seen:
            continue
        seen.add(f["url"])
        unique.append(f)
    log(con, scan_id, f"Found {len(unique)} in-scope API endpoints")

    for f in unique:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "api_endpoint", f["url"], f["status"] or "discovered", f["method"], utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=0, total_links=len(unique))
    con.close()
    return {"scan_id": scan_id, "scanner": "apirecon", "domain": domain, "endpoints": len(unique)}


def run_params(domain: str, methods: Optional[list[str]] = None) -> dict:
    """Hidden parameter discovery using arjun."""
    domain = normalize_domain(domain)
    arjun = _resolve("arjun")
    if not arjun:
        return {"scanner": "params", "ok": False, "error": "arjun not installed. Run setup.sh / setup.bat."}

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'params', ?, ?, 'running', ?)",
        (domain, str(methods or ["GET", "POST"]), utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"Param discovery started - domain: {domain}")

    pages = crawl_domain(domain, max_pages=10)
    log(con, scan_id, f"Crawled {len(pages)} pages for parameter testing")

    methods = methods or ["GET", "POST"]
    found_params: list[dict] = []
    tested = 0
    with httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=15.0, follow_redirects=True) as client:
        for page_url, html in pages[:5]:
            for method in methods:
                cmd = [arjun, "-u", page_url, "--method", method, "--stable", "-oJ", "-"]
                code, stdout, stderr = _run(cmd, timeout=120)
                if code != 0 or not stdout.strip():
                    continue
                tested += 1
                try:
                    j = json.loads(stdout)
                except Exception:
                    continue
                for param in j.get("params", []):
                    found_params.append({
                        "param": param,
                        "url": page_url,
                        "method": method,
                    })

    seen = set()
    unique = []
    for p in found_params:
        key = (p["url"], p["param"], p["method"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)
    log(con, scan_id, f"Found {len(unique)} hidden parameters across {tested} (page,method) combos")

    for p in unique:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"param_{p['method'].lower()}", p["url"], "discovered", p["param"], utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(unique))
    con.close()
    return {"scan_id": scan_id, "scanner": "params", "domain": domain, "params": len(unique), "tested": tested}


SCANNER_REGISTRY["apirecon"] = run_apirecon
SCANNER_REGISTRY["params"] = run_params
