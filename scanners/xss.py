"""
xss - Reflected XSS scanner (dalfox wrapper).

Wraps dalfox (Go-based XSS scanner) for reflected/dom XSS detection.
Falls back gracefully if dalfox binary is missing.

Usage:
  python matthunder_cli.py xss example.com
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


def run(domain: str, max_pages: int = 20) -> dict:
    domain = normalize_domain(domain)
    dalfox = _resolve("dalfox")
    if not dalfox:
        return {"scanner": "xss", "ok": False, "error": "dalfox not installed. Run setup.sh / setup.bat."}

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'xss', ?, ?, 'running', ?)",
        (domain, "dalfox", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"XSS scan started - domain: {domain}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    url_file = f"_matthunder_xss_{scan_id}.txt"
    with open(url_file, "w", encoding="utf-8") as f:
        for page_url, html in pages:
            for a in extract_anchors(html, page_url):
                if a["canonical"] and host_in_scope(_url_host(a["canonical"]), domain):
                    f.write(a["canonical"] + "\n")
            if "?" in page_url:
                f.write(page_url + "\n")
    log(con, scan_id, f"Wrote {os.path.getsize(url_file) if os.path.exists(url_file) else 0}B URL list")

    cmd = [dalfox, "file", url_file, "--silence", "--no-color", "--no-spinner",
           "--format", "json", "-o", f"_matthunder_xss_{scan_id}_out.json"]
    log(con, scan_id, f"Running dalfox...")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        proc = None
        log(con, scan_id, "dalfox timed out")
    except FileNotFoundError:
        proc = None
        log(con, scan_id, "dalfox binary not found at runtime")
    out_path = f"_matthunder_xss_{scan_id}_out.json"
    findings: list[dict] = []
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
    log(con, scan_id, f"Found {len(findings)} XSS findings")

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"xss_{f['type']}", f["url"], "vulnerable",
             f"param={f['param']} payload={f['payload'][:200]}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(findings))
    for p in (url_file, out_path):
        try:
            os.remove(p)
        except OSError:
            pass
    con.close()
    return {"scan_id": scan_id, "scanner": "xss", "domain": domain, "pages": len(pages), "findings": len(findings)}


def _url_host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.split(":")[0]
    except Exception:
        return ""


SCANNER_REGISTRY["xss"] = run
