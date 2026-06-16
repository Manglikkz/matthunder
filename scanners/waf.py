"""
waf - WAF Detection scanner.

Wraps wafw00f to detect Web Application Firewalls.
Falls back to manual header/signature detection if wafw00f is missing.

Usage:
  python matthunder_cli.py waf example.com
"""

import os
import shutil
import subprocess
from typing import Optional

import httpx

from . import SCANNER_REGISTRY
from .common import (
    resolve_tool,
    DEFAULT_TIMEOUT, USER_AGENT, finish_scan, log, normalize_domain,
    open_db, utc_now_iso,
)


def _resolve(name: str) -> Optional[str]:
    return resolve_tool(name)



# Common WAF signatures (header patterns)
WAF_SIGNATURES = {
    "cloudflare": {"headers": ["cf-ray", "cf-cache-status", "server: cloudflare"]},
    "akamai": {"headers": ["x-akamai-transformed", "akamai-origin-hop"]},
    "aws-waf": {"headers": ["x-amzn-requestid", "x-amz-cf-id"]},
    "incapsula": {"headers": ["x-iinfo", "set-cookie: visid_incap_"]},
    "sucuri": {"headers": ["x-sucuri-id", "server: sucuri"]},
    "wordfence": {"headers": ["x-wf-"]},
    "modsecurity": {"headers": ["server: mod_security", "x-mod-security"]},
    "barracuda": {"headers": ["barra_counter_session"]},
    "f5-bigip": {"headers": ["server: bigip", "x-cnection"]},
    "fortiweb": {"headers": ["server: fortiweb"]},
    "citrix": {"headers": ["via: citrix"]},
    "imperva": {"headers": ["x-unique-id", "set-cookie: incap_ses_"]},
}


def _detect_waf(domain: str, client: httpx.Client) -> list[dict]:
    """Manual WAF detection based on response headers."""
    findings = []
    urls = [f"https://{domain}", f"http://{domain}"]

    for url in urls:
        try:
            r = client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            server = headers_lower.get("server", "").lower()

            for waf_name, sig in WAF_SIGNATURES.items():
                for pattern in sig["headers"]:
                    key, _, val = pattern.partition(": ")
                    if val:
                        # Check header value
                        h_val = headers_lower.get(key.lower(), "")
                        if val.lower() in h_val.lower():
                            findings.append({"waf": waf_name, "evidence": f"{key}: {h_val}", "url": url})
                    else:
                        # Check header existence
                        if key.lower() in headers_lower:
                            findings.append({"waf": waf_name, "evidence": f"{key} present", "url": url})

            # Check server header directly
            if server and server not in ("", "apache", "nginx", "iis", "lighttpd"):
                findings.append({"waf": server, "evidence": f"Server: {server}", "url": url})

        except Exception:
            continue

    # Deduplicate by WAF name
    seen = set()
    unique = []
    for f in findings:
        if f["waf"] not in seen:
            seen.add(f["waf"])
            unique.append(f)
    return unique


def run(domain: str) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'waf', ?, ?, 'running', ?)",
        (domain, "wafw00f+manual", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"WAF detection started - domain: {domain}")

    findings: list[dict] = []

    # Try wafw00f first
    wafw00f = _resolve("wafw00f")
    if wafw00f:
        log(con, scan_id, "Running wafw00f...")
        cmd = [wafw00f, f"https://{domain}", "-o", f"_matthunder_waf_{scan_id}.txt", "-f", "json"]
        try:
            proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=60)
            out_path = f"_matthunder_waf_{scan_id}.txt"
            if os.path.exists(out_path):
                import json
                with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if content.strip():
                        try:
                            data = json.loads(content)
                            if isinstance(data, list):
                                for item in data:
                                    if item.get("firewall") and item["firewall"] != "None":
                                        findings.append({
                                            "waf": item.get("firewall", "unknown"),
                                            "evidence": item.get("detected", ""),
                                        })
                        except json.JSONDecodeError:
                            for line in content.splitlines():
                                if "behind" in line.lower() or "detected" in line.lower():
                                    findings.append({"waf": line.strip(), "evidence": "wafw00f"})
                os.remove(out_path)
            log(con, scan_id, f"wafw00f found {len(findings)} WAFs")
        except subprocess.TimeoutExpired:
            log(con, scan_id, "wafw00f timed out")
        except FileNotFoundError:
            log(con, scan_id, "wafw00f not found, using manual detection")
        except Exception as e:
            log(con, scan_id, f"wafw00f error: {e}")

    # Manual detection (always run as supplement)
    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        manual = _detect_waf(domain, client)
        existing = {f["waf"] for f in findings}
        for m in manual:
            if m["waf"] not in existing:
                findings.append(m)

    if not findings:
        log(con, scan_id, "No WAF detected")
        findings.append({"waf": "none", "evidence": "no WAF signature detected"})

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "waf", domain, "detected",
             f"waf={f['waf']} evidence={f['evidence']}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=1, total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "waf", "domain": domain, "findings": len(findings)}


SCANNER_REGISTRY["waf"] = run
