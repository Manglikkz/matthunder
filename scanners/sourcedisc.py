"""
sourcedisc - Source Code Disclosure scanner.

Checks for exposed source code, backup files, version control artifacts,
and sensitive directories that leak application internals.

Targets:
  - .git directory (full source code leak)
  - .svn directory
  - .DS_Store (directory listing)
  - Backup files (.bak, .old, .swp, ~, .orig)
  - Source maps (.map files)
  - Sensitive paths (/server-status, /server-info, /debug, /actuator)

Usage:
  python matthunder_cli.py sourcedisc example.com
"""

import os
import re
from typing import Optional
from urllib.parse import urljoin

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, crawl_domain,
    finish_scan, log, normalize_domain, open_db, utc_now_iso,
)


# ── Sensitive Paths ────────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    # Version control
    ("/.git/HEAD", "git_head", "ref:"),
    ("/.git/config", "git_config", "[core]"),
    ("/.gitignore", "gitignore", ""),
    ("/.svn/entries", "svn_entries", ""),
    ("/.svn/wc.db", "svn_wcdb", "SQLite"),
    # OS artifacts
    ("/.DS_Store", "ds_store", "Bud1"),
    ("/Thumbs.db", "thumbs_db", ""),
    # Backup files
    ("/index.php.bak", "backup", ""),
    ("/index.php.old", "backup", ""),
    ("/index.php~", "backup", ""),
    ("/index.php.swp", "backup", ""),
    ("/index.php.orig", "backup", ""),
    ("/index.php.save", "backup", ""),
    ("/web.config.bak", "backup", ""),
    ("/.env", "env_file", ""),
    ("/.env.bak", "env_backup", ""),
    ("/.env.local", "env_local", ""),
    ("/.env.production", "env_production", ""),
    # Server status
    ("/server-status", "server_status", "Apache Server Status"),
    ("/server-info", "server_info", "Apache Server Information"),
    # Debug/admin paths
    ("/debug", "debug", ""),
    ("/debug/vars", "debug_vars", ""),
    ("/debug/pprof/", "pprof", ""),
    ("/actuator", "actuator", ""),
    ("/actuator/env", "actuator_env", ""),
    ("/actuator/health", "actuator_health", ""),
    ("/actuator/beans", "actuator_beans", ""),
    ("/_debug-toolbar/", "debug_toolbar", ""),
    ("/_profiler/", "profiler", ""),
    ("/phpinfo.php", "phpinfo", "phpinfo()"),
    ("/info.php", "phpinfo", "phpinfo()"),
    ("/test.php", "test_file", ""),
    # Source maps
    ("/main.js.map", "sourcemap", ""),
    ("/app.js.map", "sourcemap", ""),
    ("/bundle.js.map", "sourcemap", ""),
    ("/static/js/main.js.map", "sourcemap", ""),
    ("/assets/js/app.js.map", "sourcemap", ""),
    ("/dist/bundle.js.map", "sourcemap", ""),
    # Database files
    ("/database.sql", "db_file", ""),
    ("/db.sql", "db_file", ""),
    ("/dump.sql", "db_file", ""),
    ("/backup.sql", "db_file", ""),
    ("/data.db", "db_file", ""),
    ("/sqlite.db", "db_file", ""),
    ("/app.db", "db_file", ""),
]

# ── Directory listing indicators ───────────────────────────────────────────

DIR_LISTING_INDICATORS = [
    r"<title>Index of /",
    r"<h1>Index of /",
    r"Parent Directory",
    r"<pre>\s*<a href=",
]

# ── Git file patterns ──────────────────────────────────────────────────────

GIT_PATTERNS = [
    (r"ref:\s*refs/heads/", "git_head_valid"),
    (r"\[core\]", "git_config_valid"),
    (r"bare\s*=\s*false", "git_config_normal"),
    (r"repositoryformatversion\s*=\s*[01]", "git_config_modern"),
]

# ── Source map validation ──────────────────────────────────────────────────

SOURCEMAP_PATTERN = r'^\s*\{[^}]*"version"\s*:\s*\d+[^}]*"sources"\s*:\s*\['


def _load_pipeline_urls() -> list[str]:
    url_file = os.environ.get("MT_PIPELINE_URLS", "")
    if url_file and os.path.exists(url_file):
        with open(url_file, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip().startswith("http")]
    return []


def _check_response(body: str, status: int, indicators: list[str] = None) -> bool:
    """Check if response indicates a disclosure."""
    if status != 200:
        return False
    if not body.strip():
        return False
    if indicators:
        for indicator in indicators:
            if indicator.lower() in body.lower():
                return True
        return False
    return True


def _probe_path(url: str, path: str, client: httpx.Client) -> dict:
    """Probe a single sensitive path."""
    full_url = urljoin(url, path)

    try:
        r = client.get(full_url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
    except Exception:
        return None

    body = r.text or ""
    status = r.status_code

    # Check for directory listing
    for pattern in DIR_LISTING_INDICATORS:
        if re.search(pattern, body, re.I):
            return {
                "url": full_url,
                "path": path,
                "status": status,
                "type": "directory_listing",
                "evidence": pattern,
                "severity": "high",
            }

    return None


def _probe_git(url: str, client: httpx.Client) -> list[dict]:
    """Deep probe for .git directory exposure."""
    findings = []
    git_paths = [
        "/.git/HEAD",
        "/.git/config",
        "/.git/index",
        "/.git/description",
        "/.git/logs/HEAD",
        "/.git/refs/heads/main",
        "/.git/refs/heads/master",
    ]

    for path in git_paths:
        full_url = urljoin(url, path)
        try:
            r = client.get(full_url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
            if r.status_code == 200 and r.text.strip():
                body = r.text
                for pattern, name in GIT_PATTERNS:
                    if re.search(pattern, body, re.I):
                        findings.append({
                            "url": full_url,
                            "path": path,
                            "status": r.status_code,
                            "type": f"git_{name}",
                            "evidence": pattern,
                            "severity": "critical",
                        })
                        break
        except Exception:
            continue

    return findings


def _check_source_map(url: str, js_url: str, client: httpx.Client) -> dict:
    """Check if a JS file has a source map."""
    map_url = js_url.rstrip("/") + ".map"
    try:
        r = client.get(map_url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
        if r.status_code == 200:
            body = r.text[:1000]
            if re.search(SOURCEMAP_PATTERN, body):
                return {
                    "url": map_url,
                    "path": "",
                    "status": 200,
                    "type": "sourcemap_exposed",
                    "evidence": "valid_source_map",
                    "severity": "high",
                }
    except Exception:
        pass
    return None


def run(domain: str, max_pages: int = 30) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'sourcedisc', ?, ?, 'running', ?)",
        (domain, "git+backup+status+sourcemap", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"Source Code Disclosure scan started - domain: {domain}")

    base_urls = [f"https://{domain}", f"http://{domain}"]
    findings: list[dict] = []
    tested = 0

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=False, timeout=DEFAULT_TIMEOUT) as client:
        for base in base_urls:
            for path, path_type, indicator in SENSITIVE_PATHS:
                full_url = urljoin(base, path)
                try:
                    r = client.get(full_url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
                    tested += 1
                    body = r.text or ""

                    if r.status_code == 200 and body.strip():
                        # Check indicators
                        if indicator:
                            if indicator.lower() in body.lower():
                                findings.append({
                                    "url": full_url,
                                    "path": path,
                                    "status": r.status_code,
                                    "type": path_type,
                                    "evidence": indicator,
                                    "severity": "critical" if "git" in path_type else "high",
                                })
                                log(con, scan_id, f"FOUND: {path_type} at {full_url}")
                        elif len(body) > 50:
                            # No specific indicator — check if it looks like real content
                            # Avoid false positives on generic error pages
                            if not re.search(r"<title>.*(?:404|Not Found|Error|Forbidden).*<title>", body, re.I):
                                findings.append({
                                    "url": full_url,
                                    "path": path,
                                    "status": r.status_code,
                                    "type": path_type,
                                    "evidence": f"status_200_content_{len(body)}",
                                    "severity": "medium",
                                })
                                log(con, scan_id, f"POSSIBLE: {path_type} at {full_url} ({len(body)} bytes)")
                except Exception:
                    continue

            # Check git directory listing
            git_result = _check_path_listing(base, "/.git/", client)
            if git_result:
                findings.append(git_result)
                log(con, scan_id, f"FOUND: git directory listing at {base}/.git/")

        # Check for source maps on crawled JS files
        pages = crawl_domain(domain, max_pages=min(max_pages, 15))
        js_urls = set()
        for page_url, html in pages:
            for match in re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html or ""):
                if match.startswith("http"):
                    js_urls.add(match)
                elif match.startswith("/"):
                    js_urls.add(f"https://{domain}{match}")

        for js_url in list(js_urls)[:20]:
            result = _check_source_map(domain and f"https://{domain}" or "", js_url, client)
            if result:
                findings.append(result)
                log(con, scan_id, f"FOUND: source map at {js_url}")

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f["url"], f["type"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    log(con, scan_id, f"Found {len(unique)} source disclosure findings in {tested} probes")

    for f in unique:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"sourcedisc_{f['type']}", f["url"], f.get("severity", "medium"),
             f"path={f['path']} evidence={f['evidence']}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=tested, total_links=len(unique))
    con.close()
    return {"scan_id": scan_id, "scanner": "sourcedisc", "domain": domain, "paths_tested": tested, "findings": len(unique)}


def _check_path_listing(base_url: str, path: str, client: httpx.Client) -> dict:
    """Check if a path returns directory listing."""
    full_url = urljoin(base_url, path)
    try:
        r = client.get(full_url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
        if r.status_code == 200:
            body = r.text or ""
            for pattern in DIR_LISTING_INDICATORS:
                if re.search(pattern, body, re.I):
                    return {
                        "url": full_url,
                        "path": path,
                        "status": 200,
                        "type": "directory_listing",
                        "evidence": pattern,
                        "severity": "critical",
                    }
    except Exception:
        pass
    return None


SCANNER_REGISTRY["sourcedisc"] = run
SCANNER_REGISTRY["source"] = run
