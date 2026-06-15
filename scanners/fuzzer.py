"""
fuzzer - Directory/path fuzzing scanner.

Wraps ffuf, feroxbuster, or gobuster for content discovery.
Falls back to a built-in wordlist probe if no tool is available.

Usage:
  python matthunder_cli.py fuzzer example.com
"""

import os
import shutil
import subprocess
from typing import Optional

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, finish_scan, log, normalize_domain,
    open_db, utc_now_iso,
)


def _resolve(name: str) -> Optional[str]:
    gopath_bin = os.path.join(os.path.expanduser("~"), "go", "bin")
    cand = os.path.join(gopath_bin, name + (".exe" if os.name == "nt" else ""))
    if os.path.exists(cand):
        return cand
    return shutil.which(name)


# Compact built-in wordlist for fallback
BUILTIN_WORDLIST = [
    "admin", "login", "dashboard", "api", "api/v1", "api/v2", "graphql",
    "console", "debug", "test", "staging", "dev", "backup", "old", "new",
    "config", "settings", "uploads", "upload", "files", "static", "assets",
    "images", "img", "css", "js", "fonts", "media", "docs", "doc", "help",
    "support", "status", "health", "info", "version", "env", ".env",
    ".git", ".svn", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "favicon.ico", "index.php", "index.html", "wp-admin",
    "wp-login.php", "wp-content", "wp-includes", "administrator", "phpmyadmin",
    "server-status", "server-info", ".well-known", "security.txt",
    "actuator", "actuator/health", "actuator/env", "swagger", "swagger-ui",
    "openapi.json", "api-docs", "v1", "v2", "v3", "internal", "private",
    "public", "temp", "tmp", "cache", "logs", "log", "data", "db",
    "database", "backup.sql", "dump.sql", "package.json", "composer.json",
    "Gemfile", "requirements.txt", ".DS_Store", "Dockerfile", "docker-compose.yml",
    ".gitignore", "README.md", "LICENSE", "CHANGELOG",
]


def _builtin_fuzz(domain: str, max_paths: int = 200) -> list[dict]:
    """Lightweight HTTP-based directory fuzzing fallback."""
    findings = []
    wordlist = BUILTIN_WORDLIST[:max_paths]

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        for scheme in ("https", "http"):
            base = f"{scheme}://{domain}"
            for path in wordlist:
                url = f"{base}/{path}"
                try:
                    r = client.get(url, timeout=5.0)
                    if r.status_code in (200, 201, 301, 302, 307, 403):
                        findings.append({
                            "url": url,
                            "status": r.status_code,
                            "size": len(r.content),
                            "redirect": r.headers.get("Location", ""),
                        })
                except Exception:
                    continue
            if findings:
                break  # Only try http if https yielded nothing
    return findings


def run(domain: str, wordlist: str = None) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'fuzzer', ?, ?, 'running', ?)",
        (domain, wordlist or "builtin", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"Directory fuzzing started - domain: {domain}")

    findings: list[dict] = []

    # Try ffuf first
    ffuf = _resolve("ffuf")
    if ffuf:
        log(con, scan_id, "Running ffuf...")
        wl = wordlist or ""
        if not wl:
            # Try common wordlist paths
            for p in [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                os.path.expanduser("~/wordlists/common.txt"),
            ]:
                if os.path.exists(p):
                    wl = p
                    break
        if not wl:
            # Use builtin
            wl_path = f"_matthunder_wl_{scan_id}.txt"
            with open(wl_path, "w") as f:
                f.write("\n".join(BUILTIN_WORDLIST))
            wl = wl_path

        out_path = f"_matthunder_fuzz_{scan_id}.json"
        cmd = [
            ffuf, "-u", f"https://{domain}/FUZZ", "-w", wl,
            "-mc", "200,201,301,302,307,403",
            "-o", out_path, "-of", "json",
            "-s", "-timeout", "10",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(out_path):
                import json
                with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.loads(f.read() or "{}")
                    for r in data.get("results", []):
                        findings.append({
                            "url": r.get("url", ""),
                            "status": r.get("status", 0),
                            "size": r.get("length", 0),
                        })
                os.remove(out_path)
            log(con, scan_id, f"ffuf found {len(findings)} paths")
        except subprocess.TimeoutExpired:
            log(con, scan_id, "ffuf timed out")
        except FileNotFoundError:
            log(con, scan_id, "ffuf not found, trying alternatives")
        except Exception as e:
            log(con, scan_id, f"ffuf error: {e}")

        # Cleanup temp wordlist
        if not wordlist:
            try:
                os.remove(f"_matthunder_wl_{scan_id}.txt")
            except OSError:
                pass

    # Try feroxbuster if ffuf not found
    if not findings:
        ferox = _resolve("feroxbuster")
        if ferox:
            log(con, scan_id, "Running feroxbuster...")
            out_path = f"_matthunder_fuzz_{scan_id}.txt"
            cmd = [
                ferox, "-u", f"https://{domain}",
                "-o", out_path, "-q", "--silent",
                "--auto-bail", "--timeout", "10",
            ]
            if wordlist:
                cmd.extend(["-w", wordlist])
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if os.path.exists(out_path):
                    with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 3:
                                findings.append({
                                    "url": parts[2] if len(parts) > 2 else "",
                                    "status": int(parts[0]) if parts[0].isdigit() else 0,
                                    "size": int(parts[1]) if parts[1].isdigit() else 0,
                                })
                    os.remove(out_path)
                log(con, scan_id, f"feroxbuster found {len(findings)} paths")
            except Exception as e:
                log(con, scan_id, f"feroxbuster error: {e}")

    # Try gobuster
    if not findings:
        gobuster = _resolve("gobuster")
        if gobuster:
            log(con, scan_id, "Running gobuster...")
            wl = wordlist or ""
            if not wl:
                for p in ["/usr/share/wordlists/dirb/common.txt"]:
                    if os.path.exists(p):
                        wl = p
                        break
            if wl:
                cmd = [
                    gobuster, "dir", "-u", f"https://{domain}",
                    "-w", wl, "-q", "-t", "20",
                ]
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    for line in (proc.stdout + proc.stderr).splitlines():
                        if "(Status:" in line:
                            parts = line.split()
                            url = parts[0] if parts else ""
                            status = ""
                            for p in parts:
                                if "Status:" in p:
                                    status = p.rstrip(")")
                            findings.append({"url": f"https://{domain}{url}", "status": status})
                    log(con, scan_id, f"gobuster found {len(findings)} paths")
                except Exception as e:
                    log(con, scan_id, f"gobuster error: {e}")

    # Fallback to builtin fuzzing
    if not findings:
        log(con, scan_id, "No fuzzer binary found, using built-in probe...")
        findings = _builtin_fuzz(domain)
        log(con, scan_id, f"Built-in probe found {len(findings)} paths")

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "directory", f.get("url", ""), str(f.get("status", "")),
             f"size={f.get('size', 0)}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=1, total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "fuzzer", "domain": domain, "findings": len(findings)}


SCANNER_REGISTRY["fuzzer"] = run
SCANNER_REGISTRY["fuzz"] = run
SCANNER_REGISTRY["dirscan"] = run
