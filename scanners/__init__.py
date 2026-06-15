"""
scanners package — security scanning modules for matthunder.

Modules:
  blh         — Broken Link Hunter (social/profile account status)
  thirdparty  — Business Asset Collab (3rd-party resource links)
  cred        — Credential/Config URL finder
  apirecon    — API endpoint recon (kiterunner wrapper)
  ssti        — Server-Side Template Injection probe
  cors        — CORS Misconfiguration scanner
  xss         — Reflected XSS scanner (dalfox wrapper)
  sqli        — SQL Injection scanner (sqlmap + heuristic)
  lfi         — Local File Inclusion / Path Traversal
  crlf        — CRLF Injection scanner
  openredirect — Open Redirect scanner
  portscan    — Port scanner (naabu/nmap/socket)
  waf         — WAF Detection (wafw00f + manual signatures)
  jsanalysis  — JavaScript secrets/endpoint extraction
  fuzzer      — Directory/path fuzzing (ffuf/feroxbuster/gobuster)

Each scanner:
  * works offline against a target domain (passive: crawl + match)
  * writes results to matthunder_scans.db (SQLite, local)
  * exposes a unified run() entrypoint
"""

DB_PATH = "matthunder_scans.db"

SCANNER_REGISTRY = {}

from . import (
    blh, thirdparty, cred, apirecon, ssti, cors, xss,
    sqli, lfi, crlf, openredirect, portscan, waf, jsanalysis, fuzzer,
)  # noqa: E402,F401
