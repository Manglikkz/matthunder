"""
scanners package — security scanning modules for matthunder.

Modules:
  blh            — Broken Link Hunter (social/profile account status)
  thirdparty     — Business Asset Collab (3rd-party resource links)
  cred           — Credential/Config URL finder
  apirecon       — API endpoint recon (kiterunner wrapper)
  ssti           — Server-Side Template Injection probe
  cors           — CORS Misconfiguration scanner
  xss            — Reflected XSS scanner (dalfox wrapper + manual fallback)
  sqli           — SQL Injection scanner (sqlmap + heuristic)
  lfi            — Local File Inclusion / Path Traversal
  crlf           — CRLF Injection scanner
  openredirect   — Open Redirect scanner
  ssrf           — Server-Side Request Forgery (internal + OOB)
  hostheader     — Host Header Injection (poisoning + cache + CRLF)
  graphql        — GraphQL Introspection & Security scanner
  portscan       — Port scanner (naabu/nmap/socket)
  waf            — WAF Detection (wafw00f + manual signatures)
  jsanalysis     — JavaScript secrets/endpoint extraction
  fuzzer         — Directory/path fuzzing (ffuf/feroxbuster/gobuster)
  pipeline       — Full 6-phase automated recon→hunt→hunt pipeline
  techfingerprint — Technology stack fingerprinting + stack-specific hunting
  gfpatterns     — GF-style URL pattern filtering by vuln type
  gate           — 7-Question Gate for finding validation
  attackrank     — Attack Surface Ranker (prioritize targets)
  acunetix       — Pull scans/vulnerabilities from Acunetix API
"""

DB_PATH = "matthunder_scans.db"

SCANNER_REGISTRY = {}

from . import (
    blh, thirdparty, cred, apirecon, ssti, cors, xss,
    sqli, lfi, crlf, openredirect, portscan, waf, jsanalysis, fuzzer,
    pipeline, techfingerprint, gfpatterns, gate, attackrank, acunetix,
    ssrf, hostheader, graphql, sourcedisc, jwt,
)  # noqa: E402,F401
