"""
scanners package — broken-link-hunter family ported from BLH-Hunter.

Modules:
  blh  — Broken Link Hunter (social/profile account status)
  bac  — Business Asset Collab (3rd-party resource links)
  cred — Credential/Config URL finder

Each scanner:
  * works offline against a target domain (passive: crawl + match)
  * writes results to matthunder_scans.db (SQLite, local)
  * exposes a unified run() entrypoint

Heavy FastAPI/UI pieces from original BLH-Hunter are intentionally not ported.
"""

DB_PATH = "matthunder_scans.db"

SCANNER_REGISTRY = {}

from . import blh, bac, cred, apirecon, ssti, cors, xss  # noqa: E402,F401
