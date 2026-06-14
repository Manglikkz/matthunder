"""
3rd-party asset links scanner (renamed from BAC to avoid conflict with the
OWASP "Broken Access Control" term).

Discovers publicly linked third-party resources (Google Drive, SharePoint,
GitHub, Notion, Trello, Figma, Dropbox) referenced from in-scope pages.
Ported from BLH-Hunter lazy_dorking.bac.scanner (streamlined).
"""

from typing import Optional
from urllib.parse import urlparse

from . import SCANNER_REGISTRY
from .common import (
    canonical_url, crawl_domain, finish_scan, log, normalize_domain,
    open_db, utc_now_iso, extract_anchors,
)


BAC_SERVICES = {
    "google_drive": ["drive.google.com"],
    "google_docs":  ["docs.google.com"],
    "sharepoint":   ["sharepoint.com"],
    "onedrive":     ["onedrive.com", "1drv.ms"],
    "dropbox":      ["dropbox.com", "dropboxs.com"],
    "github":       ["github.com"],
    "notion":       ["notion.so", "notion.site"],
    "trello":       ["trello.com"],
    "figma":        ["figma.com"],
    "atlassian":    ["atlassian.net"],
}

EXCLUDE_PATH_HINTS = {
    "drive.google.com": ["/file/", "/folders/", "/u/"],
    "github.com":       ["/login", "/signup", "/settings", "/marketplace"],
    "notion.so":        ["/login", "/signup"],
    "trello.com":       ["/login", "/signup"],
    "figma.com":        ["/login", "/signup", "/community"],
    "dropbox.com":      ["/login", "/signup", "/business"],
}


def get_service_for_host(host: str) -> Optional[str]:
    h = (host or "").lower()
    for svc, domains in BAC_SERVICES.items():
        for d in domains:
            if h == d or h.endswith("." + d):
                return svc
    return None


def is_target_link(url: str) -> Optional[str]:
    cu = canonical_url(url)
    if not cu:
        return None
    p = urlparse(cu)
    svc = get_service_for_host(p.netloc)
    if not svc:
        return None
    excludes = EXCLUDE_PATH_HINTS.get(p.netloc, [])
    if any((p.path or "").startswith(x) for x in excludes):
        return None
    return svc


def run(domain: str, services: list[str], max_pages: int = 30) -> dict:
    domain = normalize_domain(domain)
    services = [s for s in (services or list(BAC_SERVICES.keys())) if s in BAC_SERVICES]
    if not services:
        services = list(BAC_SERVICES.keys())

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'bac', ?, ?, 'running', ?)",
        (domain, str(services), utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"BAC scan started - domain: {domain} | services: {', '.join(services)}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    found: list[dict] = []
    for page_url, html in pages:
        for a in extract_anchors(html, page_url):
            svc = is_target_link(a["canonical"])
            if not svc or svc not in services:
                continue
            found.append({
                "service": svc,
                "target_url": a["canonical"],
                "source_url": page_url,
                "anchor": a["anchor"],
            })

    seen = set()
    unique = []
    for f in found:
        if f["target_url"] in seen:
            continue
        seen.add(f["target_url"])
        unique.append(f)
    log(con, scan_id, f"Discovered {len(unique)} 3rd-party resource links")

    for f in unique:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, source_url, anchor, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, 'discovered', '', ?)",
            (scan_id, f["service"], f["target_url"], f["source_url"], f["anchor"], utc_now_iso()),
        )

    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=len(unique))
    log(con, scan_id, f"3rd-party asset scan completed - {len(unique)} resource links recorded")
    con.close()
    return {"scan_id": scan_id, "scanner": "thirdparty", "domain": domain, "pages": len(pages), "links_found": len(unique)}


SCANNER_REGISTRY["thirdparty"] = run
SCANNER_REGISTRY["tpa"] = run  # short alias
