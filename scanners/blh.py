"""
BLH scanner — Broken Link Hunter.

Discovers social/profile links on in-scope pages and checks whether each
account is alive / broken / redirected / blocked / timeout / unknown.
Ported from BLH-Hunter lazy_dorking.blh.scanner (streamlined, no FastAPI).
"""

import re
from typing import Optional
from urllib.parse import urlparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, canonical_url, crawl_domain,
    extract_anchors, fetch, finish_scan, host_in_scope, log, normalize_domain, open_db,
    utc_now_iso,
)


PLATFORM_DOMAINS = {
    "twitter":  ["twitter.com", "x.com"],
    "instagram": ["instagram.com"],
    "tiktok":   ["tiktok.com"],
    "facebook": ["facebook.com", "fb.com"],
    "youtube":  ["youtube.com", "youtu.be"],
    "linkedin": ["linkedin.com"],
    "github":   ["github.com"],
    "discord":  ["discord.gg", "discord.com"],
    "bitly":    ["bit.ly"],
    "flickr":   ["flickr.com"],
}

ACCOUNT_PATH_PATTERNS = {
    "twitter.com":   re.compile(r"^/[A-Za-z0-9_]{1,50}/?$"),
    "x.com":         re.compile(r"^/[A-Za-z0-9_]{1,50}/?$"),
    "instagram.com": re.compile(r"^/[A-Za-z0-9_.]{1,50}/?$"),
    "facebook.com":  re.compile(r"^/[A-Za-z0-9_.-]{1,80}/?$"),
    "fb.com":        re.compile(r"^/[A-Za-z0-9_.-]{1,80}/?$"),
    "youtube.com":   re.compile(r"^/@[\w.-]{1,80}/?$"),
    "youtu.be":      re.compile(r"^/[A-Za-z0-9_-]{1,20}/?$"),
    "linkedin.com":  re.compile(r"^/in/[\w%-]{1,100}/?$"),
    "github.com":    re.compile(r"^/[A-Za-z0-9-]{1,39}/?$"),
    "tiktok.com":    re.compile(r"^/@[\w.]{1,50}/?$"),
    "discord.gg":    re.compile(r"^/[A-Za-z0-9-]{1,32}/?$"),
    "discord.com":   re.compile(r"^/invite/[A-Za-z0-9-]{1,32}/?$"),
    "bit.ly":        re.compile(r"^/[A-Za-z0-9_-]{1,128}/?$"),
    "flickr.com":    re.compile(r"^/(?:photos|people)/[A-Za-z0-9@._-]{1,100}/?$"),
}

RESERVED_PATHS: dict[str, frozenset] = {
    "twitter.com":   frozenset({"home", "login", "logout", "signup", "explore", "search", "share", "intent", "i", "hashtag"}),
    "x.com":         frozenset({"home", "login", "logout", "signup", "explore", "search", "share", "intent", "i", "hashtag"}),
    "instagram.com": frozenset({"accounts", "explore", "p", "reel", "reels", "stories", "tv", "login", "signup"}),
    "facebook.com":  frozenset({"events", "groups", "pages", "marketplace", "watch", "login", "signup", "help", "settings"}),
    "fb.com":        frozenset({"events", "groups", "pages", "marketplace", "watch", "login", "signup", "help"}),
    "youtube.com":   frozenset({"watch", "results", "feed", "playlist", "channel", "embed", "shorts", "live", "music"}),
    "github.com":    frozenset({"login", "logout", "signup", "explore", "topics", "trending", "settings", "notifications", "pulls", "issues"}),
    "linkedin.com":  frozenset({"feed", "login", "signup", "jobs", "messaging", "search", "mynetwork"}),
    "bit.ly":        frozenset({"pages", "pricing", "sign-in", "sign_up", "login", "oauth"}),
    "flickr.com":    frozenset({"about", "explore", "groups", "map", "prints", "search", "services", "signin", "signup"}),
}

FB_NOT_FOUND_HINTS = (
    "this page isn't available",
    "this content isn't available right now",
    "the link you followed may be broken",
    "page not found",
)


def get_platform_for_host(host: str) -> Optional[str]:
    h = (host or "").lower()
    for plat, domains in PLATFORM_DOMAINS.items():
        for d in domains:
            if h == d or h.endswith("." + d):
                return plat
    return None


def is_account_url(url: str) -> Optional[str]:
    """Return platform name if URL looks like a profile/account, else None."""
    cu = canonical_url(url)
    if not cu:
        return None
    p = urlparse(cu)
    host = p.netloc
    plat = get_platform_for_host(host)
    if not plat:
        return None
    pat = ACCOUNT_PATH_PATTERNS.get(host)
    if not pat:
        return None
    if not pat.match(p.path or "/"):
        return None
    first_seg = (p.path or "/").strip("/").split("/")[0]
    if first_seg and first_seg in RESERVED_PATHS.get(host, frozenset()):
        return None
    return plat


def classify_status(url: str, code: Optional[int], body: Optional[str], error: Optional[str]) -> str:
    if error == "timeout":
        return "timeout"
    if error:
        return "unknown"
    if code is None:
        return "unknown"
    if 200 <= code < 300:
        if body and any(h in body.lower() for h in FB_NOT_FOUND_HINTS):
            return "broken"
        return "alive"
    if 300 <= code < 400:
        return "redirect"
    if code in (401, 403, 407):
        return "blocked"
    if code == 404 or code == 410:
        return "broken"
    if 400 <= code < 500:
        return "broken"
    if 500 <= code < 600:
        return "blocked"
    return "unknown"


def run(domain: str, platforms: list[str], max_pages: int = 30) -> dict:
    domain = normalize_domain(domain)
    platforms = [p for p in (platforms or list(PLATFORM_DOMAINS.keys())) if p in PLATFORM_DOMAINS]
    if not platforms:
        platforms = list(PLATFORM_DOMAINS.keys())

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'blh', ?, ?, 'running', ?)",
        (domain, str(platforms), utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"BLH scan started - domain: {domain} | platforms: {', '.join(platforms)}")

    pages = crawl_domain(domain, max_pages=max_pages)
    log(con, scan_id, f"Crawled {len(pages)} pages")

    found: list[dict] = []
    for page_url, html in pages:
        for a in extract_anchors(html, page_url):
            plat = is_account_url(a["canonical"])
            if not plat or plat not in platforms:
                continue
            found.append({
                "platform": plat,
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
    log(con, scan_id, f"Discovered {len(unique)} candidate social/profile links")

    checked = 0
    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        for f in unique:
            code, body, err = None, None, None
            try:
                r = client.get(f["target_url"], timeout=DEFAULT_TIMEOUT)
                code = r.status_code
                body = r.text[:50000] if r.text else ""
            except httpx.TimeoutException:
                err = "timeout"
            except Exception as e:
                err = type(e).__name__
            status = classify_status(f["target_url"], code, body, err)
            con.execute(
                "INSERT INTO results (scan_id, category, target_url, source_url, anchor, status, http_code, detail, extracted_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, f["platform"], f["target_url"], f["source_url"], f["anchor"], status, code, err or "", utc_now_iso()),
            )
            checked += 1

    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(pages), total_links=checked)
    log(con, scan_id, f"BLH scan completed - {checked} links checked")
    con.close()
    return {"scan_id": scan_id, "scanner": "blh", "domain": domain, "pages": len(pages), "links_checked": checked}


SCANNER_REGISTRY["blh"] = run
