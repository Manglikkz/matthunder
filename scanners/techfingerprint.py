"""
techfingerprint - Technology stack fingerprinting + stack-specific hunting.

Inspired by:
  - ChatGPT flow: tech fingerprinting → stack-specific vulns
  - Grok "Two-Eye" approach
  - Wappalyzer, WhatWeb

Detects frameworks and auto-suggests stack-specific attack vectors.

Usage:
  python matthunder_cli.py techfingerprint example.com
"""

import re
from urllib.parse import urlparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, finish_scan, log, normalize_domain,
    open_db, utc_now_iso,
)

# Stack signatures (header + body patterns)
STACK_SIGNATURES = {
    "laravel": {
        "headers": ["set-cookie: laravel_session", "x-powered-by:"],
        "body": ["laravel", "csrf-token", "laravel_session"],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "attacks": [
            "Debug mode: /_ignition/health-check",
            ".env exposure: /.env",
            "Telescope: /telescope",
            "Horizon: /horizon",
            "API routes: /api/",
            "Sanctum: /sanctum/csrf-cookie",
        ],
    },
    "nextjs": {
        "headers": ["x-powered-by: Next.js", "x-nextjs"],
        "body": ["_next/", "__next", "nextjs", "_buildManifest"],
        "cookies": [],
        "attacks": [
            "Source maps: /_next/static/chunks/*.js.map",
            "API routes: /api/",
            "Server actions: /_next/data/",
            "RSC payload: ?_rsc=",
            "ISR cache poisoning",
            "Middleware bypass via static paths",
        ],
    },
    "wordpress": {
        "headers": ["x-powered-by:", "link: <.*wp-json"],
        "body": ["wp-content", "wp-includes", "wordpress", "wp-json"],
        "cookies": ["wordpress_logged_in", "wp-settings"],
        "attacks": [
            "XMLRPC: /xmlrpc.php",
            "WP-Admin: /wp-admin/",
            "REST API: /wp-json/wp/v2/users",
            "Plugin vuln: /wp-content/plugins/",
            "User enum: /wp-json/wp/v2/users",
            "Debug log: /wp-content/debug.log",
        ],
    },
    "django": {
        "headers": ["x-frame-options: DENY", "set-cookie: csrftoken"],
        "body": ["csrfmiddlewaretoken", "django", "__admin__"],
        "cookies": ["csrftoken", "sessionid"],
        "attacks": [
            "Admin: /admin/",
            "Debug mode: /static/admin/",
            "Debug toolbar: /__debug__/",
            "API browsable: /api/",
            "Media files: /media/",
        ],
    },
    "express": {
        "headers": ["x-powered-by: Express"],
        "body": ["express", "node_modules"],
        "cookies": ["connect.sid", "express:sess"],
        "attacks": [
            "Prototype pollution: JSON merge with __proto__",
            "API routes: /api/",
            "Source maps: *.js.map",
            "Debug: /debug/",
            "env exposure: /.env",
        ],
    },
    "flask": {
        "headers": ["server: Werkzeug", "server: gunicorn"],
        "body": ["flask", "jinja2", "werkzeug"],
        "cookies": ["session"],
        "attacks": [
            "Debug console: /console",
            "SSTI: {{7*7}} in template params",
            "Source exposure: /static/*.py",
        ],
    },
    "spring": {
        "headers": ["x-application-context"],
        "body": ["spring", "springframework", "whitelabel error"],
        "cookies": ["JSESSIONID"],
        "attacks": [
            "Actuator: /actuator/env, /actuator/heapdump",
            "SpEL injection: ${7*7}",
            "H2 console: /h2-console",
            "Gateway routes: /actuator/gateway/routes",
        ],
    },
    "rails": {
        "headers": ["x-powered-by: Phusion Passenger", "server: nginx + passenger"],
        "body": ["rails", "ruby", "csrf-token", "authenticity_token"],
        "cookies": ["_session_id"],
        "attacks": [
            "Debug: /rails/info",
            "Console: /rails/console",
            "Mass assignment: strong parameters bypass",
        ],
    },
    "graphql": {
        "headers": ["content-type: application/json"],
        "body": ["graphql", "graphiql", "__schema", "introspection"],
        "cookies": [],
        "attacks": [
            "Introspection: POST /graphql {__schema{types{name}}}",
            "IDOR via node() query",
            "Batch query DoS",
            "Field suggestion leak",
        ],
    },
    "aspnet": {
        "headers": ["x-powered-by: ASP.NET", "x-aspnet-version"],
        "body": ["__viewstate", "__eventvalidation", "asp.net", "webresource.axd"],
        "cookies": ["ASP.NET_SessionId"],
        "attacks": [
            "ViewState deserialization",
            "trace.axd: /trace.axd",
            "elmah.axd: /elmah.axd",
            "Web.config exposure",
            "Debug mode: customErrors=Off",
        ],
    },
    "nginx": {
        "headers": ["server: nginx"],
        "body": ["nginx"],
        "cookies": [],
        "attacks": [
            "Alias traversal via off-by-slash",
            "CRLF injection in headers",
            "Server info: /server-status",
        ],
    },
    "apache": {
        "headers": ["server: Apache"],
        "body": ["apache", "mod_"],
        "cookies": [],
        "attacks": [
            "Server info: /server-info",
            "Server status: /server-status",
            ".htaccess exposure",
            "Directory listing",
        ],
    },
    "cloudflare": {
        "headers": ["server: cloudflare", "cf-ray", "cf-cache-status"],
        "body": ["cloudflare", "cf-error"],
        "cookies": ["__cflb", "__cfuid"],
        "attacks": [
            "Origin IP discovery (bypass CF)",
            "Cache deception",
            "WAF bypass techniques",
        ],
    },
}


def _detect_stack(domain: str, client: httpx.Client) -> dict:
    """Detect technology stack from HTTP responses."""
    detected = {}
    urls = [f"https://{domain}", f"http://{domain}"]

    for url in urls:
        try:
            r = client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            body_lower = r.text.lower()
            cookies_lower = {c.name.lower() for c in r.cookies.jar}

            for stack_name, sig in STACK_SIGNATURES.items():
                score = 0
                evidence = []

                # Check headers
                for h_pattern in sig["headers"]:
                    key, _, val = h_pattern.partition(": ")
                    h_val = headers_lower.get(key.lower(), "")
                    if val and val.lower() in h_val.lower():
                        score += 2
                        evidence.append(f"header: {key}: {h_val}")
                    elif not val and key.lower() in headers_lower:
                        score += 1
                        evidence.append(f"header: {key} present")

                # Check body
                for pattern in sig["body"]:
                    if pattern.lower() in body_lower:
                        score += 1
                        evidence.append(f"body: {pattern}")

                # Check cookies
                for cookie in sig["cookies"]:
                    if cookie.lower() in cookies_lower:
                        score += 2
                        evidence.append(f"cookie: {cookie}")

                if score >= 2:
                    detected[stack_name] = {
                        "score": score,
                        "evidence": evidence[:3],
                        "attacks": sig["attacks"],
                    }

        except Exception:
            continue

    return detected


def run(domain: str) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'techfingerprint', ?, ?, 'running', ?)",
        (domain, "header+body+cookie", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"Tech fingerprint started - domain: {domain}")

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        detected = _detect_stack(domain, client)

    stacks = list(detected.keys())
    log(con, scan_id, f"Detected: {', '.join(stacks) if stacks else 'none'}")

    # Store results
    for stack_name, info in detected.items():
        attacks_str = " | ".join(info["attacks"][:3])
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"tech_{stack_name}", domain, "detected",
             f"score={info['score']} attacks={attacks_str}", utc_now_iso()),
        )

    # Print report
    print(f"\n  \033[1m  Tech Stack Detection — {domain}\033[0m")
    if detected:
        for stack_name, info in sorted(detected.items(), key=lambda x: -x[1]["score"]):
            print(f"  \033[92m[+]\033[0m {stack_name.upper()} (score: {info['score']})")
            for ev in info["evidence"]:
                print(f"      {ev}")
            print(f"      \033[93mSuggested attacks:\033[0m")
            for atk in info["attacks"][:3]:
                print(f"        → {atk}")
    else:
        print(f"  \033[90m[-]\033[0m No stack detected (may be behind WAF/CDN)")

    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=1, total_links=len(detected))
    con.close()

    primary = stacks[0] if stacks else "unknown"
    return {
        "scan_id": scan_id,
        "scanner": "techfingerprint",
        "domain": domain,
        "stack": primary,
        "stacks": stacks,
        "detected": {k: {"score": v["score"], "attacks": v["attacks"]} for k, v in detected.items()},
        "findings": len(detected),
    }


SCANNER_REGISTRY["techfingerprint"] = run
SCANNER_REGISTRY["tech"] = run
