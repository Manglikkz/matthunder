"""
jwt - JWT Analyzer & Weakness detector.

Analyzes JWT tokens found in cookies, headers, and responses for:
  - Algorithm confusion (RS256 → HS256)
  - None algorithm bypass
  - Weak signing secrets
  - Sensitive data exposure in payload
  - Expired/invalid tokens

Usage:
  python matthunder_cli.py jwt example.com
"""

import base64
import hashlib
import hmac
import json
import os
import re
from typing import Optional
from urllib.parse import urlparse

import httpx

from . import SCANNER_REGISTRY
from .common import (
    DEFAULT_TIMEOUT, USER_AGENT, crawl_domain,
    finish_scan, log, normalize_domain, open_db, utc_now_iso,
)


# ── Common weak secrets ───────────────────────────────────────────────────

WEAK_SECRETS = [
    "secret", "password", "jwt_secret", "key", "changeme",
    "supersecret", "mysecret", "123456", "admin", "test",
    "jwt", "token", "s3cr3t", "shhh", "keyboard cat",
    "your-256-bit-secret", "your-256-bit-secret-here",
    "256-bit-secret", "symmetric-secret",
    "HS256-secret", "hmac-secret",
    "development", "staging", "production",
    "debug", "test123", "admin123",
]

# ── Known algorithm attacks ────────────────────────────────────────────────

ALGORITHM_CONFUSION = {
    "RS256": "HS256",  # Can forge with public key
    "RS384": "HS384",
    "RS512": "HS512",
    "ES256": "HS256",
    "ES384": "HS384",
    "ES512": "HS512",
    "PS256": "HS256",
    "PS384": "HS384",
    "PS512": "HS512",
}


def _b64url_decode(data: str) -> bytes:
    """Decode base64url encoded data."""
    # Add padding
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    """Encode data to base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _parse_jwt(token: str) -> dict:
    """Parse JWT token and return header, payload, and signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        signature = parts[2]
    except Exception:
        return None

    return {"header": header, "payload": payload, "signature": signature, "raw": token}


def _find_jwt_tokens(text: str) -> list[str]:
    """Find JWT tokens in text."""
    # Standard JWT pattern: eyJ... (base64url encoded header)
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    tokens = re.findall(jwt_pattern, text)
    return list(set(tokens))


def _analyze_jwt(token_data: dict) -> dict:
    """Analyze a JWT token for weaknesses."""
    findings = []
    header = token_data["header"]
    payload = token_data["payload"]

    # 1. Check algorithm
    alg = header.get("alg", "").upper()

    if alg == "NONE":
        findings.append({
            "type": "none_algorithm",
            "severity": "critical",
            "detail": "JWT uses 'none' algorithm — signature bypass possible",
        })

    if alg in ALGORITHM_CONFUSION:
        findings.append({
            "type": "algorithm_confusion",
            "severity": "high",
            "detail": f"Algorithm {alg} can be confused with {ALGORITHM_CONFUSION[alg]}",
        })

    if alg.startswith("HS"):
        # Symmetric algorithm — check for weak secrets
        findings.append({
            "type": "symmetric_algorithm",
            "severity": "info",
            "detail": f"Uses symmetric algorithm {alg} — vulnerable to brute force",
        })

    # 2. Check for sensitive data in payload
    sensitive_keys = ["password", "passwd", "pwd", "secret", "token", "api_key",
                      "apikey", "access_token", "refresh_token", "private_key",
                      "credit_card", "ssn", "email", "phone"]

    for key in payload:
        key_lower = key.lower()
        for sensitive in sensitive_keys:
            if sensitive in key_lower:
                value = payload[key]
                # Truncate long values
                if isinstance(value, str) and len(value) > 50:
                    value = value[:20] + "..."
                findings.append({
                    "type": "sensitive_data_exposure",
                    "severity": "high",
                    "detail": f"Payload contains '{key}' = {value}",
                })
                break

    # 3. Check expiration
    if "exp" in payload:
        import time
        exp = payload["exp"]
        if isinstance(exp, (int, float)):
            if exp < time.time():
                findings.append({
                    "type": "expired_token",
                    "severity": "medium",
                    "detail": f"Token expired at {exp}",
                })

    # 4. Check for missing critical claims
    if "iss" not in payload:
        findings.append({
            "type": "missing_issuer",
            "severity": "low",
            "detail": "Token missing 'iss' (issuer) claim",
        })

    if "aud" not in payload:
        findings.append({
            "type": "missing_audience",
            "severity": "low",
            "detail": "Token missing 'aud' (audience) claim",
        })

    # 5. Check kid (key ID) for injection
    kid = header.get("kid", "")
    if kid:
        if "../" in kid or "..\\" in kid:
            findings.append({
                "type": "kid_path_traversal",
                "severity": "critical",
                "detail": f"Key ID contains path traversal: {kid}",
            })
        if "null" in kid.lower():
            findings.append({
                "type": "kid_null_injection",
                "severity": "critical",
                "detail": f"Key ID contains 'null': {kid}",
            })

    # 6. Check for jku/x5u URL injection
    for url_field in ["jku", "x5u"]:
        if url_field in header:
            url = header[url_field]
            findings.append({
                "type": f"{url_field}_url_injection",
                "severity": "high",
                "detail": f"Header contains {url_field}: {url} — can be used for key injection",
            })

    # 7. Check for weak secrets (common ones)
    alg_name = header.get("alg", "")
    if alg_name.startswith("HS"):
        for secret in WEAK_SECRETS[:5]:  # Check top 5 only for speed
            try:
                test_sig = hmac.new(
                    secret.encode(),
                    token_data["raw"].rsplit(".", 1)[0].encode(),
                    hashlib.sha256 if "256" in alg_name else hashlib.sha384 if "384" in alg_name else hashlib.sha512
                ).digest()
                test_b64 = _b64url_encode(test_sig)
                if hmac.compare_digest(test_b64, token_data["signature"]):
                    findings.append({
                        "type": "weak_secret",
                        "severity": "critical",
                        "detail": f"Weak secret found: '{secret}'",
                    })
                    break
            except Exception:
                continue

    return findings


def _probe_jwt_endpoint(url: str, client: httpx.Client) -> list[str]:
    """Try to find JWT tokens from various endpoints."""
    tokens = set()

    # Try login/register endpoints
    test_endpoints = [
        ("/api/auth/login", "POST", {"username": "admin", "password": "admin"}),
        ("/api/login", "POST", {"username": "admin", "password": "admin"}),
        ("/auth/login", "POST", {"username": "admin", "password": "admin"}),
        ("/login", "POST", {"username": "admin", "password": "admin"}),
        ("/api/v1/auth", "POST", {"username": "admin", "password": "admin"}),
        ("/token", "POST", {"grant_type": "client_credentials"}),
        ("/oauth/token", "POST", {"grant_type": "client_credentials"}),
    ]

    for path, method, data in test_endpoints:
        try:
            if method == "POST":
                r = client.post(f"{url}{path}", json=data, timeout=5, follow_redirects=False)
            else:
                r = client.get(f"{url}{path}", timeout=5, follow_redirects=False)

            # Check response body
            body = r.text or ""
            tokens.update(_find_jwt_tokens(body))

            # Check Set-Cookie headers
            for cookie in r.headers.get_list("set-cookie"):
                tokens.update(_find_jwt_tokens(cookie))

        except Exception:
            continue

    return list(tokens)


def run(domain: str, max_pages: int = 20) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'jwt', ?, ?, 'running', ?)",
        (domain, "analysis+weakness+secret", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"JWT scan started - domain: {domain}")

    base_urls = [f"https://{domain}", f"http://{domain}"]
    all_tokens = set()

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        # 1. Crawl pages for JWT tokens
        pages = crawl_domain(domain, max_pages=max_pages)
        log(con, scan_id, f"Crawled {len(pages)} pages")

        for page_url, html in pages:
            if html:
                all_tokens.update(_find_jwt_tokens(html))

        # 2. Check cookies on main pages
        for base in base_urls:
            try:
                r = client.get(base, timeout=DEFAULT_TIMEOUT)
                for cookie in r.headers.get_list("set-cookie"):
                    all_tokens.update(_find_jwt_tokens(cookie))

                # Check Authorization header in response
                auth = r.headers.get("www-authenticate", "")
                if "Bearer" in auth:
                    token_match = re.search(r'Bearer\s+([A-Za-z0-9._-]+)', auth)
                    if token_match:
                        all_tokens.add(token_match.group(1))
            except Exception:
                continue

        # 3. Try common auth endpoints
        for base in base_urls:
            tokens = _probe_jwt_endpoint(base, client)
            all_tokens.update(tokens)

        log(con, scan_id, f"Found {len(all_tokens)} JWT tokens")

        # 4. Analyze each token
        all_findings = []
        for token in all_tokens:
            token_data = _parse_jwt(token)
            if not token_data:
                continue

            log(con, scan_id, f"Analyzing JWT: alg={token_data['header'].get('alg', '?')}")
            findings = _analyze_jwt(token_data)

            for f in findings:
                f["token_preview"] = token[:50] + "..."
                f["header"] = token_data["header"]
                f["payload"] = {k: str(v)[:50] for k, v in token_data["payload"].items()}
                all_findings.append(f)

    log(con, scan_id, f"Found {len(all_findings)} JWT weaknesses")

    for f in all_findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"jwt_{f['type']}", domain, f["severity"],
             f"detail={f['detail']} token={f.get('token_preview', '')}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=len(all_tokens), total_links=len(all_findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "jwt", "domain": domain, "tokens_found": len(all_tokens), "findings": len(all_findings)}


SCANNER_REGISTRY["jwt"] = run
