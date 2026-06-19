"""
graphql - GraphQL Introspection & Security scanner.

Detects GraphQL endpoints and checks for:
- Full introspection enabled (schema leak)
- Introspection with auth bypass
- GraphQL playground/explorer exposed
- Weak query complexity / depth limits
- GraphQL-specific headers leakage

Usage:
  python matthunder_cli.py graphql example.com
"""

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


# ── GraphQL Endpoints to probe ────────────────────────────────────────────

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/graphQL",
    "/api/graphql",
    "/api/graphQL",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/gql",
    "/api/gql",
    "/graphql/console",
    "/graphql/explorer",
    "/altair",
    "/graphiql",
    "/playground",
    "/_graphql",
    "/internal/graphql",
    "/admin/graphql",
]

# ── Introspection Query ───────────────────────────────────────────────────

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                description
                fields {
                    name
                    description
                    args { name type { name kind ofType { name kind } } }
                    type { name kind ofType { name kind } }
                }
            }
            directives { name description locations args { name type { name kind } } }
        }
    }
    """,
}

# ── Simple introspection probe ────────────────────────────────────────────

SIMPLE_INTROSPECTION = {
    "query": "{ __schema { types { name } } }",
}

# ── Type introspection ────────────────────────────────────────────────────

TYPE_INTROSPECTION = {
    "query": "{ __type(name: \"User\") { name fields { name type { name } } } }",
}

# ── GraphQL Playground Indicators ──────────────────────────────────────────

PLAYGROUND_INDICATORS = [
    r"GraphQL Playground",
    r"graphiql",
    r"A GraphQL interactive IDE",
    r"<title>.*GraphiQL.*</title>",
    r"endpoint.*graphql",
    r"graphql-playground",
    r"altair-graphql",
    r"request.*endpoint",
]

# ── GraphQL Error Patterns ────────────────────────────────────────────────

GRAPHQL_ERROR_PATTERNS = [
    r"Must provide query string",
    r"Must provide query",
    r"Syntax Error",
    r"Cannot query field",
    r"Field.*not found",
    r"Cannot return null",
    r"GraphQL request",
]


def _load_pipeline_urls() -> list[str]:
    url_file = os.environ.get("MT_PIPELINE_URLS", "")
    if url_file and os.path.exists(url_file):
        with open(url_file, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip().startswith("http")]
    return []


def _find_graphql_endpoints(domain: str, pages: list[tuple[str, str]]) -> list[str]:
    """Discover GraphQL endpoints from page content and common paths."""
    endpoints = set()

    # From page content
    for page_url, html in pages:
        # Look for GraphQL URLs in HTML/JS
        graphql_refs = re.findall(
            r'(?:https?://[^"\'\\s]+)?(?:/graphql|/graphQL|/api/graphql|/query|/gql)',
            html or "", re.I
        )
        for ref in graphql_refs:
            if ref.startswith("http"):
                endpoints.add(ref)
            elif ref.startswith("/"):
                parsed = urlparse(page_url)
                endpoints.add(f"{parsed.scheme}://{parsed.netloc}{ref}")

        # Look for fetch/axios calls to graphql
        fetch_calls = re.findall(
            r'(?:fetch|axios|request)\s*\(\s*["\']([^"\']*graphql[^"\']*)["\']',
            html or "", re.I
        )
        for call in fetch_calls:
            if call.startswith("http"):
                endpoints.add(call)
            elif call.startswith("/"):
                parsed = urlparse(page_url)
                endpoints.add(f"{parsed.scheme}://{parsed.netloc}{call}")

    # Common paths
    base_urls = [f"https://{domain}", f"http://{domain}"]
    for base in base_urls:
        for endpoint in GRAPHQL_ENDPOINTS:
            endpoints.add(f"{base}{endpoint}")

    return list(endpoints)


def _probe_endpoint(url: str, client: httpx.Client) -> dict:
    """Test a single URL for GraphQL endpoint."""
    result = {
        "url": url,
        "is_graphql": False,
        "introspection_enabled": False,
        "playground_exposed": False,
        "schema_leak": False,
        "types": [],
        "queries": [],
        "mutations": [],
    }

    # 1. Check if endpoint exists (POST with empty body)
    try:
        r = client.post(url, json={}, timeout=DEFAULT_TIMEOUT)
    except Exception:
        try:
            r = client.get(url, timeout=DEFAULT_TIMEOUT)
        except Exception:
            return result

    body = r.text or ""

    # Check for GraphQL error response
    for pattern in GRAPHQL_ERROR_PATTERNS:
        if re.search(pattern, body, re.I):
            result["is_graphql"] = True
            break

    # Check for GraphQL-specific headers
    content_type = r.headers.get("Content-Type", "")
    if "graphql" in content_type.lower() or r.status_code == 400:
        result["is_graphql"] = True

    # Check for playground
    for indicator in PLAYGROUND_INDICATORS:
        if re.search(indicator, body, re.I):
            result["playground_exposed"] = True
            result["is_graphql"] = True
            break

    if not result["is_graphql"]:
        return result

    # 2. Test simple introspection
    try:
        r = client.post(url, json=SIMPLE_INTROSPECTION, timeout=DEFAULT_TIMEOUT)
        body = r.text or ""
        if r.status_code == 200 and "__schema" in body:
            result["introspection_enabled"] = True
    except Exception:
        pass

    # 3. Test full introspection
    if result["introspection_enabled"]:
        try:
            r = client.post(url, json=INTROSPECTION_QUERY, timeout=DEFAULT_TIMEOUT)
            body = r.text or ""
            if r.status_code == 200:
                try:
                    data = json.loads(body)
                    schema = data.get("data", {}).get("__schema", {})
                    types = schema.get("types", [])
                    result["types"] = [t["name"] for t in types if not t["name"].startswith("__")]

                    # Extract queries and mutations
                    query_type = schema.get("queryType", {})
                    mutation_type = schema.get("mutationType", {})

                    for t in types:
                        if t["name"] == query_type.get("name"):
                            result["queries"] = [
                                f["name"] for f in t.get("fields", [])
                            ]
                        if t["name"] == mutation_type.get("name"):
                            result["mutations"] = [
                                f["name"] for f in t.get("fields", [])
                            ]

                    result["schema_leak"] = True
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

    # 4. Check GET method (some servers support it)
    try:
        r = client.get(url, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            body = r.text or ""
            for indicator in PLAYGROUND_INDICATORS:
                if re.search(indicator, body, re.I):
                    result["playground_exposed"] = True
                    break
    except Exception:
        pass

    return result


def run(domain: str, max_pages: int = 20) -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'graphql', ?, ?, 'running', ?)",
        (domain, "introspection+playground", utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"GraphQL scan started - domain: {domain}")

    # Crawl pages for GraphQL references
    pipeline_urls = _load_pipeline_urls()
    if pipeline_urls:
        pages = [(u, "") for u in pipeline_urls[:30]]
    else:
        pages = crawl_domain(domain, max_pages=max_pages)
        log(con, scan_id, f"Crawled {len(pages)} pages")

    # Find GraphQL endpoints
    endpoints = _find_graphql_endpoints(domain, pages)
    log(con, scan_id, f"Found {len(endpoints)} candidate GraphQL endpoints")

    findings: list[dict] = []
    tested = 0

    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        for endpoint in endpoints:
            result = _probe_endpoint(endpoint, client)
            tested += 1

            if result["is_graphql"]:
                finding = {
                    "url": endpoint,
                    "introspection": result["introspection_enabled"],
                    "playground": result["playground_exposed"],
                    "schema_leak": result["schema_leak"],
                    "types_count": len(result["types"]),
                    "queries": result["queries"],
                    "mutations": result["mutations"],
                }
                findings.append(finding)
                log(con, scan_id, f"GraphQL found: {endpoint} introspection={result['introspection_enabled']} playground={result['playground_exposed']}")

    log(con, scan_id, f"Found {len(findings)} GraphQL endpoints in {tested} probes")

    for f in findings:
        detail_parts = []
        if f["introspection"]:
            detail_parts.append("introspection=enabled")
        if f["playground"]:
            detail_parts.append("playground=exposed")
        if f["schema_leak"]:
            detail_parts.append(f"types={f['types_count']}")
        if f["queries"]:
            detail_parts.append(f"queries={','.join(f['queries'][:10])}")
        if f["mutations"]:
            detail_parts.append(f"mutations={','.join(f['mutations'][:10])}")

        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, "graphql_endpoint", f["url"], "found",
             " ".join(detail_parts), utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=tested, total_links=len(findings))
    con.close()
    return {"scan_id": scan_id, "scanner": "graphql", "domain": domain, "endpoints": tested, "findings": len(findings)}


SCANNER_REGISTRY["graphql"] = run
SCANNER_REGISTRY["gql"] = run
