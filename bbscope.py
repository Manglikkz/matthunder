"""
bbscope - Bug Bounty Scope Aggregator

Pulls latest scope from public bug bounty program lists and writes to
public-bug-bounty-program/.

Sources:
  - chaos-bugbounty-list.json  (disclosed/discover project)
  - hackerone/bugcrowd/intigriti/yeswehack/immunefi/hackenproof
    (txt lists, refreshed on best-effort)
  - Local: program_domain wildcards (handled by scoper.py)

Usage:
  python bbscope.py                     # fetch all
  python bbscope.py hackerone           # single platform
  python bbscope.py --platform hackerone --output public-bug-bounty-program/
"""

import argparse
import json
import os
import sys
import time
from typing import Iterable
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

USER_AGENT = "matthunder-bbscope/1.0 (+https://github.com/hmad28/matthunder)"

PLATFORMS = {
    "hackerone":   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd":    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "intigriti":   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
    "yeswehack":   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
    "federacy":    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/federacy_data.json",
    "hackenproof": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackenproof_data.json",
    "domains":     "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
    "wildcards":   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt",
}

CHAOS_URL = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json"
CHAOS_SCHEMA_URL = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.schema.json"


def fetch_text(url: str, timeout: int = 30) -> str:
    if requests is None:
        raise RuntimeError("requests module required")
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
    r.raise_for_status()
    return r.text


def fetch_platform(scope_name: str, out_dir: str, timeout: int = 30) -> dict:
    url = PLATFORMS.get(scope_name)
    if not url:
        return {"platform": scope_name, "ok": False, "error": "unknown platform"}
    try:
        data = fetch_text(url, timeout=timeout)
    except Exception as e:
        return {"platform": scope_name, "ok": False, "error": str(e)}
    if scope_name in ("intigriti", "yeswehack", "federacy", "hackenproof"):
        try:
            parsed = json.loads(data)
            domains = set()
            for entry in parsed:
                for t in entry.get("targets", {}).get("in_scope", []):
                    asset = (t.get("endpoint", "") or t.get("url", "") or t.get("domain", ""))
                    if not asset:
                        continue
                    host = asset.strip().lower().lstrip("*.")
                    try:
                        if "://" in host:
                            host = urlparse(host).netloc
                    except Exception:
                        pass
                    if host:
                        domains.add(host)
            out_path = os.path.join(out_dir, f"{scope_name}_bounty.txt")
            with open(out_path, "w", encoding="utf-8") as f:
                for d in sorted(domains):
                    if d:
                        f.write(d + "\n")
            return {"platform": scope_name, "ok": True, "domains": len(domains), "path": out_path}
        except Exception as e:
            return {"platform": scope_name, "ok": False, "error": f"parse: {e}"}
    elif scope_name in ("hackerone", "bugcrowd"):
        try:
            parsed = json.loads(data)
            domains = set()
            for entry in parsed:
                targets = entry.get("targets", {}) if isinstance(entry.get("targets"), dict) else {}
                for t in targets.get("in_scope", []):
                    asset = (t.get("asset_identifier", "") or t.get("endpoint", "") or t.get("url", "") or t.get("domain", ""))
                    if not asset:
                        continue
                    host = asset.strip().lower().lstrip("*.")
                    try:
                        if "://" in host:
                            host = urlparse(host).netloc
                    except Exception:
                        pass
                    if host and "." in host:
                        domains.add(host)
            out_path = os.path.join(out_dir, f"{scope_name}_bounty.txt")
            with open(out_path, "w", encoding="utf-8") as f:
                for d in sorted(domains):
                    if d:
                        f.write(d + "\n")
            return {"platform": scope_name, "ok": True, "domains": len(domains), "path": out_path}
        except Exception as e:
            return {"platform": scope_name, "ok": False, "error": f"parse json: {e}"}
    elif scope_name in ("domains", "wildcards"):
        domains = sorted({
            line.strip().lower().lstrip("*.")
            for line in data.splitlines()
            if line.strip() and not line.startswith("#")
        })
        out_path = os.path.join(out_dir, f"{scope_name}.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            for d in domains:
                if d:
                    f.write(d + "\n")
        return {"platform": scope_name, "ok": True, "domains": len(domains), "path": out_path}
    else:
        domains = sorted({
            line.strip().lower().lstrip("*.")
            for line in data.splitlines()
            if line.strip() and not line.startswith("#")
        })
        out_path = os.path.join(out_dir, f"{scope_name}_bounty.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            for d in domains:
                if d:
                    f.write(d + "\n")
        return {"platform": scope_name, "ok": True, "domains": len(domains), "path": out_path}


def fetch_chaos(out_dir: str, timeout: int = 30) -> dict:
    try:
        raw = fetch_text(CHAOS_URL, timeout=timeout)
        parsed = json.loads(raw)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    out_path = os.path.join(out_dir, "chaos-bugbounty-list.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2)
    try:
        schema = fetch_text(CHAOS_SCHEMA_URL, timeout=timeout)
        with open(os.path.join(out_dir, "chaos-bugbounty-list.schema.json"), "w", encoding="utf-8") as f:
            f.write(schema)
    except Exception:
        pass
    return {"ok": True, "programs": len(parsed) if isinstance(parsed, list) else 0, "path": out_path}


def run_all(out_dir: str = "public-bug-bounty-program", timeout: int = 30) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for plat in PLATFORMS:
        results.append(fetch_platform(plat, out_dir, timeout=timeout))
    chaos = fetch_chaos(out_dir, timeout=timeout)
    return {"results": results, "chaos": chaos}


def main():
    p = argparse.ArgumentParser(description="matthunder bbscope - bug bounty scope aggregator")
    p.add_argument("platform", nargs="?", choices=list(PLATFORMS.keys()) + ["chaos", "all"], default="all")
    p.add_argument("-o", "--output", default="public-bug-bounty-program")
    p.add_argument("--timeout", type=int, default=30)
    args = p.parse_args()

    if args.platform == "all":
        out = run_all(args.output, args.timeout)
        for r in out["results"]:
            print(r)
        print(out["chaos"])
    elif args.platform == "chaos":
        print(fetch_chaos(args.output, args.timeout))
    else:
        print(fetch_platform(args.platform, args.output, args.timeout))


if __name__ == "__main__":
    main()
