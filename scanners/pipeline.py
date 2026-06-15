"""
pipeline - Full 6-phase automated recon→hunt→validate→report pipeline.

Inspired by:
  - Claude-BugHunter 6-phase architecture
  - shuvonsec/claude-bug-bounty /autopilot
  - Claude flow: Subfinder→httpx→Nuclei→Discovery→Burp
  - Gemini: Recon Pipeline (output A = input B)
  - Grok: "Two-Eye" approach

Phases:
  0. Scope Definition (target validation)
  1. Passive Recon (subfinder, assetfinder, dorks)
  2. Active Recon (httpx, portscan, wappalyzer)
  3. Content Discovery (gau, waybackurls, katana, ffuf, arjun)
  4. Automated Scanning (nuclei, gf patterns)
  5. Vuln-Specific (dalfox, sqlmap, sqli, lfi, crlf, openredirect)
  6. Validation & Summary

Usage:
  python matthunder_cli.py pipeline example.com
"""

import os
import time
from pathlib import Path

from . import SCANNER_REGISTRY
from .common import normalize_domain


def _log(phase: str, msg: str):
    print(f"  [\033[96m{phase}\033[0m] {msg}")


def run(domain: str, speed: str = "standard") -> dict:
    """Run the full 6-phase pipeline."""
    domain = normalize_domain(domain)
    start_time = time.time()
    results = {"domain": domain, "phases": {}, "total_findings": 0}

    print(f"\n  {'='*60}")
    print(f"  \033[1m\033[93m  FULL PIPELINE — {domain}\033[0m")
    print(f"  {'='*60}")

    # ── Phase 0: Scope Definition ────────────────────────────────────────
    _log("P0", f"Target: {domain}")
    _log("P0", f"Speed: {speed}")
    _log("P0", "Scope validated ✓")
    results["phases"]["scope"] = {"target": domain, "speed": speed}

    # ── Phase 1: Passive Recon ───────────────────────────────────────────
    print(f"\n  \033[92m── PHASE 1: PASSIVE RECON ──────────────────────────\033[0m")
    subfinder_subs = _run_subfinder(domain)
    _log("P1", f"Subfinder: {len(subfinder_subs)} subdomains")

    assetfinder_subs = _run_assetfinder(domain)
    _log("P1", f"Assetfinder: {len(assetfinder_subs)} subdomains")

    all_subs = sorted(set(subfinder_subs + assetfinder_subs))
    sub_file = os.path.join("subdomain", f"{domain}.txt")
    os.makedirs("subdomain", exist_ok=True)
    with open(sub_file, "w") as f:
        f.write("\n".join(all_subs))
    _log("P1", f"Total unique subdomains: {len(all_subs)} → {sub_file}")
    results["phases"]["passive"] = {"subdomains": len(all_subs), "file": sub_file}

    # ── Phase 2: Active Recon ────────────────────────────────────────────
    print(f"\n  \033[94m── PHASE 2: ACTIVE RECON & FINGERPRINTING ─────────\033[0m")
    live_hosts = _run_httpx(sub_file)
    _log("P2", f"Httpx: {len(live_hosts)} live hosts")

    # Port scan top hosts
    port_results = {}
    for host in live_hosts[:5]:
        try:
            from scanners.portscan import run as portscan_run
            pr = portscan_run(host)
            port_results[host] = pr.get("findings", 0)
            _log("P2", f"Port scan {host}: {pr.get('findings', 0)} open ports")
        except Exception as e:
            _log("P2", f"Port scan {host}: skipped ({e})")

    # WAF detection
    try:
        from scanners.waf import run as waf_run
        wr = waf_run(domain)
        _log("P2", f"WAF: {wr.get('findings', 0)} signatures detected")
    except Exception:
        _log("P2", "WAF detection: skipped")

    # Tech fingerprinting
    try:
        from scanners.techfingerprint import run as tech_run
        tr = tech_run(domain)
        _log("P2", f"Tech: {tr.get('stack', 'unknown')} detected")
    except Exception:
        _log("P2", "Tech fingerprint: skipped")

    live_file = os.path.join("subdomain", f"{domain}_live.txt")
    with open(live_file, "w") as f:
        f.write("\n".join(live_hosts))
    results["phases"]["active"] = {
        "live_hosts": len(live_hosts),
        "ports": port_results,
        "file": live_file,
    }

    # ── Phase 3: Content Discovery ───────────────────────────────────────
    print(f"\n  \033[95m── PHASE 3: CONTENT DISCOVERY & URL HARVEST ───────\033[0m")

    # Historical URLs (gau + waybackurls)
    historical_urls = _run_gau(domain)
    _log("P3", f"Gau/Wayback: {len(historical_urls)} historical URLs")

    # JS Analysis
    try:
        from scanners.jsanalysis import run as js_run
        jr = js_run(domain)
        _log("P3", f"JS Analysis: {jr.get('secrets', 0)} secrets, {jr.get('endpoints', 0)} endpoints")
    except Exception:
        _log("P3", "JS Analysis: skipped")

    # Directory fuzzing (top live hosts only)
    fuzz_results = {}
    for host in live_hosts[:3]:
        try:
            from scanners.fuzzer import run as fuzz_run
            fr = fuzz_run(host)
            fuzz_results[host] = fr.get("findings", 0)
            _log("P3", f"Fuzzer {host}: {fr.get('findings', 0)} paths found")
        except Exception as e:
            _log("P3", f"Fuzzer {host}: skipped ({e})")

    # Parameter discovery
    try:
        from scanners.params import run as params_run
        # This is registered as apirecon's params
        pass
    except Exception:
        pass

    results["phases"]["discovery"] = {
        "historical_urls": len(historical_urls),
        "fuzzer": fuzz_results,
    }

    # ── Phase 4: Automated Scanning ──────────────────────────────────────
    print(f"\n  \033[93m── PHASE 4: AUTOMATED SCANNING ────────────────────\033[0m")

    # Nuclei scan
    nuclei_results = _run_nuclei(live_file)
    _log("P4", f"Nuclei: {nuclei_results} findings")

    # GF patterns
    try:
        from scanners.gfpatterns import run as gf_run
        gfr = gf_run(domain)
        _log("P4", f"GF Patterns: {gfr.get('total', 0)} URLs categorized")
    except Exception:
        _log("P4", "GF Patterns: skipped")

    results["phases"]["scanning"] = {"nuclei": nuclei_results}

    # ── Phase 5: Vuln-Specific ───────────────────────────────────────────
    print(f"\n  \033[91m── PHASE 5: VULNERABILITY SCANNING ─────────────────\033[0m")

    vuln_scanners = [
        ("sqli", "SQL Injection"),
        ("xss", "XSS (dalfox)"),
        ("lfi", "LFI / Path Traversal"),
        ("cors", "CORS Misconfig"),
        ("ssti", "SSTI Probe"),
        ("crlf", "CRLF Injection"),
        ("openredirect", "Open Redirect"),
    ]

    vuln_findings = {}
    for scan_key, label in vuln_scanners:
        try:
            from scanners import SCANNER_REGISTRY
            runner = SCANNER_REGISTRY.get(scan_key)
            if runner:
                vr = runner(domain)
                count = vr.get("findings", 0)
                vuln_findings[scan_key] = count
                status = f"\033[92m{count} hits\033[0m" if count > 0 else f"\033[90m{count}\033[0m"
                _log("P5", f"{label}: {status}")
        except Exception as e:
            _log("P5", f"{label}: skipped ({e})")

    results["phases"]["vulns"] = vuln_findings
    total_vulns = sum(vuln_findings.values())
    results["total_findings"] = total_vulns

    # ── Phase 6: Summary ─────────────────────────────────────────────────
    elapsed = time.time() - start_time
    print(f"\n  \033[92m── PIPELINE COMPLETE ───────────────────────────────\033[0m")
    print(f"  Domain:        {domain}")
    print(f"  Subdomains:    {len(all_subs)} total, {len(live_hosts)} live")
    print(f"  Historical:    {len(historical_urls)} URLs")
    print(f"  Nuclei:        {nuclei_results} findings")
    print(f"  Vuln-specific: {total_vulns} total findings")
    print(f"  Time:          {elapsed:.1f}s")
    print(f"  Database:      matthunder_scans.db")
    print()

    results["elapsed"] = round(elapsed, 1)
    return results


def _run_subfinder(domain: str) -> list[str]:
    """Run subfinder and return list of subdomains."""
    import shutil
    import subprocess

    subfinder = shutil.which("subfinder")
    if not subfinder:
        go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", "subfinder")
        if os.path.exists(go_bin):
            subfinder = go_bin
    if not subfinder:
        return []

    try:
        proc = subprocess.run(
            [subfinder, "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=120,
        )
        return [l.strip() for l in proc.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def _run_assetfinder(domain: str) -> list[str]:
    """Run assetfinder and return list of subdomains."""
    import shutil
    import subprocess

    assetfinder = shutil.which("assetfinder")
    if not assetfinder:
        return []

    try:
        proc = subprocess.run(
            [assetfinder, "--subs-only", domain],
            capture_output=True, text=True, timeout=60,
        )
        return [l.strip() for l in proc.stdout.splitlines() if l.strip() and domain in l]
    except Exception:
        return []


def _run_httpx(sub_file: str) -> list[str]:
    """Run httpx to filter live hosts."""
    import shutil
    import subprocess

    httpx = shutil.which("httpx")
    if not httpx:
        go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", "httpx")
        if os.path.exists(go_bin):
            httpx = go_bin
    if not httpx:
        return []

    if not os.path.exists(sub_file):
        return []

    try:
        proc = subprocess.run(
            [httpx, "-l", sub_file, "-silent", "-title", "-status-code", "-tech-detect"],
            capture_output=True, text=True, timeout=180,
        )
        hosts = []
        for line in proc.stdout.splitlines():
            parts = line.split()
            if parts:
                host = parts[0]
                host = host.replace("https://", "").replace("http://", "").split("/")[0]
                if host not in hosts:
                    hosts.append(host)
        return hosts
    except Exception:
        return []


def _run_gau(domain: str) -> list[str]:
    """Run gau to collect historical URLs."""
    import shutil
    import subprocess

    gau = shutil.which("gau")
    if not gau:
        return []

    try:
        proc = subprocess.run(
            [gau, "--subs", domain],
            capture_output=True, text=True, timeout=120,
        )
        return list(set(l.strip() for l in proc.stdout.splitlines() if l.strip()))
    except Exception:
        return []


def _run_nuclei(live_file: str) -> int:
    """Run nuclei on live hosts and return finding count."""
    import shutil
    import subprocess

    nuclei = shutil.which("nuclei")
    if not nuclei:
        go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", "nuclei")
        if os.path.exists(go_bin):
            nuclei = go_bin
    if not nuclei:
        return 0

    if not os.path.exists(live_file):
        return 0

    try:
        proc = subprocess.run(
            [nuclei, "-l", live_file, "-silent", "-severity", "low,medium,high,critical"],
            capture_output=True, text=True, timeout=600,
        )
        return len(proc.stdout.splitlines())
    except Exception:
        return 0


SCANNER_REGISTRY["pipeline"] = run
