"""
pipeline - Full 6-phase automated recon→hunt→validate→report pipeline.

Inspired by 5 AI providers + Claude-BugHunter + claude-bug-bounty.

Phases:
  0. Scope Definition
  1. Passive Recon (subfinder)
  2. Active Recon (httpx, portscan, waf, tech fingerprint)
  3. Content Discovery (gau, jsanalysis, fuzzer)
  4. Automated Scanning (nuclei, gf patterns)
  5. Vuln-Specific (sqli, xss, lfi, cors, ssti, crlf, openredirect)
  6. Summary

Usage:
  python matthunder_cli.py pipeline example.com
"""

import os
import shutil
import subprocess
import time

from . import SCANNER_REGISTRY
from .common import normalize_domain

# ANSI colors
G = "\033[92m"  # green
Y = "\033[93m"  # yellow
R = "\033[91m"  # red
C = "\033[96m"  # cyan
D = "\033[90m"  # dim
BD = "\033[1m"  # bold
RST = "\033[0m" # reset


def _log(phase: str, msg: str, color: str = C):
    print(f"  {color}[{phase}]{RST} {msg}")


def _find_bin(name: str):
    """Find a binary in PATH or Go bin."""
    found = shutil.which(name)
    if found:
        return found
    go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", name + (".exe" if os.name == "nt" else ""))
    if os.path.exists(go_bin):
        return go_bin
    return None


def _run_cmd(cmd: list, timeout: int = 120, label: str = "") -> tuple:
    """Run a command and return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        _log("!", f"{label}: timed out ({timeout}s)", Y)
        return "", "timeout", -1
    except FileNotFoundError:
        _log("!", f"{label}: binary not found", R)
        return "", "not found", -1
    except Exception as e:
        _log("!", f"{label}: {e}", R)
        return "", str(e), -1


# ─── Phase 1: Passive Recon ─────────────────────────────────────────────────

def _phase1_subfinder(domain: str) -> list[str]:
    """Run subfinder for passive subdomain enumeration."""
    subfinder = _find_bin("subfinder")
    if not subfinder:
        _log("P1", "subfinder not found — run setup.bat", R)
        return []

    _log("P1", f"Running subfinder on {domain}...")
    stdout, stderr, rc = _run_cmd(
        [subfinder, "-d", domain, "-silent", "-all"],
        timeout=180, label="subfinder",
    )
    subs = list(set(l.strip() for l in stdout.splitlines() if l.strip() and "." in l))
    _log("P1", f"Subfinder: {len(subs)} subdomains", G if subs else Y)
    return subs


# ─── Phase 2: Active Recon ──────────────────────────────────────────────────

def _phase2_httpx(subs: list[str], domain: str) -> list[str]:
    """Probe subdomains for live hosts using httpx."""
    httpx = _find_bin("httpx")
    if not httpx:
        _log("P2", "httpx not found — run setup.bat", R)
        return []

    # Write subs to temp file
    tmp_in = f"_matthunder_pipe_subs_{domain}.txt"
    tmp_out = f"_matthunder_pipe_live_{domain}.txt"
    with open(tmp_in, "w") as f:
        f.write("\n".join(subs))

    # Limit to 500 subs for speed
    if len(subs) > 500:
        _log("P2", f"Limiting to 500/{len(subs)} subdomains for speed", Y)

    _log("P2", f"Probing {min(len(subs), 500)} subdomains with httpx...")

    # Run httpx — simpler flags for reliable parsing
    stdout, stderr, rc = _run_cmd(
        [httpx, "-l", tmp_in, "-silent", "-status-code", "-title", "-o", tmp_out,
         "-threads", "50", "-timeout", "10", "-retries", "1"],
        timeout=300, label="httpx",
    )

    # Parse live hosts from output file
    live_hosts = []
    if os.path.exists(tmp_out):
        with open(tmp_out, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # httpx output format: https://host [status] [title] ...
                # or just: https://host (if -silent)
                host = line.split()[0] if line.split() else line
                host = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                if host and host not in live_hosts:
                    live_hosts.append(host)

    # Fallback: if httpx returned 0, try probing root domain directly
    if not live_hosts:
        _log("P2", "httpx returned 0 — trying direct probe of root domain...", Y)
        stdout2, _, _ = _run_cmd(
            [httpx, "-u", domain, "-silent", "-status-code"],
            timeout=30, label="httpx-fallback",
        )
        if stdout2.strip():
            host = stdout2.strip().split()[0].replace("https://", "").replace("http://", "").split("/")[0]
            if host:
                live_hosts.append(host)
                _log("P2", f"Fallback found: {host}", G)

    # Second fallback: try common subdomains manually
    if not live_hosts:
        _log("P2", "Trying common subdomains manually...", Y)
        common_subs = [f"{prefix}.{domain}" for prefix in ["www", "api", "mail", "webmail", "portal", "app", "admin", "dev", "staging", "test", "beta", "cdn", "static", "media", "blog", "docs", "support", "status", "login", "sso", "auth"]]
        tmp_common = f"_matthunder_pipe_common_{domain}.txt"
        with open(tmp_common, "w") as f:
            f.write("\n".join(common_subs))
        stdout3, _, _ = _run_cmd(
            [httpx, "-l", tmp_common, "-silent", "-status-code", "-o", tmp_out + ".common"],
            timeout=60, label="httpx-common",
        )
        if os.path.exists(tmp_out + ".common"):
            with open(tmp_out + ".common", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    host = line.strip().split()[0] if line.strip().split() else ""
                    host = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                    if host and host not in live_hosts:
                        live_hosts.append(host)
            os.remove(tmp_out + ".common")
        try:
            os.remove(tmp_common)
        except OSError:
            pass

    # Cleanup
    for p in [tmp_in, tmp_out]:
        try:
            os.remove(p)
        except OSError:
            pass

    _log("P2", f"Live hosts: {len(live_hosts)}", G if live_hosts else R)
    return live_hosts


def _phase2_portscan(hosts: list[str]) -> dict:
    """Quick port scan on top hosts."""
    results = {}
    for host in hosts[:3]:  # Only top 3 for speed
        try:
            from scanners.portscan import run as portscan_run
            pr = portscan_run(host)
            count = pr.get("findings", 0)
            if count > 0:
                results[host] = count
                _log("P2", f"Ports {host}: {count} open", G)
        except Exception:
            pass
    return results


def _phase2_waf(domain: str) -> str:
    """Detect WAF."""
    try:
        from scanners.waf import run as waf_run
        wr = waf_run(domain)
        wafs = wr.get("findings", 0)
        if wafs > 0:
            _log("P2", f"WAF detected: {wafs} signatures", Y)
            return "detected"
    except Exception:
        pass
    return "none"


def _phase2_tech(domain: str) -> str:
    """Detect tech stack."""
    try:
        from scanners.techfingerprint import run as tech_run
        tr = tech_run(domain)
        stack = tr.get("stack", "unknown")
        if stack != "unknown":
            _log("P2", f"Tech stack: {stack}", G)
        return stack
    except Exception:
        pass
    return "unknown"


# ─── Phase 3: Content Discovery ─────────────────────────────────────────────

def _phase3_gau(domain: str) -> list[str]:
    """Collect historical URLs from gau/waybackurls."""
    urls = set()

    # Try gau
    gau = _find_bin("gau")
    if gau:
        _log("P3", "Running gau for historical URLs...")
        stdout, _, _ = _run_cmd([gau, "--subs", domain], timeout=120, label="gau")
        for line in stdout.splitlines():
            url = line.strip()
            if url and url.startswith("http"):
                urls.add(url)

    # Try waybackurls as fallback
    wayback = _find_bin("waybackurls")
    if wayback and not urls:
        _log("P3", "Running waybackurls...")
        stdout, _, _ = _run_cmd([wayback, domain], timeout=60, label="waybackurls")
        for line in stdout.splitlines():
            url = line.strip()
            if url and url.startswith("http"):
                urls.add(url)

    url_list = list(urls)
    _log("P3", f"Historical URLs: {len(url_list)}", G if url_list else Y)
    return url_list


def _phase3_jsanalysis(domain: str) -> dict:
    """Analyze JavaScript files for secrets and endpoints."""
    try:
        from scanners.jsanalysis import run as js_run
        jr = js_run(domain)
        secrets = jr.get("secrets", 0)
        endpoints = jr.get("endpoints", 0)
        _log("P3", f"JS Analysis: {secrets} secrets, {endpoints} endpoints", G if secrets or endpoints else D)
        return jr
    except Exception as e:
        _log("P3", f"JS Analysis: skipped ({e})", Y)
        return {}


def _phase3_fuzz(hosts: list[str]) -> dict:
    """Directory fuzzing on top live hosts."""
    results = {}
    for host in hosts[:2]:  # Only top 2 for speed
        try:
            from scanners.fuzzer import run as fuzz_run
            fr = fuzz_run(host)
            count = fr.get("findings", 0)
            if count > 0:
                results[host] = count
                _log("P3", f"Fuzzer {host}: {count} paths", G)
        except Exception:
            pass
    return results


# ─── Phase 4: Automated Scanning ────────────────────────────────────────────

def _phase4_nuclei(live_hosts: list[str]) -> int:
    """Run nuclei on live hosts."""
    nuclei = _find_bin("nuclei")
    if not nuclei:
        _log("P4", "nuclei not found — run setup.bat", R)
        return 0

    if not live_hosts:
        _log("P4", "No live hosts to scan", Y)
        return 0

    # Write live hosts to file
    tmp = f"_matthunder_pipe_nuclei_{int(time.time())}.txt"
    with open(tmp, "w") as f:
        f.write("\n".join(live_hosts[:50]))  # Limit for speed

    _log("P4", f"Running nuclei on {min(len(live_hosts), 50)} hosts...")
    stdout, stderr, rc = _run_cmd(
        [nuclei, "-l", tmp, "-silent", "-severity", "low,medium,high,critical",
         "-rate-limit", "50", "-timeout", "10"],
        timeout=600, label="nuclei",
    )

    findings = len([l for l in stdout.splitlines() if l.strip()])
    try:
        os.remove(tmp)
    except OSError:
        pass

    _log("P4", f"Nuclei: {findings} findings", G if findings else D)
    return findings


def _phase4_gf(domain: str, urls: list[str]) -> dict:
    """Apply GF patterns to filter URLs by vuln type."""
    try:
        from scanners.gfpatterns import run as gf_run
        gfr = gf_run(domain)
        total = gfr.get("total", 0)
        categorized = gfr.get("categorized", {})
        if total > 0:
            cats = ", ".join(f"{k}:{v}" for k, v in sorted(categorized.items(), key=lambda x: -x[1]))
            _log("P4", f"GF Patterns: {total} URLs → {cats}", G)
        else:
            _log("P4", "GF Patterns: 0 matches", D)
        return gfr
    except Exception as e:
        _log("P4", f"GF Patterns: skipped ({e})", Y)
        return {}


# ─── Phase 5: Vuln-Specific Scanning ────────────────────────────────────────

def _phase5_vulns(domain: str) -> dict:
    """Run vulnerability-specific scanners."""
    vuln_scanners = [
        ("sqli", "SQL Injection"),
        ("xss", "XSS (dalfox)"),
        ("lfi", "LFI / Path Traversal"),
        ("cors", "CORS Misconfig"),
        ("ssti", "SSTI Probe"),
        ("crlf", "CRLF Injection"),
        ("openredirect", "Open Redirect"),
    ]

    findings = {}
    from scanners import SCANNER_REGISTRY

    for scan_key, label in vuln_scanners:
        runner = SCANNER_REGISTRY.get(scan_key)
        if not runner:
            continue
        try:
            vr = runner(domain)
            count = vr.get("findings", 0)
            findings[scan_key] = count
            if count > 0:
                _log("P5", f"{label}: {count} hits!", G)
            else:
                _log("P5", f"{label}: 0", D)
        except Exception as e:
            _log("P5", f"{label}: error ({e})", Y)
            findings[scan_key] = 0

    return findings


# ─── Main Pipeline ──────────────────────────────────────────────────────────

def run(domain: str, speed: str = "standard") -> dict:
    """Run the full 6-phase pipeline."""
    domain = normalize_domain(domain)
    start_time = time.time()
    results = {"domain": domain, "phases": {}, "total_findings": 0}

    print(f"\n  {'='*60}")
    print(f"  {BD}{Y}  FULL PIPELINE — {domain}{RST}")
    print(f"  {D}Speed: {speed} | Started: {time.strftime('%H:%M:%S')}{RST}")
    print(f"  {'='*60}")

    # ── Phase 0: Scope ────────────────────────────────────────────────────
    _log("P0", f"Target: {domain} ✓", G)
    os.makedirs("subdomain", exist_ok=True)
    os.makedirs("results", exist_ok=True)

    # ── Phase 1: Passive Recon ────────────────────────────────────────────
    print(f"\n  {G}── PHASE 1: PASSIVE RECON ──────────────────────────{RST}")
    subs = _phase1_subfinder(domain)

    if not subs:
        _log("P1", "No subdomains found — using root domain only", Y)
        subs = [domain]

    # Save subdomains
    sub_file = os.path.join("subdomain", f"{domain}.txt")
    with open(sub_file, "w") as f:
        f.write("\n".join(subs))
    _log("P1", f"Saved: {sub_file} ({len(subs)} subdomains)", D)

    results["phases"]["passive"] = {"subdomains": len(subs), "file": sub_file}

    # ── Phase 2: Active Recon ─────────────────────────────────────────────
    print(f"\n  {C}── PHASE 2: ACTIVE RECON & FINGERPRINTING ─────────{RST}")

    live_hosts = _phase2_httpx(subs, domain)

    # Save live hosts
    live_file = os.path.join("subdomain", f"{domain}_live.txt")
    with open(live_file, "w") as f:
        f.write("\n".join(live_hosts))

    port_results = _phase2_portscan(live_hosts)
    waf_status = _phase2_waf(domain)
    tech_stack = _phase2_tech(domain)

    results["phases"]["active"] = {
        "live_hosts": len(live_hosts),
        "ports": port_results,
        "waf": waf_status,
        "tech": tech_stack,
        "file": live_file,
    }

    # ── Phase 3: Content Discovery ────────────────────────────────────────
    print(f"\n  {Y}── PHASE 3: CONTENT DISCOVERY & URL HARVEST ───────{RST}")

    historical_urls = _phase3_gau(domain)
    js_results = _phase3_jsanalysis(domain)
    fuzz_results = _phase3_fuzz(live_hosts)

    # Merge all URLs for GF patterns
    all_urls = list(set(historical_urls + live_hosts))

    results["phases"]["discovery"] = {
        "historical_urls": len(historical_urls),
        "js_secrets": js_results.get("secrets", 0),
        "js_endpoints": js_results.get("endpoints", 0),
        "fuzzer": fuzz_results,
    }

    # ── Phase 4: Automated Scanning ───────────────────────────────────────
    print(f"\n  {Y}── PHASE 4: AUTOMATED SCANNING ────────────────────{RST}")

    nuclei_count = _phase4_nuclei(live_hosts)
    gf_results = _phase4_gf(domain, all_urls)

    results["phases"]["scanning"] = {
        "nuclei": nuclei_count,
        "gf_patterns": gf_results.get("total", 0),
    }

    # ── Phase 5: Vuln-Specific ────────────────────────────────────────────
    print(f"\n  {R}── PHASE 5: VULNERABILITY SCANNING ─────────────────{RST}")

    vuln_findings = _phase5_vulns(domain)
    total_vulns = sum(vuln_findings.values())

    results["phases"]["vulns"] = vuln_findings
    results["total_findings"] = total_vulns + nuclei_count

    # ── Phase 6: Summary ──────────────────────────────────────────────────
    elapsed = time.time() - start_time
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)

    print(f"\n  {G}── PIPELINE COMPLETE ───────────────────────────────{RST}")
    print(f"  Domain:        {BD}{domain}{RST}")
    print(f"  Subdomains:    {BD}{len(subs)}{RST} total → {BD}{len(live_hosts)}{RST} live")
    print(f"  Historical:    {BD}{len(historical_urls)}{RST} URLs")
    print(f"  JS Analysis:   {BD}{js_results.get('secrets', 0)}{RST} secrets, {BD}{js_results.get('endpoints', 0)}{RST} endpoints")
    print(f"  Nuclei:        {BD}{nuclei_count}{RST} findings")
    print(f"  Vuln-specific: {BD}{total_vulns}{RST} findings")
    print(f"  Total:         {BD}{results['total_findings']}{RST} findings")
    print(f"  Time:          {mins}m {secs}s")
    print(f"  Database:      matthunder_scans.db")
    print()

    results["elapsed"] = round(elapsed, 1)
    return results


SCANNER_REGISTRY["pipeline"] = run
