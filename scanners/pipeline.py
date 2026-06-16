"""
pipeline - Full automated recon→hunt→validate→report pipeline.

Runs ALL available scanners in the correct order.

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
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
C = "\033[96m"
M = "\033[95m"
D = "\033[90m"
BD = "\033[1m"
RST = "\033[0m"


def _log(phase, msg, color=C):
    print(f"  {color}[{phase}]{RST} {msg}")


def _find_bin(name):
    """Find binary — prioritize Go bin over Python pip scripts."""
    ext = ".exe" if os.name == "nt" else ""
    # 1. Check Go bin first (most security tools live here)
    go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", name + ext)
    if os.path.exists(go_bin):
        return go_bin
    # 2. Check PATH but skip Python Scripts dir (httpx pip != httpx Go)
    found = shutil.which(name)
    if found:
        if "Python" in found and "Scripts" in found:
            return None  # This is a pip package, not the security tool
        return found
    return None


def _run_cmd(cmd, timeout=120, label=""):
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired:
        _log("!", f"{label}: timed out ({timeout}s)", Y)
        return "", "timeout", -1
    except FileNotFoundError:
        _log("!", f"{label}: binary not found", R)
        return "", "not found", -1
    except Exception as e:
        _log("!", f"{label}: {e}", R)
        return "", str(e), -1


def _run_scanner(scan_key, domain, label):
    """Run a scanner from the registry."""
    from scanners import SCANNER_REGISTRY
    runner = SCANNER_REGISTRY.get(scan_key)
    if not runner:
        _log("!", f"{label}: not registered", D)
        return {}
    try:
        import inspect
        sig = inspect.signature(runner)
        params = list(sig.parameters.keys())
        # Call with just domain if it accepts it
        if len(params) == 1:
            result = runner(domain)
        elif len(params) == 2 and params[1] in ("platforms", "services", "categories"):
            result = runner(domain, [])
        else:
            result = runner(domain)
        return result if isinstance(result, dict) else {}
    except Exception as e:
        _log("!", f"{label}: {e}", Y)
        return {}


# ─── Phase 1: Passive Recon ─────────────────────────────────────────────────

def phase1(domain):
    print(f"\n  {G}{'='*55}{RST}")
    print(f"  {G}{BD}PHASE 1: PASSIVE RECON{RST}")
    print(f"  {G}{'='*55}{RST}")

    subfinder = _find_bin("subfinder")
    if not subfinder:
        _log("P1", "subfinder not found — run setup.bat", R)
        return [domain]

    _log("P1", f"subfinder -d {domain} -all")
    stdout, stderr, rc = _run_cmd(
        [subfinder, "-d", domain, "-silent", "-all"],
        timeout=180, label="subfinder",
    )
    subs = list(set(l.strip() for l in stdout.splitlines() if l.strip() and "." in l))
    _log("P1", f"Found {len(subs)} subdomains", G if subs else Y)

    if not subs:
        subs = [domain]
        _log("P1", "Using root domain as fallback", Y)

    sub_file = os.path.join("subdomain", f"{domain}.txt")
    os.makedirs("subdomain", exist_ok=True)
    with open(sub_file, "w") as f:
        f.write("\n".join(subs))
    _log("P1", f"Saved → {sub_file}", D)

    return subs


# ─── Phase 2: Active Recon ──────────────────────────────────────────────────

def phase2(domain, subs):
    print(f"\n  {C}{'='*55}{RST}")
    print(f"  {C}{BD}PHASE 2: ACTIVE RECON & FINGERPRINTING{RST}")
    print(f"  {C}{'='*55}{RST}")

    live_hosts = _probe_httpx(subs, domain)

    # Port scan (top 3)
    if live_hosts:
        _log("P2", "Port scan on top hosts...")
        _run_scanner("portscan", live_hosts[0], "portscan")
    else:
        _log("P2", "Port scan: no live hosts, scanning root domain...")
        _run_scanner("portscan", domain, "portscan")

    # WAF detection
    _log("P2", "WAF detection...")
    _run_scanner("waf", domain, "waf")

    # Tech fingerprint
    _log("P2", "Tech fingerprint...")
    _run_scanner("tech", domain, "tech")

    return live_hosts


def _probe_httpx(subs, domain):
    httpx = _find_bin("httpx")
    if not httpx:
        _log("P2", "httpx not found — run setup.bat", R)
        return [domain]

    tmp_in = f"_mt_pipe_{domain}_subs.txt"
    tmp_out = f"_mt_pipe_{domain}_live.txt"
    with open(tmp_in, "w") as f:
        f.write("\n".join(subs[:500]))

    _log("P2", f"httpx probing {min(len(subs), 500)} subdomains...")

    # Run httpx with simple flags first
    stdout, stderr, rc = _run_cmd(
        [httpx, "-l", tmp_in, "-silent", "-o", tmp_out,
         "-threads", "50", "-timeout", "10", "-retries", "1"],
        timeout=300, label="httpx",
    )

    # Parse from output file
    live = []
    if os.path.exists(tmp_out):
        with open(tmp_out, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # httpx -silent outputs just URLs like: https://host
                host = line.split()[0] if line.split() else line
                host = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                if host and host not in live:
                    live.append(host)

    # If file is empty, try parsing stdout
    if not live and stdout.strip():
        _log("P2", f"Parsing httpx stdout ({len(stdout.splitlines())} lines)...", D)
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            host = line.split()[0] if line.split() else line
            host = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if host and host not in live:
                live.append(host)

    # Fallback 1: probe root domain directly
    if not live:
        _log("P2", "httpx batch returned 0 — probing root domain directly...", Y)
        stdout2, stderr2, rc2 = _run_cmd(
            [httpx, "-u", f"https://{domain}", "-silent", "-status-code"],
            timeout=30, label="httpx-https",
        )
        if stdout2.strip():
            host = stdout2.strip().split()[0].replace("https://", "").replace("http://", "").split("/")[0]
            if host:
                live.append(host)
                _log("P2", f"Found via HTTPS: {host}", G)

        if not live:
            stdout3, stderr3, rc3 = _run_cmd(
                [httpx, "-u", f"http://{domain}", "-silent", "-status-code"],
                timeout=30, label="httpx-http",
            )
            if stdout3.strip():
                host = stdout3.strip().split()[0].replace("https://", "").replace("http://", "").split("/")[0]
                if host:
                    live.append(host)
                    _log("P2", f"Found via HTTP: {host}", G)

    # Fallback 2: try common subdomains
    if not live:
        _log("P2", "Probing common subdomains...", Y)
        common = [f"{p}.{domain}" for p in ["www", "api", "mail", "portal", "app", "admin", "dev", "staging", "blog", "cdn", "static", "login", "sso"]]
        tmp_c = f"_mt_pipe_{domain}_common.txt"
        with open(tmp_c, "w") as f:
            f.write("\n".join(common))
        stdout4, _, _ = _run_cmd(
            [httpx, "-l", tmp_c, "-silent", "-o", tmp_out + ".c"],
            timeout=60, label="httpx-common",
        )
        if os.path.exists(tmp_out + ".c"):
            with open(tmp_out + ".c") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    host = line.split()[0].replace("https://", "").replace("http://", "").split("/")[0]
                    if host and host not in live:
                        live.append(host)
                        _log("P2", f"Found: {host}", G)
            os.remove(tmp_out + ".c")
        try:
            os.remove(tmp_c)
        except OSError:
            pass

    # Fallback 3: if still nothing, use root domain
    if not live:
        _log("P2", "No live hosts found — using root domain as fallback", Y)
        live = [domain]

    # Cleanup
    for p in [tmp_in, tmp_out]:
        try:
            os.remove(p)
        except OSError:
            pass

    # Save live hosts
    live_file = os.path.join("subdomain", f"{domain}_live.txt")
    with open(live_file, "w") as f:
        f.write("\n".join(live))

    _log("P2", f"Live hosts: {len(live)}", G if live and live != [domain] else Y)
    return live


# ─── Phase 3: Content Discovery ─────────────────────────────────────────────

def phase3(domain, live_hosts):
    print(f"\n  {M}{'='*55}{RST}")
    print(f"  {M}{BD}PHASE 3: CONTENT DISCOVERY{RST}")
    print(f"  {M}{'='*55}{RST}")

    # Historical URLs
    _log("P3", "Historical URL harvest (gau/waybackurls)...")
    gau = _find_bin("gau")
    urls = set()
    if gau:
        stdout, stderr, rc = _run_cmd([gau, "--subs", domain], timeout=300, label="gau")
        if rc == 0:
            urls = set(l.strip() for l in stdout.splitlines() if l.strip().startswith("http"))
        else:
            _log("P3", f"gau failed (rc={rc}), trying without --subs...", Y)
            stdout2, _, _ = _run_cmd([gau, domain], timeout=120, label="gau-simple")
            urls = set(l.strip() for l in stdout2.splitlines() if l.strip().startswith("http"))
    if not urls:
        wayback = _find_bin("waybackurls")
        if wayback:
            _log("P3", "Trying waybackurls...")
            stdout, _, _ = _run_cmd([wayback, domain], timeout=120, label="waybackurls")
            urls = set(l.strip() for l in stdout.splitlines() if l.strip().startswith("http"))
    _log("P3", f"Historical URLs: {len(urls)}", G if urls else Y)

    # JS Analysis
    _log("P3", "JavaScript analysis...")
    _run_scanner("jsanalysis", domain, "jsanalysis")

    # Directory fuzzing (top 2 live hosts)
    if live_hosts and live_hosts != [domain]:
        _log("P3", "Directory fuzzing...")
        for host in live_hosts[:2]:
            _run_scanner("fuzzer", host, f"fuzzer:{host}")

    # API endpoint recon
    _log("P3", "API endpoint recon...")
    _run_scanner("apirecon", domain, "apirecon")

    # Hidden parameter discovery
    _log("P3", "Hidden parameter discovery...")
    _run_scanner("params", domain, "params")

    return list(urls)


# ─── Phase 4: Automated Scanning ────────────────────────────────────────────

def phase4(domain, live_hosts, urls):
    print(f"\n  {Y}{'='*55}{RST}")
    print(f"  {Y}{BD}PHASE 4: AUTOMATED SCANNING{RST}")
    print(f"  {Y}{'='*55}{RST}")

    # Nuclei
    _log("P4", "Nuclei CVE/misconfig scan...")
    nuclei = _find_bin("nuclei")
    nuclei_count = 0
    if nuclei and live_hosts:
        # Use live hosts or root domain
        targets = live_hosts[:50] if live_hosts != [domain] else [domain]
        tmp = f"_mt_pipe_{domain}_nuclei.txt"
        with open(tmp, "w") as f:
            f.write("\n".join(targets))
        stdout, stderr, rc = _run_cmd(
            [nuclei, "-l", tmp, "-silent", "-severity", "low,medium,high,critical",
             "-rate-limit", "50", "-timeout", "10"],
            timeout=600, label="nuclei",
        )
        if stdout.strip():
            nuclei_count = len([l for l in stdout.splitlines() if l.strip()])
        try:
            os.remove(tmp)
        except OSError:
            pass
    _log("P4", f"Nuclei: {nuclei_count} findings", G if nuclei_count else D)

    # GF Patterns
    _log("P4", "GF pattern filtering...")
    _run_scanner("gf", domain, "gfpatterns")

    return nuclei_count


# ─── Phase 5: Vuln Scanning ─────────────────────────────────────────────────

def phase5(domain):
    print(f"\n  {R}{'='*55}{RST}")
    print(f"  {R}{BD}PHASE 5: VULNERABILITY SCANNING{RST}")
    print(f"  {R}{'='*55}{RST}")

    vulns = [
        ("sqli",         "SQL Injection"),
        ("xss",          "XSS (dalfox)"),
        ("lfi",          "LFI / Path Traversal"),
        ("cors",         "CORS Misconfig"),
        ("ssti",         "SSTI Probe"),
        ("crlf",         "CRLF Injection"),
        ("openredirect", "Open Redirect"),
    ]

    total = 0
    for key, label in vulns:
        _log("P5", f"{label}...")
        result = _run_scanner(key, domain, label)
        count = result.get("findings", 0)
        total += count
        if count > 0:
            _log("P5", f"{label}: {count} hits!", G)
        else:
            _log("P5", f"{label}: 0", D)

    return total


# ─── Phase 6: Intel & Discovery ─────────────────────────────────────────────

def phase6(domain):
    print(f"\n  {C}{'='*55}{RST}")
    print(f"  {C}{BD}PHASE 6: INTEL & DISCOVERY{RST}")
    print(f"  {C}{'='*55}{RST}")

    # Broken Link Hunter
    _log("P6", "Broken Link Hunter...")
    _run_scanner("blh", domain, "blh")

    # 3rd Party Assets
    _log("P6", "3rd Party Asset Links...")
    _run_scanner("tpa", domain, "tpa")

    # Credential URLs
    _log("P6", "Credential/Config URLs...")
    _run_scanner("cred", domain, "cred")

    # Sensitive Data
    _log("P6", "Sensitive data scan...")
    try:
        from matthunder import find_sensitive_data
        find_sensitive_data(domain)
        _log("P6", "Sensitive data scan complete", G)
    except Exception as e:
        _log("P6", f"Sensitive data: {e}", Y)


# ─── Main Pipeline ──────────────────────────────────────────────────────────

def run(domain, speed="standard"):
    domain = normalize_domain(domain)
    start = time.time()
    os.makedirs("subdomain", exist_ok=True)
    os.makedirs("results", exist_ok=True)

    total_scanners = 0
    total_findings = 0

    print(f"\n  {'='*55}")
    print(f"  {BD}{Y}  FULL PIPELINE — {domain}{RST}")
    print(f"  {D}Speed: {speed} | Started: {time.strftime('%H:%M:%S')}{RST}")
    print(f"  {D}Running ALL scanners in sequence...{RST}")
    print(f"  {'='*55}")

    # Phase 1
    subs = phase1(domain)
    total_scanners += 1

    # Phase 2
    live_hosts = phase2(domain, subs)
    total_scanners += 4

    # Phase 3
    urls = phase3(domain, live_hosts)
    total_scanners += 5

    # Phase 4
    nuclei_count = phase4(domain, live_hosts, urls)
    total_findings += nuclei_count
    total_scanners += 2

    # Phase 5
    vuln_count = phase5(domain)
    total_findings += vuln_count
    total_scanners += 7

    # Phase 6
    phase6(domain)
    total_scanners += 4

    # Summary
    elapsed = time.time() - start
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)

    print(f"\n  {G}{'='*55}{RST}")
    print(f"  {G}{BD}PIPELINE COMPLETE{RST}")
    print(f"  {G}{'='*55}{RST}")
    print(f"  Domain:          {BD}{domain}{RST}")
    print(f"  Subdomains:      {BD}{len(subs)}{RST} total → {BD}{len(live_hosts)}{RST} live")
    print(f"  Historical URLs: {BD}{len(urls)}{RST}")
    print(f"  Scanners run:    {BD}{total_scanners}{RST}")
    print(f"  Total findings:  {BD}{total_findings}{RST}")
    print(f"  Time:            {mins}m {secs}s")
    print(f"  Database:        matthunder_scans.db")
    print()

    return {
        "domain": domain,
        "subdomains": len(subs),
        "live_hosts": len(live_hosts),
        "historical_urls": len(urls),
        "scanners_run": total_scanners,
        "total_findings": total_findings,
        "elapsed": round(elapsed, 1),
    }


SCANNER_REGISTRY["pipeline"] = run
