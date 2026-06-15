"""
matthunder_cli.py
Interactive CLI entrypoint for matthunder with optional AI query parser (BYOK).

Usage:
  python matthunder_cli.py
  python matthunder_cli.py deep example.com standard
  python matthunder_cli.py -i          # interactive menu
  python matthunder_cli.py --ai "deep scan example.com fast"
  python matthunder_cli.py --update
  python matthunder_cli.py --telegram  # also fire Telegram bot
"""

import argparse
import os
import sys
import sqlite3
import time
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import matthunder as core
from matthunder import (
    print_logo,
    light_scan_target,
    dark_deep_target,
    takeover_mass_file,
    takeover_single,
    find_sensitive_data,
    check_previous_scan,
    ask_continue_or_restart,
    feature_update_tool,
)

DB_PATH = str(ROOT / "matthunder_scans.db")

SCAN_MAP = {
    "light": ("lts", light_scan_target, "target"),
    "dark": ("dks", dark_deep_target, "target"),
    "deep": ("dps", dark_deep_target, "target"),
    "takeover": ("tov", None, "list_or_target"),
    "sensitive": ("sens", find_sensitive_data, "target"),
    "blh": ("blh", None, "target"),
    "bac": ("tpa", None, "target"),
    "thirdparty": ("tpa", None, "target"),
    "tpa": ("tpa", None, "target"),
    "cred": ("cred", None, "target"),
}

SPEED_ALIAS = {"1": "low", "2": "standard", "3": "fast"}


# ─── Color helpers ───────────────────────────────────────────────────────────

class C:
    R = "\033[91m"   # red
    G = "\033[92m"   # green
    Y = "\033[93m"   # yellow
    B = "\033[94m"   # blue
    M = "\033[95m"   # magenta
    CY = "\033[96m"  # cyan
    D = "\033[90m"   # dim/gray
    BD = "\033[1m"   # bold
    RST = "\033[0m"  # reset


def _c(color: str, text: str) -> str:
    return f"{color}{text}{C.RST}"


# ─── Target helper ───────────────────────────────────────────────────────────

def _normalize_target(raw: str) -> str:
    t = (raw or "").strip().lower()
    for p in ("https://", "http://"):
        if t.startswith(p):
            t = t[len(p):]
    t = t.split("/")[0].split("?")[0].split("#")[0].rstrip(".")
    if t.startswith("www."):
        t = t[4:]
    return t


def _resolve_resume(target: str, auto_continue: bool, auto_restart: bool):
    if auto_continue:
        return "continue"
    if auto_restart:
        return "restart"
    scan_status = check_previous_scan(target)
    if not scan_status.get("has_any_files"):
        return None
    import config as _cfg
    mode = getattr(_cfg, "RESUME_SCAN_MODE", "ask")
    if mode == "continue":
        return "continue"
    if mode == "restart":
        return "restart"
    return ask_continue_or_restart(target, scan_status)


# ─── Scan history ────────────────────────────────────────────────────────────

def _get_scan_history(limit: int = 15) -> list[dict]:
    """Query matthunder_scans.db for recent scan records."""
    if not os.path.exists(DB_PATH):
        return []
    try:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT id, scanner, domain, status, total_sources, total_links, "
            "created_at, finished_at "
            "FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        con.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def show_scan_history():
    """Display recent scan history from the local database."""
    scans = _get_scan_history(20)
    print(f"\n{_c(C.BD, '  SCAN HISTORY')}  {_c(C.D, '(last 20 scans)')}")
    print(f"  {_c(C.D, 'Database:')} {DB_PATH}")
    print()

    if not scans:
        print(f"  {_c(C.D, 'No scans recorded yet.')}\n")
        return

    print(f"  {_c(C.D, 'NO')}  {'SCANNER':<14} {'DOMAIN':<30} {'STATUS':<12} {'HITS':<8} {'DATE'}")
    print(f"  {_c(C.D, '───')} {'──────────────':<14} {'──────────────────────────────':<30} {'────────────':<12} {'────────':<8} {'──────────────────'}")

    for i, s in enumerate(scans, 1):
        scanner = s.get("scanner", "?")
        domain = s.get("domain", "?")
        status = s.get("status", "?")
        total = s.get("total_links", 0) or 0
        created = (s.get("created_at", "") or "")[:16]

        status_color = C.G if status == "completed" else C.Y if status == "running" else C.R
        hit_str = str(total) if total else "-"

        print(f"  {C.D}{i:>2}{C.RST}  {scanner:<14} {domain:<30} {_c(status_color, status):<22} {hit_str:<8} {C.D}{created}{C.RST}")

    print()


# ─── Status banner ───────────────────────────────────────────────────────────

def _check_tool_status() -> dict:
    """Check availability of key external tools."""
    import shutil
    tools = {}
    for name in ("subfinder", "httpx", "nuclei", "katana", "dalfox", "gau", "assetfinder", "kr", "arjun"):
        found = shutil.which(name)
        if not found:
            go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", name + (".exe" if os.name == "nt" else ""))
            found = go_bin if os.path.exists(go_bin) else None
        tools[name] = found is not None
    return tools


def show_status_banner():
    """Show quick system status after logo."""
    tools = _check_tool_status()
    ok = sum(1 for v in tools.values() if v)
    total = len(tools)

    status_line = f"  {_c(C.G, f'{ok}/{total}')} tools ready"
    missing = [n for n, v in tools.items() if not v]
    if missing:
        status_line += f"  {_c(C.R, '(missing: ' + ', '.join(missing) + ')')}"

    print(status_line)

    # Recent scan summary
    scans = _get_scan_history(3)
    if scans:
        last = scans[0]
        domain = last.get("domain", "?")
        scanner = last.get("scanner", "?")
        status = last.get("status", "?")
        created = (last.get("created_at", "") or "")[:16]
        sc = C.G if status == "completed" else C.Y if status == "running" else C.R
        print(f"  {_c(C.D, 'Last scan:')} {scanner} → {domain} ({_c(sc, status)}) {_c(C.D, created)}")
    print()


# ─── Display menu ────────────────────────────────────────────────────────────

FEATURES = {
    # Pipeline ★
    "0":  ("pipeline",    "FULL PIPELINE ★",      "6-phase auto: recon→hunt→validate→report (ALL 5 PROVIDERS)"),
    # Recon
    "1":  ("light",       "Light Scan",           "Subfinder + Httpx + Nuclei (fast recon)"),
    "2":  ("dark",        "Dark Scan",            "Subfinder + Assetfinder + Katana + Nuclei"),
    "3":  ("deep",        "Deep Scan",            "Full recon: 4-stage Nuclei + takeover check"),
    # Vuln scanning
    "12": ("ssti",        "SSTI Probe",           "Test for Server-Side Template Injection"),
    "13": ("cors",        "CORS Misconfig",       "Check for CORS origin-reflection bugs"),
    "14": ("xss",         "XSS Scan",             "Reflected/DOM XSS detection with dalfox"),
    "15": ("sqli",        "SQL Injection",        "Error-based SQLi probe + sqlmap wrapper"),
    "16": ("lfi",         "LFI / Path Traversal", "Local File Inclusion payload fuzzing"),
    "17": ("crlf",        "CRLF Injection",       "Header injection via CRLF sequences"),
    "18": ("openredirect", "Open Redirect",       "Redirect parameter fuzzing (URL/header/JS)"),
    # Discovery
    "20": ("takeover",    "Subdomain Takeover",   "Check for dangling CNAME / unclaimed services"),
    "21": ("sensitive",   "Sensitive Data",        "Find exposed .env, .sql, .bak, .config files"),
    "22": ("blh",         "Broken Link Hunter",   "Check social/profile links (IG, Twitter, etc)"),
    "23": ("tpa",         "3rd Party Assets",     "Find Drive/SharePoint/GitHub links on site"),
    "24": ("cred",        "Credential URLs",      "Search for leaked config/credential endpoints"),
    "25": ("apirecon",    "API Endpoint Recon",   "Bruteforce API routes with kiterunner"),
    "26": ("params",      "Hidden Parameters",    "Discover hidden params with arjun"),
    # Infra & Analysis
    "30": ("portscan",    "Port Scan",            "Open port detection (naabu/nmap/socket)"),
    "31": ("waf",         "WAF Detection",        "Identify Web Application Firewall (wafw00f)"),
    "32": ("jsanalysis",  "JS Analysis",          "Extract secrets/endpoints from JavaScript"),
    "33": ("fuzzer",      "Dir/Path Fuzzer",      "Content discovery (ffuf/feroxbuster/gobuster)"),
    "34": ("tech",        "Tech Fingerprint",     "Detect stack + auto stack-specific hunting"),
    "35": ("rank",        "Attack Surface Rank",  "Rank subdomains by attack value (admin>api>staging)"),
    "36": ("gf",          "GF Patterns",          "Filter URLs by vuln type (sqli/xss/ssrf/lfi/idor)"),
    # Utility
    "40": ("bbscope",     "Bug Bounty Scope",     "Pull scope from HackerOne/Bugcrowd/Intigriti"),
    "41": ("scoper",      "Check Scope",          "Check if a target is in-scope for a program"),
    "42": ("fullchain",   "Full Scanner Chain",   "Run all scanners on each active subdomain"),
    "43": ("gate",        "7-Question Gate",      "Validate finding before submission (kill weak bugs)"),
}


def display_menu():
    """Show the interactive menu with descriptions."""
    print(f"\n  {_c(C.BD, 'MAIN MENU')}")
    print()

    # Pipeline ★
    tag, name, desc = FEATURES["0"]
    print(f"  {_c(C.R, '── PIPELINE (recommended) ───────────────────────────')}")
    print(f"  [{_c(C.BD, '0')}]  {name:<20} {_c(C.D, desc)}")

    # Recon group
    print(f"\n  {_c(C.CY, '── Recon ─────────────────────────────────────────────')}")
    for key in ("1", "2", "3"):
        tag, name, desc = FEATURES[key]
        marker = " ★" if key == "3" else ""
        print(f"  [{_c(C.BD, key)}]  {name:<20} {_c(C.D, desc)}{_c(C.R, marker)}")

    # Vuln scan group
    print(f"\n  {_c(C.CY, '── Vulnerability Scanning ────────────────────────────')}")
    for key in ("12", "13", "14", "15", "16", "17", "18"):
        tag, name, desc = FEATURES[key]
        print(f"  [{_c(C.BD, key)}]  {name:<20} {_c(C.D, desc)}")

    # Discovery group
    print(f"\n  {_c(C.CY, '── Discovery ────────────────────────────────────────')}")
    for key in ("20", "21", "22", "23", "24", "25", "26"):
        tag, name, desc = FEATURES[key]
        print(f"  [{_c(C.BD, key)}]  {name:<20} {_c(C.D, desc)}")

    # Infra & Analysis
    print(f"\n  {_c(C.CY, '── Infrastructure & Analysis ─────────────────────────')}")
    for key in ("30", "31", "32", "33", "34", "35", "36"):
        tag, name, desc = FEATURES[key]
        print(f"  [{_c(C.BD, key)}]  {name:<20} {_c(C.D, desc)}")

    # Utility group
    print(f"\n  {_c(C.CY, '── Utility ──────────────────────────────────────────')}")
    for key in ("40", "41", "42", "43"):
        tag, name, desc = FEATURES[key]
        print(f"  [{_c(C.BD, key)}]  {name:<20} {_c(C.D, desc)}")

    print()
    print(f"  [{_c(C.BD, 'H')}]  Scan History          {_c(C.D, 'View previous scan results')}")
    print(f"  [{_c(C.BD, 'S')}]  Setup / Config        {_c(C.D, 'Bot token, speed, katana limit')}")
    print(f"  [{_c(C.BD, 'I')}]  Feature Info          {_c(C.D, 'Detailed explanation of each feature')}")
    print(f"  [{_c(C.BD, 'U')}]  Update Tool           {_c(C.D, 'Pull latest version from GitHub')}")
    print(f"  [{_c(C.BD, 'Q')}]  Quit")
    print()
    print(f"  {_c(C.D, '──────────────────────────────────────────────────────────────────────────────')}")

    valid = [str(i) for i in range(0, 50)] + ["h", "s", "i", "u", "q"]
    while True:
        choice = input(f"  {_c(C.BD, 'Choose')} > ").strip().lower()
        if choice in valid:
            return choice
        print(f"  {_c(C.R, '[!]')} Invalid choice. Type a number or H/S/I/U/Q.")


# ─── Scan runner ─────────────────────────────────────────────────────────────

def run_scan(scan: str, target: str = None, speed: str = "standard",
             list_path: str = None, auto_continue: bool = False, auto_restart: bool = False,
             full: bool = False):
    if speed in SPEED_ALIAS:
        speed = SPEED_ALIAS[speed]
    if speed not in ("low", "standard", "fast"):
        speed = "standard"
    core.CMD_LINE_SPEED = speed
    core.SCAN_SPEED = speed

    if scan == "lts":
        if not target:
            return "[!] Light scan butuh target"
        print(f"\n  {_c(C.G, '[*]')} Starting Light Scan on {_c(C.BD, target)} (speed: {speed})")
        action = _resolve_resume(target, auto_continue, auto_restart)
        light_scan_target(target, resume=(action == "continue"))
        if full:
            from deep_full import run_full_chain
            sub_file = os.path.join("subdomain", f"{target}.txt")
            run_full_chain(target, subdomain_file=sub_file)
        return f"  {_c(C.G, '[OK]')} Light scan selesai: {target}"

    if scan in ("dks", "dps"):
        mode = "dark" if scan == "dks" else "deep"
        if not target:
            return "[!] Dark/Deep scan butuh target"
        print(f"\n  {_c(C.G, '[*]')} Starting {mode.title()} Scan on {_c(C.BD, target)} (speed: {speed})")
        action = _resolve_resume(target, auto_continue, auto_restart)
        dark_deep_target(mode, target, resume=(action == "continue"))
        if full:
            from deep_full import run_full_chain
            sub_file = os.path.join("subdomain", f"{target}.txt")
            run_full_chain(target, subdomain_file=sub_file)
        else:
            try:
                from report_gen import generate as gen_report
                res = gen_report(target)
                print(f"\n  {_c(C.G, '[REPORT]')} HTML: {res['html']}")
                print(f"  {_c(C.G, '[REPORT]')} TXT : {res['txt']}")
                print(f"  {_c(C.G, '[REPORT]')} {res['findings']} findings collected")
            except Exception as e:
                print(f"  {_c(C.R, '[!]')} Report generation failed: {e}")
        return f"  {_c(C.G, '[OK]')} {mode.title()} scan selesai: {target}"

    if scan == "tov":
        if list_path:
            if not os.path.isfile(list_path):
                return f"[!] File tidak ditemukan: {list_path}"
            print(f"\n  {_c(C.G, '[*]')} Starting Takeover mass scan from {_c(C.BD, list_path)}")
            takeover_mass_file(list_path, target)
            return f"  {_c(C.G, '[OK]')} Takeover mass selesai: {list_path}"
        if target:
            print(f"\n  {_c(C.G, '[*]')} Starting Takeover scan on {_c(C.BD, target)}")
            takeover_single(target)
            return f"  {_c(C.G, '[OK]')} Takeover single selesai: {target}"
        return "[!] Takeover butuh -t target atau -l list"

    if scan == "sens":
        if not target:
            return "[!] Sensitive scan butuh target"
        print(f"\n  {_c(C.G, '[*]')} Scanning for sensitive data on {_c(C.BD, target)}")
        find_sensitive_data(target)
        return f"  {_c(C.G, '[OK]')} Sensitive scan selesai: {target}"

    if scan in ("blh", "bac", "cred", "apirecon", "params", "ssti", "cors", "xss",
                "sqli", "lfi", "crlf", "openredirect", "portscan", "waf", "jsanalysis", "fuzzer",
                "pipeline", "techfingerprint", "tech", "gfpatterns", "gf", "gate", "validate",
                "attackrank", "rank"):
        if not target:
            return f"[!] {scan.upper()} scan butuh target"
        from scanners import SCANNER_REGISTRY
        runner = SCANNER_REGISTRY.get(scan)
        if not runner:
            return f"[!] Scanner module {scan} tidak tersedia"

        scan_labels = {
            "blh": "Broken Link Hunter", "tpa": "3rd Party Assets",
            "cred": "Credential URLs", "apirecon": "API Endpoint Recon",
            "params": "Hidden Parameters", "ssti": "SSTI Probe",
            "cors": "CORS Misconfiguration", "xss": "XSS Scan (dalfox)",
            "sqli": "SQL Injection", "lfi": "LFI / Path Traversal",
            "crlf": "CRLF Injection", "openredirect": "Open Redirect",
            "portscan": "Port Scan", "waf": "WAF Detection",
            "jsanalysis": "JS Analysis", "fuzzer": "Dir/Path Fuzzer",
            "pipeline": "Full Pipeline", "techfingerprint": "Tech Fingerprint",
            "tech": "Tech Fingerprint", "gfpatterns": "GF Patterns",
            "gf": "GF Patterns", "gate": "7-Question Gate",
            "validate": "7-Question Gate", "attackrank": "Attack Surface Rank",
            "rank": "Attack Surface Rank",
        }
        label = scan_labels.get(scan, scan.upper())
        print(f"\n  {_c(C.G, '[*]')} Starting {_c(C.BD, label)} on {_c(C.BD, target)}")

        try:
            result = runner(target)
        except Exception as e:
            return f"  {_c(C.R, '[!]')} {scan} error: {e}"

        if isinstance(result, dict) and result.get("ok") is False:
            return f"  {_c(C.R, '[!]')} {scan} gagal: {result.get('error', 'unknown')}"

        keys = ("endpoints", "params", "probes", "findings", "links_checked", "links_found")
        summary = next((result[k] for k in keys if k in result), 0)
        sid = result.get("scan_id", "?")
        return (
            f"  {_c(C.G, '[OK]')} {label} selesai: {_c(C.BD, str(summary))} hits\n"
            f"  {_c(C.D, 'Database:')} matthunder_scans.db  {_c(C.D, 'Scan ID:')} {sid}"
        )

    return f"[!] Scan tidak dikenal: {scan}"


# ─── Interactive menu logic ──────────────────────────────────────────────────

def interactive_menu():
    print_logo()
    show_status_banner()

    while True:
        choice = display_menu()

        # ── Pipeline ★ ─────────────────────────────────────────────────────
        if choice == "0":
            t = _ask_target()
            if t:
                spd = _ask_speed()
                try:
                    from scanners.pipeline import run as pipeline_run
                    pipeline_run(t, speed=spd)
                except Exception as e:
                    print(f"  {_c(C.R, '[!]')} Pipeline error: {e}")

        # ── Recon ────────────────────────────────────────────────────────────
        elif choice == "1":
            _run_light_scan()
        elif choice == "2":
            _run_scan_with_speed("dark")
        elif choice == "3":
            _run_scan_with_speed("deep")

        # ── Vuln scanning ───────────────────────────────────────────────────
        elif choice == "12":
            t = _ask_target()
            if t: print(run_scan("ssti", target=t))
        elif choice == "13":
            t = _ask_target()
            if t: print(run_scan("cors", target=t))
        elif choice == "14":
            t = _ask_target()
            if t: print(run_scan("xss", target=t))
        elif choice == "15":
            t = _ask_target()
            if t: print(run_scan("sqli", target=t))
        elif choice == "16":
            t = _ask_target()
            if t: print(run_scan("lfi", target=t))
        elif choice == "17":
            t = _ask_target()
            if t: print(run_scan("crlf", target=t))
        elif choice == "18":
            t = _ask_target()
            if t: print(run_scan("openredirect", target=t))

        # ── Discovery ───────────────────────────────────────────────────────
        elif choice == "20":
            _run_takeover()
        elif choice == "21":
            t = _ask_target()
            if t:
                print(f"\n  {_c(C.G, '[*]')} Scanning for sensitive data on {_c(C.BD, t)}")
                find_sensitive_data(t)
                print(f"  {_c(C.G, '[OK]')} Sensitive scan selesai: {t}")
        elif choice == "22":
            t = _ask_target()
            if t: print(run_scan("blh", target=t))
        elif choice == "23":
            t = _ask_target()
            if t: print(run_scan("tpa", target=t))
        elif choice == "24":
            t = _ask_target()
            if t: print(run_scan("cred", target=t))
        elif choice == "25":
            t = _ask_target()
            if t: print(run_scan("apirecon", target=t))
        elif choice == "26":
            t = _ask_target()
            if t: print(run_scan("params", target=t))

        # ── Infra & Analysis ────────────────────────────────────────────────
        elif choice == "30":
            t = _ask_target()
            if t: print(run_scan("portscan", target=t))
        elif choice == "31":
            t = _ask_target()
            if t: print(run_scan("waf", target=t))
        elif choice == "32":
            t = _ask_target()
            if t: print(run_scan("jsanalysis", target=t))
        elif choice == "33":
            t = _ask_target()
            if t: print(run_scan("fuzzer", target=t))
        elif choice == "34":
            t = _ask_target()
            if t: print(run_scan("tech", target=t))
        elif choice == "35":
            t = _ask_target()
            if t: print(run_scan("rank", target=t))
        elif choice == "36":
            t = _ask_target()
            if t: print(run_scan("gf", target=t))

        # ── Utility ─────────────────────────────────────────────────────────
        elif choice == "40":
            _run_bbscope()
        elif choice == "41":
            _run_scoper()
        elif choice == "42":
            _run_fullchain()
        elif choice == "43":
            try:
                from scanners.gate import run_interactive
                run_interactive()
            except Exception as e:
                print(f"  {_c(C.R, '[!]')} Gate error: {e}")

        # ── Meta / Navigation ───────────────────────────────────────────────
        elif choice == "h":
            show_scan_history()
        elif choice == "s":
            from matthunder import setup_menu
            setup_menu()
        elif choice == "i":
            _show_feature_info()
        elif choice == "u":
            feature_update_tool()
        elif choice in ("99", "q"):
            print(f"\n  {_c(C.G, '[OK]')} Bye!\n")
            break
        elif choice == "0":
            _show_feature_info()
        elif choice == "9":
            from matthunder import setup_menu
            setup_menu()
        elif choice == "999":
            feature_update_tool()


# ─── Prompt helpers ──────────────────────────────────────────────────────────

def _ask_target() -> str:
    t = input(f"  {_c(C.BD, 'Target')} (example.com): ").strip()
    return _normalize_target(t)


def _ask_speed() -> str:
    print(f"  {_c(C.D, 'Speed:')} [1] low  [2] standard  [3] fast")
    spd = input(f"  {_c(C.BD, 'Speed')} (default standard): ").strip().lower() or "standard"
    if spd in SPEED_ALIAS:
        spd = SPEED_ALIAS[spd]
    if spd not in ("low", "standard", "fast"):
        spd = "standard"
    return spd


def _ask_full_chain() -> bool:
    ans = input(f"  {_c(C.D, 'Run full scanner chain after?')} (y/N): ").strip().lower()
    return ans == "y"


# ─── Scan wrappers ───────────────────────────────────────────────────────────

def _run_light_scan():
    t = _ask_target()
    if not t:
        return
    spd = _ask_speed()
    full = _ask_full_chain()
    print(run_scan("lts", target=t, speed=spd, full=full))


def _run_scan_with_speed(kind: str):
    t = _ask_target()
    if not t:
        return
    spd = _ask_speed()
    full = _ask_full_chain()
    scan = "dks" if kind == "dark" else "dps"
    print(run_scan(scan, target=t, speed=spd, full=full))


def _run_takeover():
    print(f"\n  {_c(C.D, '[1]')} Single target")
    print(f"  {_c(C.D, '[2]')} Mass from file")
    m = input(f"  {_c(C.BD, 'Pilih')} (1/2): ").strip()
    if m == "1":
        t = _ask_target()
        if t:
            print(run_scan("tov", target=t))
    elif m == "2":
        fp = input(f"  {_c(C.BD, 'Path file')} subdomain list: ").strip()
        if fp:
            name = input(f"  {_c(C.D, 'Output name')} (optional): ").strip() or None
            print(run_scan("tov", target=name, list_path=fp))


def _run_bbscope():
    print(f"\n  {_c(C.G, '[*]')} Pulling bug bounty scope...")
    try:
        import bbscope
        res = bbscope.run_all()
        ok_count = sum(1 for r in res["results"] if r.get("ok"))
        chaos = res.get("chaos", {}).get("programs", 0)
        print(f"  {_c(C.G, '[OK]')} Scope fetched: {ok_count} platforms ok, {chaos} chaos programs")
    except Exception as e:
        print(f"  {_c(C.R, '[!]')} bbscope error: {e}")


def _run_scoper():
    try:
        from scoper import Scoper
    except ImportError:
        print(f"  {_c(C.R, '[!]')} scoper module not found")
        return

    rules_path = input(
        f"  {_c(C.D, 'Rules file')} (default: public-bug-bounty-program/hackerone_bounty.txt): "
    ).strip() or "public-bug-bounty-program/hackerone_bounty.txt"

    if not os.path.exists(rules_path):
        print(f"  {_c(C.R, '[!]')} File not found: {rules_path}")
        return

    sc = Scoper()
    with open(rules_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            sc.add_rule(line)

    target = input(f"  {_c(C.BD, 'Check target')} (e.g. api.example.com): ").strip()
    if target:
        if sc.in_scope(target):
            print(f"  {_c(C.G, 'IN_SCOPE')} — {target}")
        else:
            print(f"  {_c(C.R, 'OUT_OF_SCOPE')} — {target}")


def _run_fullchain():
    t = _ask_target()
    if not t:
        return
    sub_file = os.path.join("subdomain", f"{t}.txt")
    if not os.path.exists(sub_file):
        print(f"  {_c(C.R, '[!]')} {sub_file} not found. Run a Deep Scan first to generate subdomains.")
        return
    from deep_full import run_full_chain
    print(f"\n  {_c(C.G, '[*]')} Running full scanner chain on {_c(C.BD, t)}")
    run_full_chain(t, subdomain_file=sub_file)


# ─── Feature info ────────────────────────────────────────────────────────────

def _show_feature_info():
    """Show detailed explanation for each feature with examples."""
    print(f"\n{_c(C.BD, '  ═══════════════════════════════════════════════════════════════')}")
    print(f"  {_c(C.BD, 'FEATURE GUIDE')}")
    print(f"{_c(C.BD, '  ═══════════════════════════════════════════════════════════════')}")

    sections = [
        (_c(C.CY, "  RECON"), [
            ("1  Light Scan",
             "Scan cepat untuk pemula. Cocok untuk first look.\n"
             "   Tools: Subfinder (cari subdomain) → Httpx (filter yang aktif) → Nuclei (scan vuln umum)\n"
             "   Contoh: scan semua subdomain jogjaprov.go.id yang aktif, lalu cek CVE/misconfig"),
            ("2  Dark Scan",
             "Recon menengah. Lebih dalam dari Light.\n"
             "   Tools: Subfinder + Assetfinder → Httpx → Katana (crawl URL) → Nuclei (xss/sqli/lfi)\n"
             "   Tambah: crawling URL berparameter, scan .js exposure"),
            ("3  Deep Scan  ★",
             "Full recon paling lengkap. Best choice buat serious hunting.\n"
             "   Tools: Semua di Dark + 4-stage Nuclei + subdomain takeover check\n"
             "   Stage 1: misconfig/exposure  Stage 2: xss/sqli/lfi\n"
             "   Stage 3: .js exposure        Stage 4: subdomain takeover"),
        ]),
        (_c(C.CY, "  VULNERABILITY SCANNING"), [
            ("12 SSTI Probe",
             "Cek Server-Side Template Injection (Jinja2, Twig, Freemarker, ERB, dll).\n"
             "   Kirim payload polyglot {{7*7}} ke semua URL yang di-crawl, cek response."),
            ("13 CORS Misconfig",
             "Cek apakah origin bisa di-reflected di response header.\n"
             "   Deteksi: reflected origin + credentials, null origin, wildcard + creds."),
            ("14 XSS Scan (dalfox)",
             "Scan Reflected/DOM XSS pake dalfox (Go tool).\n"
             "   Crawl URL → extract parameter → fuzz dengan dalfox payload.\n"
             "   Catatan: butuh dalfox installed (setup.bat / go install dalfox)."),
            ("15 SQL Injection",
             "Cek SQLi error-based + sqlmap wrapper.\n"
             "   Kirim payload SQLi (' OR 1=1, UNION SELECT, dll) ke parameter URL.\n"
             "   Kalau sqlmap terinstall, otomatis dijalankan juga."),
            ("16 LFI / Path Traversal",
             "Cek Local File Inclusion dengan payload traversal (../../etc/passwd).\n"
             "   Deteksi: /etc/passwd, /proc/self/environ, php://filter, dll."),
            ("17 CRLF Injection",
             "Cek header injection via CRLF sequence (\\r\\n).\n"
             "   Tools: crlfuzz (Go) + manual probe.\n"
             "   Deteksi: injected header, redirect injection."),
            ("18 Open Redirect",
             "Cek parameter redirect yang bisa di-arahkan ke domain lain.\n"
             "   Test: url, redirect, next, return, goto, dest, dll.\n"
             "   Deteksi: 302 redirect ke evil.com, meta refresh, JS redirect."),
        ]),
        (_c(C.CY, "  DISCOVERY"), [
            ("20 Subdomain Takeover",
             "Cek subdomain yang bisa di-takeover (dangling CNAME).\n"
             "   Mode: single target atau mass dari file .txt."),
            ("21 Sensitive Data",
             "Cari file sensitif yang terekspos (.env, .sql, .bak, .config, .log, .json, .js).\n"
             "   Tools: gau (URL archive) → filter extension → Httpx (verify aktif)."),
            ("22 Broken Link Hunter",
             "Cek status social media links di website target.\n"
             "   Deteksi: akun mati, redirect, blocked di IG/Twitter/FB/LinkedIn/GitHub/dll."),
            ("23 3rd Party Assets",
             "Cari link Google Drive, SharePoint, GitHub di halaman target.\n"
             "   Berguna buat nemu dokumen internal yang bocor."),
            ("24 Credential URLs",
             "Cari URL yang mengandung config/credential (.env, wp-config, .htaccess, dll)."),
            ("25 API Endpoint Recon",
             "Bruteforce API routes pake kiterunner.\n"
             "   Cocok buat REST/GraphQL endpoint discovery."),
            ("26 Hidden Parameters",
             "Discover hidden query parameters pake arjun.\n"
             "   Berguna buat nemu param yang gak keliatan di source code."),
        ]),
        (_c(C.CY, "  INFRASTRUCTURE & ANALYSIS"), [
            ("30 Port Scan",
             "Scan port terbuka di target.\n"
             "   Tools: naabu (Go) → nmap → Python socket fallback.\n"
             "   Default: top 30 ports (21,22,80,443,3306,8080, dll)."),
            ("31 WAF Detection",
             "Deteksi Web Application Firewall (Cloudflare, Akamai, AWS WAF, dll).\n"
             "   Tools: wafw00f + manual header signature detection."),
            ("32 JS Analysis",
             "Analisis file JavaScript buat nemu secrets & endpoints.\n"
             "   Deteksi: API keys (AWS, GitHub, Stripe, dll), JWT, private keys,\n"
             "   high-entropy strings, API endpoints, fetch/axios calls."),
            ("33 Dir/Path Fuzzer",
             "Content discovery: cari direktori & file tersembunyi.\n"
             "   Tools: ffuf → feroxbuster → gobuster → built-in probe.\n"
             "   Contoh: /admin, /api, /backup, /.env, /wp-admin, dll."),
        ]),
        (_c(C.CY, "  UTILITY"), [
            ("40 Bug Bounty Scope",
             "Pull scope dari HackerOne, Bugcrowd, Intigriti.\n"
             "   Output: list domain/wildcard yang in-scope."),
            ("41 Check Scope",
             "Cek apakah target tertentu masuk scope program bug bounty.\n"
             "   Input: rules file + target domain."),
            ("42 Full Chain",
             "Jalankan semua scanner pada setiap subdomain aktif.\n"
             "   Butuh Deep Scan dulu buat generate subdomain list."),
        ]),
        (_c(C.CY, "  TIPS UNTUK PEMULA"), [
            ("Mulai dari Light Scan",
             "Coba: pilih [1] → masukkan target → speed standard.\n"
             "   Hasilnya otomatis disimpan di matthunder_scans.db."),
            ("Pakai Scan History",
             "Ketik [H] di menu utama buat lihat hasil scan sebelumnya.\n"
             "   Termasuk scan ID, status, jumlah hits."),
            ("Cek Status Tools",
             "Banner di atas menu nunjukin tool mana yang udah terinstall.\n"
             "   Kalau ada yang missing, jalankan setup.bat / setup.sh."),
            ("CLI Mode",
             "Bisa langsung: python matthunder_cli.py deep example.com\n"
             "   Tambah --telegram buat auto-start bot Telegram."),
        ]),
    ]

    for header, items in sections:
        print(f"\n  {header}")
        print(f"  {'─' * 60}")
        for title, desc in items:
            print(f"  {_c(C.BD, title)}")
            for line in desc.split("\n"):
                print(f"  {line}")
            print()

    print(f"  {_c(C.D, '──────────────────────────────────────────────────────────────────────────────')}")
    input(f"  {_c(C.D, 'Press Enter to return to menu...')}")


# ─── AI parser ───────────────────────────────────────────────────────────────

def ai_parse(query: str, provider: str = None, model: str = None):
    from ai_parser import parse_query, heuristic_parse
    res = parse_query(query, provider=provider, model=model)
    if "error" in res and not res.get("scan"):
        fb = heuristic_parse(query)
        if fb:
            fb["source"] = "heuristic-fallback"
            return fb
    return res


# ─── Telegram starter ────────────────────────────────────────────────────────

def _start_telegram():
    bot = ROOT / "telegram_deep_bot.py"
    if not bot.exists():
        print(f"  {_c(C.R, '[!]')} telegram_deep_bot.py tidak ditemukan")
        return
    import subprocess
    print(f"  {_c(C.G, '[*]')} Starting Telegram bot...")
    try:
        subprocess.Popen([sys.executable, str(bot)], cwd=str(ROOT))
    except Exception as e:
        print(f"  {_c(C.R, '[!]')} Gagal start Telegram bot: {e}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="matthunder",
        description="matthunder CLI — recon automation with optional AI parser (BYOK)",
    )
    p.add_argument("scan", nargs="?", help="light | dark | deep | sqli | lfi | crlf | openredirect | xss | ssti | cors | portscan | waf | jsanalysis | fuzzer | takeover | sensitive | blh | tpa | cred | apirecon | params")
    p.add_argument("target", nargs="?", help="Target domain")
    p.add_argument("speed", nargs="?", default="standard", help="low | standard | fast (or 1/2/3)")
    p.add_argument("-l", "--list", help="Subdomain list file (for takeover mass)")
    p.add_argument("-ac", "--auto-continue", action="store_true")
    p.add_argument("-ar", "--auto-restart", action="store_true")
    p.add_argument("-i", "--interactive", action="store_true", help="Force interactive menu")
    p.add_argument("--ai", metavar="QUERY", help="Parse natural language query via AI (BYOK)")
    p.add_argument("--ai-provider", choices=["openai", "anthropic", "gemini", "openrouter"])
    p.add_argument("--ai-model", help="Override AI model (e.g. gpt-4o, claude-3-5-sonnet-latest)")
    p.add_argument("--update", action="store_true", help="Run self-update from GitHub")
    p.add_argument("--telegram", action="store_true", help="Also start Telegram bot wrapper")
    p.add_argument("--info", action="store_true", help="Show version + AI status")
    p.add_argument("--full", action="store_true", help="After deep/dark scan, run full inline scanner chain (blh/tpa/cred/ssti/cors/xss/apirecon/params) per active subdomain")
    p.add_argument("--history", action="store_true", help="Show scan history and exit")
    args = p.parse_args()

    if args.info:
        from ai_parser import detect_provider
        print_logo()
        print(f"  matthunder CLI")
        print(f"    AI provider: {detect_provider() or 'not configured (set OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY / OPENROUTER_API_KEY)'}")
        print(f"    Telegram:    {'enabled (--telegram)' if args.telegram else 'off'}")
        return

    if args.history:
        show_scan_history()
        return

    if args.update:
        feature_update_tool()
        return

    if args.ai:
        result = ai_parse(args.ai, provider=args.ai_provider, model=args.ai_model)
        if "error" in result and not result.get("scan"):
            print(f"[!] {result['error']}")
            sys.exit(2)
        print(f"[AI] source={result.get('source', 'api')} -> {result}")
        msg = run_scan(
            result["scan"],
            target=result.get("target"),
            speed=result.get("speed", "standard"),
            list_path=result.get("list"),
            auto_continue=result.get("resume") == "continue",
            auto_restart=result.get("resume") == "restart",
            full=result.get("full", False),
        )
        print(msg)
        if args.telegram:
            _start_telegram()
        return

    if args.interactive or (not args.scan and not args.target and not args.list):
        interactive_menu()
        if args.telegram:
            _start_telegram()
        return

    if not args.scan:
        p.print_help()
        sys.exit(1)

    scan = args.scan.lower()
    SCAN_ALIASES = {
        "light": "lts", "lts": "lts",
        "dark": "dks", "dks": "dks",
        "deep": "dps", "dps": "dps",
        "takeover": "tov", "tov": "tov",
        "sensitive": "sens", "sens": "sens",
        "blh": "blh", "broken": "blh",
        "tpa": "tpa", "thirdparty": "tpa", "collab": "tpa", "drive": "tpa", "sharepoint": "tpa", "3rd-party": "tpa",
        "cred": "cred", "credentials": "cred", "config": "cred",
        "apirecon": "apirecon", "api": "apirecon", "kiterunner": "apirecon",
        "params": "params", "parameters": "params", "arjun": "params",
        "ssti": "ssti", "template": "ssti",
        "cors": "cors",
        "xss": "xss", "dalfox": "xss", "cross-site-scripting": "xss",
        "sqli": "sqli", "sqlmap": "sqli", "sql-injection": "sqli",
        "lfi": "lfi", "path-traversal": "lfi", "file-inclusion": "lfi",
        "crlf": "crlf", "header-injection": "crlf",
        "openredirect": "openredirect", "oredir": "openredirect", "open-redirect": "openredirect",
        "portscan": "portscan", "ports": "portscan", "nmap": "portscan", "port-scan": "portscan",
        "waf": "waf", "wafw00f": "waf", "firewall": "waf",
        "jsanalysis": "jsanalysis", "js": "jsanalysis", "javascript": "jsanalysis",
        "fuzzer": "fuzzer", "fuzz": "fuzzer", "dirscan": "fuzzer", "directory": "fuzzer",
        "pipeline": "pipeline", "autopilot": "pipeline", "full-pipeline": "pipeline",
        "techfingerprint": "techfingerprint", "tech": "techfingerprint", "fingerprint": "techfingerprint",
        "gfpatterns": "gfpatterns", "gf": "gfpatterns", "patterns": "gfpatterns",
        "gate": "gate", "validate": "gate", "triage": "gate",
        "attackrank": "attackrank", "rank": "attackrank", "surface": "attackrank",
    }
    scan = SCAN_ALIASES.get(scan)
    if not scan:
        print(f"[!] Scan tidak dikenal: {args.scan}")
        print(f"    Available: light, dark, deep, sqli, lfi, crlf, openredirect, xss, ssti, cors,")
        print(f"               portscan, waf, jsanalysis, fuzzer, takeover, sensitive, blh, tpa, cred, apirecon, params")
        sys.exit(1)

    target = _normalize_target(args.target) if args.target else None
    msg = run_scan(
        scan,
        target=target,
        speed=args.speed,
        list_path=args.list,
        auto_continue=args.auto_continue,
        auto_restart=args.auto_restart,
        full=args.full,
    )
    print(msg)
    if args.telegram:
        _start_telegram()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  [!] Dibatalkan.")
        sys.exit(130)
