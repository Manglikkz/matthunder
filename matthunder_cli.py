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
    display_menu,
    light_scan_target,
    dark_deep_target,
    takeover_mass_file,
    takeover_single,
    find_sensitive_data,
    check_previous_scan,
    ask_continue_or_restart,
    feature_update_tool,
)


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
        action = _resolve_resume(target, auto_continue, auto_restart)
        light_scan_target(target, resume=(action == "continue"))
        if full:
            from deep_full import run_full_chain
            sub_file = os.path.join("subdomain", f"{target}.txt")
            run_full_chain(target, subdomain_file=sub_file)
        return f"[OK] Light scan selesai: {target}"
    if scan in ("dks", "dps"):
        mode = "dark" if scan == "dks" else "deep"
        if not target:
            return "[!] Dark/Deep scan butuh target"
        action = _resolve_resume(target, auto_continue, auto_restart)
        dark_deep_target(mode, target, resume=(action == "continue"))
        if full:
            from deep_full import run_full_chain
            sub_file = os.path.join("subdomain", f"{target}.txt")
            run_full_chain(target, subdomain_file=sub_file)
        return f"[OK] {mode.title()} scan selesai: {target}"
    if scan == "tov":
        if list_path:
            if not os.path.isfile(list_path):
                return f"[!] File tidak ditemukan: {list_path}"
            takeover_mass_file(list_path, target)
            return f"[OK] Takeover mass selesai: {list_path}"
        if target:
            takeover_single(target)
            return f"[OK] Takeover single selesai: {target}"
        return "[!] Takeover butuh -t target atau -l list"
    if scan == "sens":
        if not target:
            return "[!] Sensitive scan butuh target"
        find_sensitive_data(target)
        return f"[OK] Sensitive scan selesai: {target}"
    if scan in ("blh", "bac", "cred", "apirecon", "params", "ssti", "cors", "xss"):
        if not target:
            return "[!] %s scan butuh target" % scan.upper()
        from scanners import SCANNER_REGISTRY
        runner = SCANNER_REGISTRY.get(scan)
        if not runner:
            return f"[!] Scanner module {scan} tidak tersedia"
        try:
            result = runner(target, [])
        except Exception as e:
            return f"[!] {scan} error: {e}"
        keys = ("endpoints", "params", "probes", "findings", "links_checked", "links_found")
        summary = next((result[k] for k in keys if k in result), 0)
        return f"[OK] {scan.upper()} scan selesai: {summary} hits (db: matthunder_scans.db, scan_id: {result.get('scan_id')})"
    return f"[!] Scan tidak dikenal: {scan}"


def interactive_menu():
    print_logo()
    while True:
        choice = display_menu()
        if choice == "1":
            light_scan()
        elif choice == "2":
            prompt_scan("dark")
        elif choice == "3":
            prompt_scan("deep")
        elif choice == "4":
            prompt_takeover()
        elif choice == "5":
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                find_sensitive_data(t)
        elif choice == "6":
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                run_scan("blh", target=t)
        elif choice == "7":
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                run_scan("tpa", target=t)
        elif choice == "8":
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                run_scan("cred", target=t)
        elif choice == "10":
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                run_scan("apirecon", target=t)
        elif choice == "11":
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                run_scan("params", target=t)
        elif choice == "12":
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                run_scan("ssti", target=t)
        elif choice == "13":
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                run_scan("cors", target=t)
        elif choice == "14":
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                run_scan("xss", target=t)
        elif choice == "15":
            import bbscope
            res = bbscope.run_all()
            print(f"[OK] Scope fetched: {sum(1 for r in res['results'] if r.get('ok'))} platforms ok, {res['chaos'].get('programs', 0)} chaos programs")
        elif choice == "16":
            from scoper import Scoper
            rules_path = input("Rules file (default public-bug-bounty-program/hackerone_bounty.txt): ").strip() or "public-bug-bounty-program/hackerone_bounty.txt"
            if not os.path.exists(rules_path):
                print(f"[!] File not found: {rules_path}")
            else:
                sc = Scoper()
                with open(rules_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        sc.add_rule(line)
                target = input("Check target (example: api.example.com): ").strip()
                if target:
                    print("IN_SCOPE" if sc.in_scope(target) else "OUT_OF_SCOPE")
        elif choice == "17":
            from deep_full import run_full_chain
            t = _normalize_target(input("Target (example.com): ").strip())
            if t:
                sub_file = os.path.join("subdomain", f"{t}.txt")
                if not os.path.exists(sub_file):
                    print(f"[!] {sub_file} not found. Run 'deep' first.")
                else:
                    run_full_chain(t, subdomain_file=sub_file)
        elif choice == "9":
            from matthunder import setup_menu
            setup_menu()
        elif choice == "0":
            from matthunder import feature_info
            feature_info()
        elif choice == "99":
            print("[OK] Bye.")
            break
        elif choice == "999":
            feature_update_tool()
        else:
            print("[!] Pilihan tidak valid.")


def light_scan():
    t = _normalize_target(input("Target (example.com): ").strip())
    if not t:
        return
    spd = input("Speed [low/standard/fast] (default standard): ").strip().lower() or "standard"
    full = input("Run full inline scanner chain after? (y/N): ").strip().lower() == "y"
    run_scan("lts", target=t, speed=spd, full=full)


def prompt_scan(kind: str):
    t = _normalize_target(input("Target (example.com): ").strip())
    if not t:
        return
    spd = input("Speed [low/standard/fast] (default standard): ").strip().lower() or "standard"
    full = input("Run full inline scanner chain after? (y/N): ").strip().lower() == "y"
    scan = "dks" if kind == "dark" else "dps"
    run_scan(scan, target=t, speed=spd, full=full)


def prompt_takeover():
    print("1. Single target\n2. Mass from file")
    m = input("Pilih (1/2): ").strip()
    if m == "1":
        t = _normalize_target(input("Target: ").strip())
        if t:
            run_scan("tov", target=t)
    elif m == "2":
        fp = input("Path file subdomain list: ").strip()
        if fp:
            name = input("Output name (optional): ").strip() or None
            run_scan("tov", target=name, list_path=fp)


def ai_parse(query: str, provider: str = None, model: str = None):
    from ai_parser import parse_query, heuristic_parse
    res = parse_query(query, provider=provider, model=model)
    if "error" in res and not res.get("scan"):
        fb = heuristic_parse(query)
        if fb:
            fb["source"] = "heuristic-fallback"
            return fb
    return res


def main():
    p = argparse.ArgumentParser(
        prog="matthunder",
        description="matthunder CLI — recon automation with optional AI parser (BYOK)",
    )
    p.add_argument("scan", nargs="?", help="light | dark | deep | takeover | sensitive | blh | tpa | cred | apirecon | params | ssti | cors | xss")
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
    args = p.parse_args()

    if args.info:
        from ai_parser import detect_provider
        print_logo()
        print(f"matthunder CLI")
        print(f"  AI provider: {detect_provider() or 'not configured (set OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY / OPENROUTER_API_KEY)'}")
        print(f"  Telegram:    {'enabled (--telegram)' if args.telegram else 'off'}")
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
    if scan in ("light", "lts"):
        scan = "lts"
    elif scan in ("dark", "dks"):
        scan = "dks"
    elif scan in ("deep", "dps"):
        scan = "dps"
    elif scan in ("takeover", "tov"):
        scan = "tov"
    elif scan in ("sensitive", "sens"):
        scan = "sens"
    elif scan in ("blh", "broken"):
        scan = "blh"
    elif scan in ("tpa", "thirdparty", "collab", "drive", "sharepoint", "3rd-party"):
        scan = "tpa"
    elif scan in ("cred", "credentials", "config"):
        scan = "cred"
    elif scan in ("apirecon", "api", "kiterunner"):
        scan = "apirecon"
    elif scan in ("params", "parameters", "arjun"):
        scan = "params"
    elif scan in ("ssti", "template"):
        scan = "ssti"
    elif scan in ("cors",):
        scan = "cors"
    elif scan in ("xss", "dalfox", "cross-site-scripting"):
        scan = "xss"
    else:
        print(f"[!] Scan tidak dikenal: {scan}")
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


def _start_telegram():
    bot = ROOT / "telegram_deep_bot.py"
    if not bot.exists():
        print("[!] telegram_deep_bot.py tidak ditemukan")
        return
    import subprocess
    print("[*] Starting Telegram bot...")
    try:
        subprocess.Popen([sys.executable, str(bot)], cwd=str(ROOT))
    except Exception as e:
        print(f"[!] Gagal start Telegram bot: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Dibatalkan.")
        sys.exit(130)
