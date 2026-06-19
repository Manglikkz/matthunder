#!/usr/bin/env python3
"""
botman.py — Multi-account bot manager for matthunder Telegram bot.

Manage multiple Telegram bot instances on the same machine, each with its
own token, owner ID, and isolated output directories.

Usage:
    python botman.py add --name MyBot --token TOKEN --owner 123456
    python botman.py start MyBot
    python botman.py stop  MyBot
    python botman.py list
    python botman.py logs  MyBot
    python botman.py remove MyBot
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BOTS_DIR = ROOT / "bots"
TELEGRAM_BOT = ROOT / "telegram_deep_bot.py"
PYTHON_BIN = os.getenv("MATTHUNDER_PYTHON", sys.executable or "python")

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200


# ── Helpers ─────────────────────────────────────────────────────────

def _bot_is_alive(name: str) -> bool:
    """Check if a bot is alive by heartbeat file freshness.

    The bot refreshes its heartbeat every ~10s. If the heartbeat file is
    newer than 60s, the bot is considered alive. No PID check needed —
    tasklist/WMI hang on zombie PIDs.
    """
    hb = _heartbeat_path(name)
    if not hb.exists():
        return False
    try:
        hb_ts = float(hb.read_text("utf-8").strip())
        return (time.time() - hb_ts) < 60
    except Exception:
        return False


def _kill_pid_tree(pid: int):
    if not pid:
        return
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass


def _bot_path(name: str) -> Path:
    return BOTS_DIR / name


def _config_path(name: str) -> Path:
    return _bot_path(name) / "config.json"


def _state_path(name: str) -> Path:
    return _bot_path(name) / "state"


def _lock_path(name: str) -> Path:
    return _state_path(name) / "bot.lock"


def _heartbeat_path(name: str) -> Path:
    return _state_path(name) / "bot.heartbeat"


def _logs_dir(name: str) -> Path:
    return _bot_path(name) / "logs"


def _read_lock(name: str) -> dict:
    p = _lock_path(name)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {}


def _bot_status(name: str) -> dict:
    """Return dict with status info for one bot directory."""
    cfg = _config_path(name)
    if not cfg.exists():
        return {"name": name, "exists": False}

    with open(cfg, "r", encoding="utf-8") as f:
        config = json.load(f)

    lock_data = _read_lock(name)
    pid = lock_data.get("pid")
    alive = _bot_is_alive(name)
    hb = _heartbeat_path(name)
    hb_age = -1
    if hb.exists():
        try:
            hb_age = int(time.time() - float(hb.read_text("utf-8").strip()))
        except Exception:
            hb_age = -1

    logs = _logs_dir(name)
    err_log = logs / "bot.err.log"
    last_err = ""
    if err_log.exists() and err_log.stat().st_size > 0:
        try:
            lines = err_log.read_text("utf-8", errors="replace").splitlines()
            last_err = lines[-1][:120] if lines else ""
        except Exception:
            pass

    return {
        "name": name,
        "exists": True,
        "pid": pid,
        "alive": alive,
        "heartbeat_age": hb_age,
        "last_error": last_err,
        "config": config,
    }


# ── Commands ────────────────────────────────────────────────────────

def cmd_add(args):
    name = args.name
    bot_dir = _bot_path(name)
    if bot_dir.exists():
        print(f"[!] Bot '{name}' already exists at {bot_dir}")
        return 1
    bot_dir.mkdir(parents=True, exist_ok=True)
    (bot_dir / "logs").mkdir(exist_ok=True)
    (bot_dir / "state").mkdir(exist_ok=True)
    (bot_dir / "reports").mkdir(exist_ok=True)
    for folder in ("subdomain", "active", "crawled", "crawled_filtered",
                   "nuclei", "take_over", "sensitive_data",
                   "output", "results"):
        (bot_dir / folder).mkdir(exist_ok=True)
    config = {
        "token": args.token,
        "owner_id": args.owner,
        "name": args.name,
    }
    if args.speed:
        config["speed"] = args.speed
    _config_path(name).write_text(
        json.dumps(config, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[+] Bot '{name}' created at {bot_dir}")
    return 0


def cmd_remove(args):
    name = args.name
    cmd_stop(args)  # stop first
    bot_dir = _bot_path(name)
    if not bot_dir.exists():
        print(f"[!] Bot '{name}' not found")
        return 1
    shutil.rmtree(bot_dir)
    print(f"[+] Bot '{name}' removed.")
    return 0


def cmd_start(args):
    name = args.name
    cfg = _config_path(name)
    if not cfg.exists():
        print(f"[!] Bot '{name}' not found. Use 'botman.py add --name {name} ...' first.")
        return 1

    # Check if already running (heartbeat)
    if _bot_is_alive(name):
        lock = _read_lock(name)
        pid = lock.get("pid", "?")
        print(f"[!] Bot '{name}' already running (PID {pid}). Use 'stop' first.")
        return 1

    # Ensure dirs
    _state_path(name).mkdir(parents=True, exist_ok=True)
    _logs_dir(name).mkdir(parents=True, exist_ok=True)

    # Launch detached
    log_out = (_logs_dir(name) / "bot.out.log").open("a", encoding="utf-8", errors="replace")
    log_err = (_logs_dir(name) / "bot.err.log").open("a", encoding="utf-8", errors="replace")
    try:
        sub_env = os.environ.copy()
        sub_env["PYTHONUNBUFFERED"] = "1"
        sub_env["PYTHONIOENCODING"] = "utf-8"
        sub_env["PYTHONUTF8"] = "1"
        proc = subprocess.Popen(
            [str(PYTHON_BIN), "-u", str(TELEGRAM_BOT), "--bot-dir", str(_bot_path(name))],
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=log_out,
            stderr=log_err,
            env=sub_env,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
        print(f"[+] Bot '{name}' started (PID {proc.pid}).")
    except Exception as e:
        print(f"[!] Failed to start '{name}': {e}")
        return 1
    finally:
        log_out.close()
        log_err.close()
    return 0


def cmd_stop(args):
    name = args.name
    lock = _read_lock(name)
    pid = lock.get("pid")
    if not _bot_is_alive(name):
        print(f"[i] Bot '{name}' is not running.")
        # Clean stale lock + heartbeat
        _lock_path(name).unlink(missing_ok=True)
        _heartbeat_path(name).unlink(missing_ok=True)
        return 0
    print(f"[i] Stopping bot '{name}' (PID {pid})...")
    _kill_pid_tree(pid)
    _lock_path(name).unlink(missing_ok=True)
    _heartbeat_path(name).unlink(missing_ok=True)
    print(f"[+] Bot '{name}' stopped.")
    return 0


def cmd_list(args):
    if not BOTS_DIR.exists():
        print("[i] No bots directory (bots/).")
        return 0
    bots = sorted(d.name for d in BOTS_DIR.iterdir() if d.is_dir() and (d / "config.json").exists())
    if not bots:
        print("[i] No bots found. Create one with 'botman.py add --name ...'")
        return 0
    print(f"{'NAME':<20} {'PID':<8} {'STATUS':<12} {'OWNER':<12} {'HEARTBEAT':<10} LAST ERROR")
    print("-" * 100)
    for name in bots:
        status = _bot_status(name)
        if not status["exists"]:
            continue
        pid_str = str(status["pid"]) if status["pid"] else "-"
        alive_str = "RUNNING" if status["alive"] else "STOPPED"
        owner = str(status["config"].get("owner_id", "?"))[:10]
        hb = f"{status['heartbeat_age']}s" if status["heartbeat_age"] >= 0 else "-"
        err = status["last_error"][:60] if status["last_error"] else ""
        print(f"{name:<20} {pid_str:<8} {alive_str:<12} {owner:<12} {hb:<10} {err}")
    return 0


def cmd_logs(args):
    name = args.name
    log_file = _logs_dir(name) / "bot.err.log"
    out_file = _logs_dir(name) / "bot.out.log"

    if not log_file.exists() and not out_file.exists():
        print(f"[!] No logs found for '{name}'.")
        return 1

    lines = args.lines or 30
    source = args.source or "err"

    target = out_file if source == "out" else log_file
    if not target.exists():
        print(f"[!] No {source} log for '{name}'.")
        return 1

    try:
        text = target.read_text(encoding="utf-8", errors="replace")
        tail = text.splitlines()
        if lines > 0:
            tail = tail[-lines:]
        print(f"=== {target} (last {len(tail)} lines) ===")
        for line in tail:
            print(line)
    except Exception as e:
        print(f"[!] Error reading log: {e}")
        return 1
    return 0


def cmd_status(args):
    name = args.name
    status = _bot_status(name)
    if not status["exists"]:
        print(f"[!] Bot '{name}' not found.")
        return 1
    print(f"Bot:     {name}")
    print(f"Owner:   {status['config'].get('owner_id', '?')}")
    print(f"Token:   {str(status['config'].get('token', '?'))[:15]}...")
    print(f"PID:     {status['pid'] or '-'}")
    print(f"Alive:   {'YES' if status['alive'] else 'NO'}")
    print(f"Heartbeat: {status['heartbeat_age']}s ago" if status['heartbeat_age'] >= 0 else "Heartbeat: -")
    print(f"Log dir: {_logs_dir(name)}")
    if status["last_error"]:
        print(f"Last err: {status['last_error']}")
    return 0


def cmd_config(args):
    """Show or edit a bot's config.json."""
    name = args.name
    cfg_p = _config_path(name)
    if not cfg_p.exists():
        print(f"[!] Bot '{name}' not found.")
        return 1
    if args.key is not None:
        with open(cfg_p, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if args.value is not None:
            cfg[args.key] = args.value
        else:
            cfg.pop(args.key, None)
        cfg_p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] {args.key} updated for '{name}'.")
    else:
        print(cfg_p.read_text(encoding="utf-8").rstrip())
    return 0


# ── Main ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="matthunder multi-bot manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python botman.py add --name Bot1 --token 123:abc --owner 123456
  python botman.py add --name Bot2 --token 456:def --owner 789012
  python botman.py start Bot1
  python botman.py list
  python botman.py logs Bot1 --lines 50
  python botman.py stop Bot1
  python botman.py remove Bot1
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # add
    p_add = sub.add_parser("add", help="Create a new bot")
    p_add.add_argument("--name", required=True, help="Bot name (used as directory name)")
    p_add.add_argument("--token", required=True, help="Telegram Bot Token from @BotFather")
    p_add.add_argument("--owner", required=True, help="Telegram user ID (owner)")
    p_add.add_argument("--speed", default=None, help="Default scan speed: low/standard/fast")
    p_add.set_defaults(func=cmd_add)

    # remove
    p_rem = sub.add_parser("remove", help="Stop and delete a bot")
    p_rem.add_argument("name")
    p_rem.set_defaults(func=cmd_remove)

    # start
    p_start = sub.add_parser("start", help="Start a bot")
    p_start.add_argument("name")
    p_start.set_defaults(func=cmd_start)

    # stop
    p_stop = sub.add_parser("stop", help="Stop a bot")
    p_stop.add_argument("name")
    p_stop.set_defaults(func=cmd_stop)

    # list
    sub.add_parser("list", help="List all bots and their status").set_defaults(func=cmd_list)

    # logs
    p_logs = sub.add_parser("logs", help="Show bot log tail")
    p_logs.add_argument("name")
    p_logs.add_argument("--lines", "-n", type=int, default=30, help="Number of lines (default 30)")
    p_logs.add_argument("--source", choices=["err", "out"], default="err", help="err or out log")
    p_logs.set_defaults(func=cmd_logs)

    # status
    p_st = sub.add_parser("status", help="Detailed status of a bot")
    p_st.add_argument("name")
    p_st.set_defaults(func=cmd_status)

    # config (get/set)
    p_cfg = sub.add_parser("config", help="Show or update bot config")
    p_cfg.add_argument("name")
    p_cfg.add_argument("--key", default=None, help="Config key to update")
    p_cfg.add_argument("--value", default=None, help="Config value to set")
    p_cfg.set_defaults(func=cmd_config)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
