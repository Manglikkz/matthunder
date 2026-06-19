import asyncio
import argparse
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import sys
import time
import zipfile
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction
from telegram.error import TelegramError, TimedOut
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

ROOT = Path(__file__).resolve().parent
MATTHUNDER = ROOT / "matthunder.py"
REPORT_DIR = ROOT / "bot_reports"
DB_PATH = str(ROOT / "matthunder_scans.db")
LOG_DIR = ROOT / "bot_logs"
REPORT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

DEFAULT_SPEED = os.getenv("MATTHUNDER_DEEP_SPEED", "standard").lower()
PYTHON_BIN = os.getenv("MATTHUNDER_PYTHON", sys.executable or "python")

try:
    import config as lazy_config
except Exception:
    lazy_config = None

# ── Multi-account: --bot-dir support ──────────────────────────────────
# Parse --bot-dir early before anything else uses the config.
_bot_arg_parser = argparse.ArgumentParser(add_help=False)
_bot_arg_parser.add_argument("--bot-dir", default=None,
    help="Path to a per-bot directory containing config.json + state/ + logs/")
_bot_dir_args, _remaining_argv = _bot_arg_parser.parse_known_args()
BOT_DIR = _bot_dir_args.bot_dir
sys.argv = [sys.argv[0]] + _remaining_argv  # Restore argv for later parsers

if BOT_DIR:
    BOT_DIR = Path(BOT_DIR).resolve()
    BOT_CONFIG = BOT_DIR / "config.json"
    if BOT_CONFIG.exists():
        try:
            with open(BOT_CONFIG, "r", encoding="utf-8") as _f:
                _cfg = json.load(_f)
        except Exception:
            _cfg = {}
    else:
        _cfg = {}

    # Redirect log, report, scan-output paths into the bot dir
    LOG_DIR = BOT_DIR / "logs"
    REPORT_DIR = BOT_DIR / "reports"
    DB_PATH = str(BOT_DIR / "matthunder_scans.db")
    _state_dir = BOT_DIR / "state"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _state_dir.mkdir(parents=True, exist_ok=True)

    # Read token & owner from config.json, then fall back to env / config.py
    _bot_token = (_cfg.get("token") or "").strip()
    _bot_owner = str(_cfg.get("owner_id") or _cfg.get("chat_id") or "0").strip()

    BOT_TOKEN = _bot_token or (os.getenv("MATTHUNDER_BOT_TOKEN") or getattr(lazy_config, "BOT_TOKEN", "") or "").strip()
    OWNER_ID = int(_bot_owner or os.getenv("MATTHUNDER_OWNER_ID") or getattr(lazy_config, "OWNER_ID",
                           getattr(lazy_config, "CHAT_ID", "0")) or "0")

    # Tell matthunder.py to write outputs inside this bot dir
    os.environ["MATTHUNDER_BOT_DIR"] = str(BOT_DIR)

    # ── Per-bot lock ────────────────────────────────────────────────
    _lock_file = _state_dir / "bot.lock"
    _heartbeat_file = _state_dir / "bot.heartbeat"

    def _pid_really_dead(pid):
        """Return True iff PID is definitely not alive.

        Uses taskkill /PID (without /F). If the PID exists, taskkill returns
        0 (and we then fully kill it). If the PID doesn't exist, taskkill
        returns 128 immediately — no hanging on zombie PIDs.
        """
        if not pid:
            return True
        try:
            _rc = subprocess.run(
                ["taskkill", "/PID", str(pid)],
                capture_output=True, timeout=3,
            )
            if _rc.returncode == 0:
                # PID was alive — fully kill it so startup is clean
                subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                               capture_output=True, timeout=3)
                return False
            return True
        except Exception:
            return True

    def _check_lock():
        """Single-instance guard: exit if another bot with same --bot-dir is alive."""
        if _lock_file.exists():
            try:
                _old = json.loads(_lock_file.read_text(encoding="utf-8") or "{}")
            except Exception:
                _old = {}
            _old_pid = _old.get("pid")
            if not _pid_really_dead(_old_pid):
                print(f"[bot] --bot-dir {BOT_DIR} already running as PID {_old_pid}. Exiting.", flush=True)
                sys.exit(0)
            # Stale lock
            _lock_file.unlink(missing_ok=True)
        _lock_file.write_text(
            json.dumps({"pid": os.getpid(), "started_at": time.time()}, ensure_ascii=False),
            encoding="utf-8",
        )

    def _clear_lock():
        try:
            _lock_file.unlink(missing_ok=True)
        except Exception:
            pass

    def _write_heartbeat():
        try:
            _heartbeat_file.write_text(str(int(time.time())), encoding="utf-8")
        except Exception:
            pass

    # Override the global heartbeat to use per-bot file
    HEARTBEAT_PATH = _heartbeat_file

    # Replace global MATTHUNDER reference so start_deep_scan runs with bot_dir as cwd
    MATTHUNDER = ROOT / "matthunder.py"

    _check_lock()
    import atexit
    atexit.register(_clear_lock)

else:
    # ── Legacy single-instance mode (no --bot-dir) ─────────────────
    BOT_CONFIG = None
    OWNER_ID = int(os.getenv("MATTHUNDER_OWNER_ID") or getattr(lazy_config, "OWNER_ID",
                           getattr(lazy_config, "CHAT_ID", "0")) or "0")
    BOT_TOKEN = (os.getenv("MATTHUNDER_BOT_TOKEN") or getattr(lazy_config, "BOT_TOKEN", "") or "").strip()
    HEARTBEAT_PATH = Path(os.getenv("TEMP", "/tmp")) / "matthunder_bot.heartbeat"

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("matthunder_deep_bot")

active_scan = {
    "process": None,
    "target": None,
    "started_at": None,
    "log_path": None,
    "message_id": None,
    "step": "Idle",
    "step_detail": "Belum ada scan berjalan.",
    "progress_pct": 0,
}

pending_target = {}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def is_owner(update: Update) -> bool:
    return bool(update.effective_user and int(update.effective_user.id) == OWNER_ID)


async def deny(update: Update):
    if update.message:
        await update.message.reply_text("⛔ Access denied. Bot ini private.")


def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    raw = raw.split("/")[0].split("?")[0].split("#")[0].strip().lower().rstrip(".")
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


def validate_target(target: str):
    if not target:
        return False, "Target kosong. Contoh: /deep example.com"
    if len(target) > 253 or not DOMAIN_RE.match(target):
        return False, "Format target tidak valid. Gunakan domain saja, contoh: example.com"
    blocked_exact = {"localhost", "local", "internal", "example.local"}
    if target in blocked_exact or target.endswith(".local") or target.endswith(".lan"):
        return False, "Target lokal/internal tidak diizinkan."
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False, "IP private/internal tidak diizinkan."
    except ValueError:
        pass
    return True, "OK"


def speed_from_args(args):
    if len(args) >= 2:
        speed = args[1].lower().strip()
        aliases = {"1": "low", "2": "standard", "3": "fast", "slow": "low", "std": "standard"}
        speed = aliases.get(speed, speed)
        if speed in {"low", "standard", "fast"}:
            return speed
    return DEFAULT_SPEED if DEFAULT_SPEED in {"low", "standard", "fast"} else "standard"


def scan_running() -> bool:
    p = active_scan.get("process")
    return p is not None and p.returncode is None


def clean_log_line(line: str) -> str:
    return ANSI_RE.sub("", line or "").strip()


def detect_scan_step_from_line(line: str):
    raw = clean_log_line(line)
    text = raw.lower()
    if not raw:
        return None, None, None

    # Skip Python stack traces / errors — they shouldn't count as scan step
    if "traceback" in text or "codec can't encode" in text or "unicodeencodeerror" in text:
        return None, None, None

    # Use matthunder's own printed stage/result lines as the visible status.
    stage_markers = [
        "starting process", "resuming process", "scan speed", "starting crawling",
        "starting active validation and crawling", "starting nuclei scan", "starting nuclei scans",
        "subfinder found", "assetfinder found", "successfully found", "httpx found",
        "waybackurls found", "gau found", "katana found", "active subdomains",
        "urls with parameter", "urls .js", "successfully collected urls",
        "nuclei (basic", "nuclei (js", "nuclei (dast", "nuclei (takeover", "nuclei scan",
        "unlimited mode enabled", "katana limit set", "nuclei scanning process completed",
        "all nuclei scans already completed", "nuclei scan already completed",
        "post-nuclei dast", "dalfox xss scan starting", "dalfox completed", "dalfox failed",
        "sqlmap sqli scan starting", "sqlmap completed", "sqlmap failed",
        "scan finished",
    ]
    tool_markers = ["subfinder", "assetfinder", "httpx", "wayback", "gau", "katana", "nuclei", "dalfox", "sqlmap"]
    # Avoid matching the bare word "error" (e.g. in tool output) — too noisy
    if any(m in text for m in stage_markers) or any(m in text for m in tool_markers):
        return raw[:700], classify_progress_from_tool_line(text), raw[:700]
    return None, None, None


def classify_progress_from_tool_line(text: str) -> int:
    if "starting process" in text or "scan speed" in text or "resuming process" in text:
        return 5
    if "subfinder found" in text:
        return 10
    if "assetfinder found" in text:
        return 14
    if "successfully found" in text and "subdomains" in text:
        return 20
    if "httpx found" in text and "subdomain" in text:
        return 30
    if "starting active validation" in text or "starting crawling" in text:
        return 38
    if "waybackurls found" in text:
        return 45
    if "gau found" in text:
        return 50
    if "active subdomains" in text:
        return 55
    if "katana found" in text or "katana limit" in text or "unlimited mode" in text:
        return 62
    if "httpx found" in text and "url active" in text:
        return 70
    if "urls with parameter" in text:
        return 74
    if "urls .js" in text or "javascript" in text:
        return 78
    if "successfully collected urls" in text:
        return 80
    if "nuclei (basic" in text:
        return 84
    if "nuclei (js" in text:
        return 88
    if "nuclei (dast" in text:
        return 92
    if "nuclei (takeover" in text:
        return 96
    if "starting nuclei" in text or "nuclei" in text:
        return 82
    if "completed" in text or "scan finished" in text or "successfully sent" in text:
        return 100
    if "failed" in text or "error" in text:
        return 90
    return 10


STAGE_FLOW = [
    ("start", "Starting process", ["starting process"]),
    ("subfinder", "Subfinder", ["subfinder found"]),
    ("assetfinder", "Assetfinder", ["assetfinder found"]),
    ("subdomains", "Combine/discovered subdomains", ["successfully found", "subdomains"]),
    ("active_subdomains", "Httpx active subdomains", ["httpx found", "subdomain active"]),
    ("wayback", "Waybackurls", ["waybackurls found"]),
    ("gau", "Gau", ["gau found"]),
    ("katana_limit", "Active subdomains selection", ["active subdomains"]),
    ("katana", "Katana", ["katana found"]),
    ("active_urls", "Httpx active URLs", ["httpx found", "url active"]),
    ("params", "URLs with parameter", ["successfully found", "urls with parameter"]),
    ("js", "URLs .js", ["successfully found", "urls .js"]),
    ("collected", "Collected URLs summary", ["successfully collected urls"]),
    ("nuclei_basic", "Nuclei (Basic scan)", ["nuclei (basic"]),
    ("nuclei_js", "Nuclei (JS scan)", ["nuclei (js"]),
    ("nuclei_dast", "Nuclei (DAST scan)", ["nuclei (dast"]),
    ("nuclei_takeover", "Nuclei (Takeover scan)", ["nuclei (takeover"]),
    ("dast_dalfox", "Dalfox XSS scan", ["dalfox xss scan starting", "dalfox completed", "dalfox failed"]),
    ("dast_sqlmap", "Sqlmap SQLi scan", ["sqlmap sqli scan starting", "sqlmap completed", "sqlmap failed"]),
]


def line_matches_stage(text: str, required):
    return all(part in text for part in required)


def analyze_stage_flow_from_log():
    log_path = active_scan.get("log_path")
    result = {
        "completed": set(),
        "current_index": 0,
        "stage_lines": {},
        "last_stage_line": "",
    }
    if not log_path or not Path(log_path).exists():
        return result
    try:
        lines = Path(log_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return result

    for line in lines:
        raw = clean_log_line(line)
        text = raw.lower()
        if not raw:
            continue
        for idx, (key, _label, required) in enumerate(STAGE_FLOW):
            if key not in result["completed"] and line_matches_stage(text, required):
                result["completed"].add(key)
                result["stage_lines"][key] = raw[:700]
                result["last_stage_line"] = raw[:700]
                result["current_index"] = min(idx + 1, len(STAGE_FLOW) - 1)

    # Do not skip stages visually: current is the first stage not yet completed.
    for idx, (key, _label, _required) in enumerate(STAGE_FLOW):
        if key not in result["completed"]:
            result["current_index"] = idx
            break
    else:
        result["current_index"] = len(STAGE_FLOW)
    return result


def build_stage_checklist(max_items: int = 20):
    analysis = analyze_stage_flow_from_log()
    completed = analysis["completed"]
    current_index = analysis["current_index"]
    lines = []
    for idx, (key, label, _required) in enumerate(STAGE_FLOW[:max_items]):
        real_line = analysis["stage_lines"].get(key)
        if key in completed:
            # Completed lines are shown exactly as matthunder printed them.
            lines.append(f"✅ {real_line or label}")
        elif idx == current_index:
            lines.append(f"🔄 Waiting for: {label}")
        else:
            lines.append(f"⏳ {label}")
    if analysis["last_stage_line"]:
        pct = classify_progress_from_tool_line(analysis["last_stage_line"].lower())
    else:
        pct = int((len(completed) / max(1, len(STAGE_FLOW))) * 100)
    return lines, pct, analysis


def update_scan_step_from_log_tail(max_lines: int = 80):
    lines, pct, analysis = build_stage_checklist()
    prev_step = active_scan.get("step")
    active_scan["progress_pct"] = pct
    if analysis.get("last_stage_line"):
        new_step = analysis["last_stage_line"]
        if new_step != prev_step:
            active_scan["step_started_at"] = time.time()
        active_scan["step"] = new_step
        active_scan["step_detail"] = "Mengikuti urutan tahapan asli matthunder."
        active_scan["last_log_line"] = new_step
        _save_scan_state()
        return

    log_path = active_scan.get("log_path")
    if not log_path or not Path(log_path).exists():
        return
    try:
        raw_lines = Path(log_path).read_text(encoding="utf-8", errors="ignore").splitlines()[-max_lines:]
    except Exception:
        return
    for line in reversed(raw_lines):
        step, pct2, raw = detect_scan_step_from_line(line)
        if step:
            if step != prev_step:
                active_scan["step_started_at"] = time.time()
            active_scan["step"] = step
            active_scan["step_detail"] = "Mengikuti tahapan/output asli dari matthunder."
            active_scan["progress_pct"] = pct2
            active_scan["last_log_line"] = raw
            _save_scan_state()
            return


def progress_bar_for_step(step: str) -> str:
    pct = int(active_scan.get("progress_pct") or (5 if scan_running() else 0))
    pct = max(0, min(100, pct))
    filled = max(0, min(10, pct // 10))
    return "█" * filled + "░" * (10 - filled) + f" {pct}%"


CLEANABLE_FOLDERS = [
    "subdomain", "active", "crawled", "crawled_filtered", "nuclei",
    "take_over", "sensitive_data", "output", "results", "reports",
    "bot_logs", "bot_reports", "__pycache__"
]


def human_size(num: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def clean_outputs(days: int = 7, clean_all: bool = False):
    cutoff = time.time() - (days * 86400)
    removed_files = 0
    removed_bytes = 0
    skipped = []
    for folder in CLEANABLE_FOLDERS:
        base = ROOT / folder
        if not base.exists():
            continue
        for p in sorted(base.rglob("*"), reverse=True):
            try:
                if p.is_file():
                    should_delete = clean_all or p.stat().st_mtime < cutoff or folder == "__pycache__"
                    if should_delete:
                        size = p.stat().st_size
                        p.unlink()
                        removed_files += 1
                        removed_bytes += size
                elif p.is_dir() and not any(p.iterdir()):
                    p.rmdir()
            except Exception as e:
                skipped.append(f"{p}: {e}")
    return removed_files, removed_bytes, skipped[:5]


def output_candidates_for_target(target: str):
    safe_parts = {target, target.replace(".", "_"), target.replace(".", "-")}
    folders = [
        "subdomain", "active", "crawled", "crawled_filtered", "nuclei",
        "take_over", "sensitive_data", "output", "results", "reports"
    ]
    found = []
    for folder in folders:
        base = ROOT / folder
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()
            if any(part.lower() in name for part in safe_parts):
                found.append(p)
    log_path = active_scan.get("log_path")
    if log_path and Path(log_path).exists():
        found.append(Path(log_path))
    return sorted(set(found))




def nuclei_files_for_target(target: str):
    safe_parts = {target, target.replace(".", "_"), target.replace(".", "-")}
    base = ROOT / "nuclei"
    if not base.exists():
        return []
    files = []
    for p in base.rglob("*"):
        if p.is_file() and any(part.lower() in p.name.lower() for part in safe_parts):
            files.append(p)
    return sorted(files)


def build_nuclei_summary(target: str, max_lines: int = 35, max_chars: int = 3500) -> str:
    files = nuclei_files_for_target(target)
    if not files:
        return ""

    findings = []
    for file_path in files:
        try:
            for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line:
                    findings.append(line)
        except Exception:
            continue

    if not findings:
        return "📭 Nuclei result kosong. Tidak ada finding yang tertulis di file nuclei."

    total = len(findings)
    shown = findings[:max_lines]
    body = "\n".join(f"• {line}" for line in shown)
    msg = (
        "🧪 Nuclei Findings\n\n"
        f"🎯 Target: {target}\n"
        f"📌 Total lines: {total}\n\n"
        f"{body}"
    )
    if total > len(shown):
        msg += f"\n\n...dan {total - len(shown)} baris lain. Detail lengkap ada di ZIP report."
    if len(msg) > max_chars:
        msg = msg[:max_chars - 120].rstrip() + "\n\n...dipotong karena batas Telegram. Detail lengkap ada di ZIP report."
    return msg


def make_report_zip(target: str) -> Path | None:
    files = output_candidates_for_target(target)
    if not files:
        return None
    ts = time.strftime("%Y%m%d_%H%M%S")
    zip_path = REPORT_DIR / f"deep_scan_{target}_{ts}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            try:
                z.write(p, p.relative_to(ROOT))
            except Exception:
                z.write(p, p.name)
    return zip_path


def main_menu_keyboard():
    """New 5+1 button top-level menu."""
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Tambah Target", callback_data="app:target")],
        [InlineKeyboardButton("▶️ Mulai Scan", callback_data="app:scan")],
        [InlineKeyboardButton("📊 Hasil Scan", callback_data="app:hasil")],
        [InlineKeyboardButton("🤖 AI Assistant", callback_data="app:ai")],
        [InlineKeyboardButton("⚙️ Setup", callback_data="setup:home"),
         InlineKeyboardButton("📖 Tutorial", callback_data="app:tutorial")],
    ])


def status_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Refresh", callback_data="menu_status")],
        [InlineKeyboardButton("📄 View Log", callback_data="menu_log"),
         InlineKeyboardButton("⛔ Stop Scan", callback_data="menu_stop")],
        [InlineKeyboardButton("📦 Latest Report", callback_data="menu_report")],
        [InlineKeyboardButton("⬅️ Main Menu", callback_data="menu_home")],
    ])


def clean_confirm_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🧹 Clean Old >7 Hari", callback_data="clean_confirm")],
        [InlineKeyboardButton("🔥 Clean All Output", callback_data="clean_all_confirm")],
        [InlineKeyboardButton("❌ Cancel", callback_data="menu_home")],
    ])


def app_home_text() -> str:
    """Welcome / main menu description (HTML formatted)."""
    return (
        "<pre>"
        "███╗   ███╗ █████╗ ████████╗████████╗██╗  ██╗██╗   ██╗███╗   ██╗██████╗ ███████╗██████╗\n"
        "████╗ ████║██╔══██╗╚══██╔══╝╚══██╔══╝██║  ██║██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗\n"
        "██╔████╔██║███████║   ██║      ██║   ███████║██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝\n"
        "██║╚██╔╝██║██╔══██║   ██║      ██║   ██╔══██║██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗\n"
        "██║ ╚═╝ ██║██║  ██║   ██║      ██║   ██║  ██║╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║\n"
        "╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝"
        "</pre>\n"
        "🦅 <b>Recon &amp; Vuln Bot</b>\n\n"
        "Bot ini ngejalanin matthunder scanner (subfinder, httpx, nuclei, dalfox, dll) "
        "plus integrasi Acunetix (kalau di-setup) — langsung dari Telegram.\n\n"
        "Cocok buat:\n"
        "• Bug bounty hunter: tambah target → scan → lihat vuln\n"
        "• Pentest: monitor Acunetix dashboard di HP\n"
        "• Personal recon automation\n\n"
        "Pilih aksi di bawah ⬇️"
    )


async def send_main_menu(message_obj):
    """Send main menu as a banner image + caption with buttons.
    Image sidesteps Telegram's monospace rendering issues with ASCII art.
    """
    try:
        from matthunder_banner import get_banner_bytes
        photo = get_banner_bytes()
        await message_obj.reply_photo(
            photo=photo,
            caption=(
                "🦅 <b>Recon &amp; Vuln Bot</b>\n\n"
                "Bot ini ngejalanin matthunder scanner (subfinder, httpx, nuclei, dalfox, dll) "
                "plus integrasi Acunetix (kalau di-setup) — langsung dari Telegram.\n\n"
                "Cocok buat:\n"
                "• Bug bounty hunter: tambah target → scan → lihat vuln\n"
                "• Pentest: monitor Acunetix dashboard di HP\n"
                "• Personal recon automation\n\n"
                "Pilih aksi di bawah ⬇️"
            ),
            parse_mode="HTML",
            reply_markup=main_menu_keyboard(),
        )
    except Exception:
        # Fallback to plain text if banner module not available
        await message_obj.reply_text(
            app_home_text(), parse_mode="HTML",
            reply_markup=main_menu_keyboard(),
        )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    await send_main_menu(update.message)


# ─── New top-level app flows (Target / Scan / Hasil / Tutorial) ──────────────

APP_STATE = "app_state"  # per-user state for flows awaiting input


def _app_state(context) -> dict:
    s = context.user_data.get(APP_STATE)
    if not s:
        s = {}
        context.user_data[APP_STATE] = s
    return s


async def _send(query, text, reply_markup=None, parse_mode="Markdown"):
    """Edit current message (preferred) or send new — never crash on BadRequest."""
    try:
        await query.message.edit_text(text, parse_mode=parse_mode, reply_markup=reply_markup)
    except TelegramError:
        await query.message.reply_text(text, parse_mode=parse_mode, reply_markup=reply_markup)


def back_to_main_button() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
    ])


# ─── Tambah Target ───────────────────────────────────────────────────────────

def target_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add Target", callback_data="app:target:add")],
        [InlineKeyboardButton("📋 List All Targets", callback_data="app:target:list")],
        [InlineKeyboardButton("▶️ Mulai Scan", callback_data="app:scan")],
        [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
    ])


def matthunder_targets_keyboard(targets: list[dict]) -> InlineKeyboardMarkup:
    """targets: list of dicts {name, addresses, notes, created_at}"""
    rows: list[list[InlineKeyboardButton]] = []
    for t in targets[:30]:
        name = t.get("name", "?")
        rows.append([InlineKeyboardButton(f"🎯 {name[:40]}", callback_data=f"app:target:info:{name}")])
    rows.append([InlineKeyboardButton("➕ Add Target", callback_data="app:target:add")])
    rows.append([InlineKeyboardButton("⬅️ Target Menu", callback_data="app:target")])
    return InlineKeyboardMarkup(rows)


def _read_targets() -> list[dict]:
    """Read neutral target registry (targets.json)."""
    p = ROOT / "targets.json"
    if not p.exists():
        return []
    try:
        import json as _json
        with open(p, "r", encoding="utf-8") as f:
            return _json.load(f)
    except Exception:
        return []


def _write_targets(targets: list[dict]) -> bool:
    p = ROOT / "targets.json"
    try:
        import json as _json
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            _json.dump(targets, f, indent=2, ensure_ascii=False)
        os.replace(tmp, p)
        return True
    except Exception:
        return False


def _read_matthunder_targets() -> list[str]:
    """Read legacy matthunder targets from subdomain/*.txt (kept for backward compat)."""
    sub_dir = ROOT / "subdomain"
    if not sub_dir.exists():
        return []
    out = []
    for f in sorted(sub_dir.glob("*.txt")):
        if f.stem.startswith("."):
            continue
        out.append(f.stem)
    return out


def _read_matthunder_subdomains(target: str) -> list[str]:
    p = ROOT / "subdomain" / f"{target}.txt"
    if not p.exists():
        return []
    try:
        return [line.strip() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
    except Exception:
        return []


async def app_target_menu(query, context):
    targets = _read_targets()
    n = len(targets)
    mat_targets = _read_matthunder_targets()
    nm = len(mat_targets)
    text = (
        "🎯 *Targets*\n\n"
        f"Registry: *{n}* target(s) di `targets.json`\n"
        f"Legacy subdomain files: *{nm}* di `subdomain/`\n\n"
        "Target di sini sifatnya *netral* — bisa di-scan pakai matthunder, Acunetix, atau AI Parser.\n"
        "Pilih engine nanti di menu ▶️ Mulai Scan."
    )
    await _send(query, text, target_menu_keyboard())


async def app_target_add(query, context):
    s = _app_state(context)
    s["flow"] = "add_target"
    s["step"] = "name"
    await _send(
        query,
        "➕ *Add Target*\n\n"
        "Kirim nama target (FQDN only, tanpa path).\n"
        "Contoh: `example.com` atau `app.example.com`\n\n"
        "Target akan disimpan di registry `targets.json` + otomatis bikin `subdomain/<target>.txt` kosong.\n\n"
        "Engine scan (matthunder / Acunetix) dipilih nanti di ▶️ Mulai Scan.\n\n"
        "Ketik /cancel untuk batal.",
        back_to_main_button(),
    )


async def app_target_list(query, context):
    targets = _read_targets()
    mat_targets = _read_matthunder_targets()
    # Merge: registry first, then legacy files not in registry
    registry_names = {t.get("name", "") for t in targets}
    extras = [{"name": n, "addresses": [], "notes": "(legacy subdomain file)", "created_at": ""} for n in mat_targets if n not in registry_names]
    all_targets = targets + extras
    if not all_targets:
        await _send(
            query,
            "📋 Belum ada target.\n\nKlik ➕ Add Target dulu.",
            target_menu_keyboard(),
        )
        return
    lines = [f"📋 *All Targets* ({len(all_targets)})\n"]
    for i, t in enumerate(all_targets[:50], 1):
        name = t.get("name", "?")
        notes = t.get("notes", "")
        line = f"{i}. `{_esc(name)}`"
        if notes:
            line += f" — _{_esc(notes[:50])}_"
        lines.append(line)
    if len(all_targets) > 50:
        lines.append(f"\n… {len(all_targets) - 50} more")
    text = "\n".join(lines)
    await _send(query, text, matthunder_targets_keyboard(all_targets))


async def app_target_info(query, context, target: str):
    """Show target detail + actions (scan / delete)."""
    # Find in registry
    target_obj = None
    for t in _read_targets():
        if t.get("name") == target:
            target_obj = t
            break
    subs = _read_matthunder_subdomains(target)
    sub_count = len(subs)
    if target_obj:
        text = (
            f"🎯 *Target `{_esc(target)}`*\n\n"
            f"Subdomains on file: *{sub_count}*\n"
            f"Notes: _{_esc(target_obj.get('notes', '(none)'))}_\n"
            f"Created: `{_esc(target_obj.get('created_at', '-'))}`\n"
        )
    else:
        text = (
            f"🎯 *Target `{_esc(target)}`*\n\n"
            f"Subdomains on file: *{sub_count}* (legacy subdomain/ file only)\n"
        )
    if subs:
        sample = ", ".join(subs[:5])
        text += f"Sample: `{_esc(sample)}`{'…' if sub_count > 5 else ''}\n"
    text += f"\nFile: `subdomain/{_esc(target)}.txt`"
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("▶️ Scan this target", callback_data=f"app:scan:startmat:{target}")],
        [InlineKeyboardButton("🗑️ Delete", callback_data=f"app:target:del:{target}")],
        [InlineKeyboardButton("⬅️ Target Menu", callback_data="app:target")],
    ])
    await _send(query, text, kb)


async def app_target_del(query, context, target: str):
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Yes, delete", callback_data=f"app:target:del_yes:{target}"),
         InlineKeyboardButton("❌ Cancel", callback_data=f"app:target:info:{target}")],
    ])
    await _send(
        query,
        f"🗑️ Delete target `{_esc(target)}`?\n\n"
        "Registry entry + `subdomain/<target>.txt` (kalau ada) bakal dihapus.",
        kb,
    )


async def app_target_del_yes(query, context, target: str):
    # Remove from registry
    targets = _read_targets()
    targets = [t for t in targets if t.get("name") != target]
    _write_targets(targets)
    # Remove subdomain file if exists
    p = ROOT / "subdomain" / f"{target}.txt"
    if p.exists():
        try:
            p.unlink()
        except Exception:
            pass
    await _send(
        query,
        f"✅ Target `{_esc(target)}` deleted.",
        target_menu_keyboard(),
    )


# ─── Mulai Scan ──────────────────────────────────────────────────────────────

def scan_mode_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🛠 matthunder (Deep Scan)", callback_data="app:scan:mat")],
        [InlineKeyboardButton("🦅 Acunetix", callback_data="app:scan:acx")],
        [InlineKeyboardButton("🧠 AI Parser (NL→CLI)", callback_data="app:ai:parse")],
        [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
    ])


def matthunder_speed_keyboard(target: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🐢 Thorough", callback_data=f"app:scan:domat:{target}:low"),
         InlineKeyboardButton("⚖️ Standard", callback_data=f"app:scan:domat:{target}:standard")],
        [InlineKeyboardButton("🚀 Fast", callback_data=f"app:scan:domat:{target}:fast"),
         InlineKeyboardButton("⚡ Quick (CVE only)", callback_data=f"app:scan:domat:{target}:quick")],
        [InlineKeyboardButton("⬅️ Scan Menu", callback_data="app:scan")],
    ])


async def app_scan_menu(query, context):
    text = (
        "▶️ *Mulai Scan*\n\n"
        "Pilih engine:\n"
        "• *🛠 matthunder* — Full pipeline (subfinder + httpx + nuclei + dalfox). "
        "Output: subdomain/, results/, ZIP report.\n"
        "• *🦅 Acunetix* — Web vuln scanner (kalau sudah di-setup). "
        "Output: vuln list by severity + Acunetix dashboard.\n"
    )
    await _send(query, text, scan_mode_keyboard())


async def app_scan_mat(query, context):
    # Use neutral target registry (targets.json) + legacy subdomain files
    registry = _read_targets()
    registry_names = {t.get("name", "") for t in registry}
    legacy = [n for n in _read_matthunder_targets() if n not in registry_names]
    target_names = [t["name"] for t in registry] + legacy
    if not target_names:
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("➕ Add Target dulu", callback_data="app:target:add")],
            [InlineKeyboardButton("✏️ Ketik domain langsung", callback_data="app:scan:matcustom")],
            [InlineKeyboardButton("⬅️ Scan Menu", callback_data="app:scan")],
        ])
        await _send(
            query,
            "▶️ *Mulai Scan — matthunder*\n\n"
            "Belum ada target. Klik ➕ Add Target dulu, "
            "atau ketik domain langsung.",
            kb,
        )
        return
    text = "▶️ *Mulai Scan — matthunder*\n\nPilih target:"
    rows: list[list[InlineKeyboardButton]] = []
    for t in target_names[:20]:
        rows.append([InlineKeyboardButton(f"🎯 {t[:40]}", callback_data=f"app:scan:speedmat:{t}")])
    rows.append([InlineKeyboardButton("✏️ Custom domain", callback_data="app:scan:matcustom")])
    rows.append([InlineKeyboardButton("⬅️ Scan Menu", callback_data="app:scan")])
    await _send(query, text, InlineKeyboardMarkup(rows))


async def app_scan_matcustom(query, context):
    s = _app_state(context)
    s["flow"] = "scan_mat"
    s["step"] = "domain"
    await _send(
        query,
        "▶️ *Custom domain scan*\n\nKirim domain target sekarang.\nContoh: `example.com`\n\n/cancel untuk batal.",
        back_to_main_button(),
    )


async def app_scan_speed_mat(query, context, target: str):
    text = (
        f"▶️ *Deep Scan: `{_esc(target)}`*\n\n"
        "Pilih speed:\n"
        "• 🐢 Low — thorough, anti-ban (best for prod)\n"
        "• ⚖️ Standard — balanced\n"
        "• 🚀 Fast — speed first"
    )
    await _send(query, text, matthunder_speed_keyboard(target))


async def app_scan_do_mat(query, context, target: str, speed: str):
    """Trigger actual deep scan subprocess via matthunder.py."""
    ok, msg = validate_target(target)
    if not ok:
        await _send(query, f"❌ {msg}", matthunder_speed_keyboard(target))
        return
    if speed not in {"low", "standard", "fast", "quick"}:
        speed = "standard"
    is_quick = (speed == "quick")
    if scan_running():
        await _send(
            query,
            f"⚠️ Masih ada scan berjalan.\nTarget: `{_esc(str(active_scan.get('target')))}`\nStop dulu via Main Menu.",
            back_to_main_button(),
        )
        return
    # Start scan
    pending_target.pop(OWNER_ID, None)
    log_path = LOG_DIR / f"deep_{target}_{time.strftime('%Y%m%d_%H%M%S')}.log"
    # For quick mode, run with "fast" speed but tell matthunder to skip non-CVE scans
    matthunder_speed = "fast" if is_quick else speed
    cmd = [PYTHON_BIN, str(MATTHUNDER), "-dps", "-t", target, "-s", matthunder_speed, "-ar"]
    try:
        log_f = open(log_path, "w", encoding="utf-8", errors="replace")
        # Force UTF-8 stdout in subprocess to avoid cp1252 crash on emoji prints
        sub_env = os.environ.copy()
        sub_env["PYTHONIOENCODING"] = "utf-8"
        sub_env["PYTHONUTF8"] = "1"
        if is_quick:
            sub_env["MATTHUNDER_QUICK_MODE"] = "1"
            sub_env["MATTHUNDER_SKIP_DAST"] = "1"  # quick mode also skips Dalfox + Sqlmap
        # Pass scan log path so background DAST thread can append progress
        sub_env["MATTHUNDER_SCAN_LOG"] = str(log_path)
        proc = subprocess.Popen(
            cmd, stdout=log_f, stderr=subprocess.STDOUT,
            cwd=str(BOT_DIR or ROOT), env=sub_env,
        )
    except Exception as e:
        await _send(query, f"❌ Gagal start scan: `{_esc(str(e)[:200])}`", back_to_main_button())
        return
    active_scan.update({
        "process": proc,
        "target": target,
        "started_at": time.time(),
        "log_path": str(log_path),
        "message_id": query.message.message_id,
        "chat_id": query.message.chat_id,
        "step": "🚀 Starting",
        "step_detail": f"matthunder -dps -t {target} -s {matthunder_speed}" + (" [QUICK MODE]" if is_quick else ""),
        "progress_pct": 0,
    })
    speed_label = "⚡ Quick (CVE only, fastest)" if is_quick else speed
    quick_note = "\n⚠️ _Quick mode: skip JS / DAST / takeover — only CVE + default-login nuclei._" if is_quick else ""
    # Send a NEW status message that will be auto-refreshed
    status_msg = await query.message.reply_text(
        f"🚀 *Deep Scan started*\n\n"
        f"🎯 Target: `{_esc(target)}`\n"
        f"⏱ Speed: {speed_label}\n"
        f"📄 Log: `{log_path.name}`\n"
        f"🕐 Started: `{time.strftime('%H:%M:%S')}`\n"
        f"{quick_note}\n\n"
        "⏳ _Auto-refresh aktif tiap 30s. Lo ga perlu klik manual._\n"
        "📩 Notifikasi akan dikirim saat scan selesai.",
        reply_markup=status_keyboard(),
    )
    active_scan["status_message_id"] = status_msg.message_id
    # Spawn background auto-refresh + completion notifier
    asyncio.create_task(_scan_autorefresh_and_notify(
        context=context, chat_id=query.message.chat_id,
        status_msg_id=status_msg.message_id,
        target=target, log_path=str(log_path), started_at=time.time(),
    ))


async def _scan_autorefresh_and_notify(
    context, chat_id: int, status_msg_id: int,
    target: str, log_path: str, started_at: float,
    interval_s: int = 30,
):
    """Background task: refresh status message every interval_s, then send
    completion notification with summary + write to DB.
    """
    # Save scan to DB at start (status='running')
    scan_id = _track_scan_start(target, log_path)
    try:
        while True:
            await asyncio.sleep(interval_s)
            if not active_scan.get("process") or active_scan.get("target") != target:
                # Scan was stopped or replaced
                return
            proc = active_scan["process"]
            if proc.poll() is not None:
                # Process exited
                break
            # Build status text + edit
            try:
                text = build_status_text()
                kb = status_keyboard()
                await context.bot.edit_message_text(
                    chat_id=chat_id, message_id=status_msg_id,
                    text=text, reply_markup=kb,
                )
            except TelegramError:
                pass
            except Exception:
                pass
        # Scan finished
        await asyncio.sleep(2)  # let matthunder flush
        # Read final status
        final_text = build_status_text()
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id, message_id=status_msg_id,
                text=final_text, reply_markup=status_keyboard(),
            )
        except Exception:
            pass
        # Build summary
        proc = active_scan.get("process")
        rc = proc.returncode if proc else -1
        # Count findings in sub-scanner DB rows
        findings_count = _count_target_findings(target)
        # ZIP path
        zips = sorted(REPORT_DIR.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        zip_name = zips[0].name if zips else None
        duration = int(time.time() - started_at)
        # Update DB row
        _track_scan_finish(scan_id, target, rc, duration, findings_count)
        # Send notification
        notif = (
            f"{'✅' if rc == 0 else '⚠️'} *Scan selesai* — `{_esc(target)}`\n\n"
            f"⏱ Duration: `{duration}s`\n"
            f"📊 Findings: *{findings_count}*\n"
            f"📄 Log: `{Path(log_path).name}`\n"
        )
        if zip_name:
            notif += f"📦 Report: `{zip_name}`\n"
        notif += f"\nLihat 📊 Hasil Scan di Main Menu."
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("📊 Lihat Hasil", callback_data="app:hasil")],
            [InlineKeyboardButton("📦 Download Report", callback_data="menu_report")],
            [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
        ])
        try:
            await context.bot.send_message(
                chat_id=chat_id, text=notif, parse_mode="Markdown", reply_markup=kb,
            )
        except Exception as e:
            logger.warning("send completion notif failed: %s", e)
    except asyncio.CancelledError:
        # Scan stopped manually — write partial state
        _track_scan_finish(scan_id, target, -1, int(time.time() - started_at), 0)
        try:
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"⛔ Scan stopped — `{_esc(target)}`",
                reply_markup=back_to_main_button(),
            )
        except Exception:
            pass
    finally:
        # Cleanup
        if active_scan.get("target") == target:
            active_scan.update({
                "process": None, "target": None, "started_at": None,
                "log_path": None, "message_id": None, "chat_id": None,
                "status_message_id": None,
                "step": "Idle", "step_detail": "Belum ada scan berjalan.", "progress_pct": 0,
            })


def _track_scan_start(target: str, log_path: str):
    """Insert a 'deep' row into matthunder_scans.db so it shows in history."""
    try:
        from scanners.common import open_db, utc_now_iso
        con = open_db()
        row_id = con.execute(
            "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
            "VALUES (lower(hex(randomblob(16))), 'deep', ?, ?, 'running', ?)",
            (target, log_path, utc_now_iso()),
        ).lastrowid
        con.commit()
        sid = con.execute("SELECT id FROM scans WHERE rowid=?", (row_id,)).fetchone()["id"]
        con.close()
        return sid
    except Exception as e:
        logger.warning("_track_scan_start failed: %s", e)
        return None


def _track_scan_finish(scan_id, target, rc: int, duration: int, findings_count: int):
    if not scan_id:
        return
    try:
        from scanners.common import open_db, utc_now_iso
        con = open_db()
        status = "completed" if rc == 0 else "failed"
        # Sum finding count into total_links
        cur = con.execute("SELECT total_links FROM scans WHERE id=?", (scan_id,)).fetchone()
        existing = (cur["total_links"] or 0) if cur else 0
        total = max(existing, findings_count)
        con.execute(
            "UPDATE scans SET status=?, finished_at=?, total_sources=?, total_links=? WHERE id=?",
            (status, utc_now_iso(), duration, total, scan_id),
        )
        con.commit()
        con.close()
    except Exception as e:
        logger.warning("_track_scan_finish failed: %s", e)


def _count_target_findings(target: str) -> int:
    """Count total findings (results rows) for a target in DB."""
    try:
        from scanners.common import open_db
        con = open_db()
        n = con.execute(
            "SELECT COUNT(*) AS c FROM results WHERE target_url LIKE ? OR source_url LIKE ?",
            (f"%{target}%", f"%{target}%"),
        ).fetchone()["c"]
        con.close()
        return n
    except Exception:
        return 0


async def app_scan_acx(query, context):
    # Delegate to Acunetix main menu (existing flow)
    await acx_show_main(query, context)


# ─── Hasil Scan ──────────────────────────────────────────────────────────────

async def app_hasil_menu(query, context):
    rows: list[list[InlineKeyboardButton]] = []
    # Local DB history
    rows.append([InlineKeyboardButton("📋 Scan History (DB)", callback_data="app:hasil:history")])
    rows.append([InlineKeyboardButton("📦 Latest ZIP Report", callback_data="menu_report")])
    rows.append([InlineKeyboardButton("🧹 Clean Old Reports", callback_data="menu_clean")])
    # Acunetix dashboard if configured
    try:
        import user_config
        s = user_config.status()
        if s["acunetix"]["configured"]:
            rows.append([InlineKeyboardButton("🦅 Acunetix Dashboard", callback_data="acx:summary")])
            rows.append([InlineKeyboardButton("📋 Acunetix Scans", callback_data="acx:list")])
    except Exception:
        pass
    rows.append([InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")])
    text = (
        "📊 *Hasil Scan*\n\n"
        "Semua hasil scan (matthunder + Acunetix) ada di sini.\n"
        "Pilih yang mau dilihat:"
    )
    await _send(query, text, InlineKeyboardMarkup(rows))


async def app_hasil_history(query, context):
    """Show local DB scan history."""
    if not os.path.exists(DB_PATH):
        await _send(query, "❌ Database `matthunder_scans.db` belum ada.", app_hasil_menu_kb())
        return
    try:
        import sqlite3
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT id, scanner, domain, status, total_sources, total_links, "
            "created_at, finished_at "
            "FROM scans ORDER BY created_at DESC LIMIT 30"
        ).fetchall()
        con.close()
    except Exception as e:
        await _send(query, f"❌ DB read failed: `{_esc(str(e)[:200])}`", app_hasil_menu_kb())
        return
    if not rows:
        await _send(query, "📋 No scans yet. Jalankan scan dulu.", app_hasil_menu_kb())
        return
    lines = ["📋 *Scan History* (latest 30)\n"]
    for r in rows:
        scanner = r["scanner"] or "?"
        domain = r["domain"] or "?"
        status = r["status"] or "?"
        total = r["total_links"] or 0
        created = (r["created_at"] or "")[:16]
        status_icon = "✅" if status == "completed" else ("🔄" if status == "running" else "❌")
        lines.append(
            f"{status_icon} `{scanner}` → `{_esc(domain[:30])}`\n"
            f"   hits: {total} | {_esc(created)}"
        )
    # List recent log files (so user can inspect a past scan)
    log_dir = ROOT / "bot_logs"
    if log_dir.exists():
        logs = sorted(log_dir.glob("deep_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:5]
        if logs:
            lines.append("\n📄 *Recent logs:*")
            for lp in logs:
                lines.append(f"  • `{lp.name}`")
    text = "\n".join(lines)
    if len(text) > TELEGRAM_MAX:
        text = text[:TELEGRAM_MAX] + "\n\n… (truncated)"
    await _send(query, text, app_hasil_menu_kb())


async def app_hasil_logs(query, context):
    """List recent bot_logs/deep_*.log files with view + delete buttons."""
    log_dir = ROOT / "bot_logs"
    if not log_dir.exists():
        await _send(query, "❌ Folder `bot_logs/` belum ada.", app_hasil_menu_kb())
        return
    logs = sorted(log_dir.glob("deep_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:20]
    if not logs:
        await _send(query, "❌ Belum ada log file.", app_hasil_menu_kb())
        return
    rows: list[list[InlineKeyboardButton]] = []
    lines = ["📂 *Recent log files*\n"]
    for lp in logs:
        size = lp.stat().st_size
        mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(lp.stat().st_mtime))
        size_str = f"{size//1024}KB" if size > 1024 else f"{size}B"
        lines.append(f"• `{_esc(lp.name)}`  {size_str}  {mtime}")
        rows.append([InlineKeyboardButton(f"📄 {lp.name[:40]}", callback_data=f"app:hasil:viewlog:{lp.name}")])
    rows.append([InlineKeyboardButton("⬅️ Back", callback_data="app:hasil")])
    text = "\n".join(lines)
    if len(text) > TELEGRAM_MAX:
        text = text[:TELEGRAM_MAX] + "\n… (truncated)"
    await _send(query, text, InlineKeyboardMarkup(rows))


async def app_hasil_viewlog(query, context, filename: str):
    """View tail of a log file."""
    log_path = ROOT / "bot_logs" / filename
    if not log_path.exists() or not filename.startswith("deep_") or "/" in filename or "\\" in filename:
        await _send(query, "❌ Log file tidak ditemukan.", app_hasil_menu_kb())
        return
    try:
        tail = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()[-30:]
    except Exception as e:
        await _send(query, f"❌ Read error: `{_esc(str(e)[:200])}`", app_hasil_menu_kb())
        return
    text = f"📄 *Log tail: `{_esc(filename)}`*\n\n```\n" + "\n".join(tail) + "\n```"
    if len(text) > 3500:
        text = text[:3500] + "\n… (truncated)"
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📦 Send Full Log as File", callback_data=f"app:hasil:sendlog:{filename}")],
        [InlineKeyboardButton("⬅️ Back to logs", callback_data="app:hasil:logs")],
    ])
    await _send(query, text, kb)


async def app_hasil_sendlog(query, context, filename: str):
    """Send log file as Telegram document."""
    log_path = ROOT / "bot_logs" / filename
    if not log_path.exists() or not filename.startswith("deep_") or "/" in filename or "\\" in filename:
        await _send(query, "❌ Log file tidak ditemukan.", app_hasil_menu_kb())
        return
    try:
        await query.message.reply_document(
            document=log_path.open("rb"),
            filename=filename,
            caption=f"📄 Log: {filename}",
        )
    except Exception as e:
        await _send(query, f"❌ Send error: `{_esc(str(e)[:200])}`", app_hasil_menu_kb())


def app_hasil_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Refresh", callback_data="app:hasil:history")],
        [InlineKeyboardButton("📂 Browse Log Files", callback_data="app:hasil:logs")],
        [InlineKeyboardButton("📦 Latest Report", callback_data="menu_report")],
        [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
    ])


# ─── Tutorial ────────────────────────────────────────────────────────────────

TUTORIAL_TEXT = (
    "📖 *Tutorial Matthunder Bot*\n\n"
    "*1. Tambah Target*\n"
    "Pilih mode:\n"
    "• *matthunder* — untuk full pipeline scan dari awal\n"
    "• *Acunetix* — kalau target mau di-scan via Acunetix (perlu setup API key dulu)\n\n"
    "*2. Mulai Scan*\n"
    "Pilih engine, target, dan speed:\n"
    "• 🐢 *Low* — thorough, anti-rate-limit\n"
    "• ⚖️ *Standard* — balanced\n"
    "• 🚀 *Fast* — quick win\n\n"
    "*3. Hasil Scan*\n"
    "Cek di:\n"
    "• 📋 *Scan History* — list semua scan di DB\n"
    "• 📦 *Latest Report* — ZIP report terakhir\n"
    "• 🦅 *Acunetix Dashboard* — kalau pakai Acunetix\n\n"
    "*4. Setup*\n"
    "Wajib setup sebelum pakai Acunetix:\n"
    "• 🦅 Acunetix URL + API key\n"
    "• 🤖 AI provider + key (opsional, untuk `--ai` parser)\n\n"
    "*Tips*\n"
    "• Selalu test di target yang kamu punya izin\n"
    "• Bot ini private (chat_id di `config.py`)\n"
    "• Scan output disimpan di `subdomain/`, `results/`, `matthunder_scans.db`\n"
    "• ZIP report auto-generated setelah scan selesai\n\n"
    "Butuh bantuan? Buka issue di GitHub atau lihat README."
)


async def app_tutorial(query, context):
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🌐 Open README", url="https://github.com/hmad28/matthunder")],
        [InlineKeyboardButton("⚙️ Setup sekarang", callback_data="setup:home")],
        [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
    ])
    await _send(query, TUTORIAL_TEXT, kb)


# ─── AI Assistant + AI Parse ─────────────────────────────────────────────────

AI_STATE = "ai_state"  # {flow: "chat"|"parse", pending: bool, parsed: {...}}


def _ai_state(context) -> dict:
    s = context.user_data.get(AI_STATE)
    if not s:
        s = {"flow": None, "pending": False, "parsed": None}
        context.user_data[AI_STATE] = s
    return s


def _ai_status_text(provider: str) -> str:
    try:
        import user_config
        cfg = user_config.get_ai()
        if cfg["provider"] and cfg["api_key"]:
            return f"✅ AI ready (provider: `{_esc(cfg['provider'])}`, model: `{_esc(cfg['model'] or 'default')}`)"
        return "❌ AI belum di-setup. Buka ⚙️ Setup → 🤖 AI Provider."
    except Exception:
        return "❌ AI status unknown."


def ai_menu_keyboard() -> InlineKeyboardMarkup:
    import ai_guard
    if not ai_guard.is_configured():
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("⚙️ Setup AI Provider", callback_data="setup:ai")],
            [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
        ])
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("💬 Chat dengan AI", callback_data="app:ai:chat")],
        [InlineKeyboardButton("🧠 AI Parser (NL→CLI)", callback_data="app:ai:parse")],
        [InlineKeyboardButton("⚙️ Setup AI", callback_data="setup:ai")],
        [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
    ])


async def app_ai_menu(query, context):
    import ai_guard
    status = _ai_status_text("") if ai_guard.is_configured() else "❌ AI belum di-setup"
    text = (
        "🤖 *AI Assistant*\n\n"
        f"Status: {status}\n\n"
        "Dua mode:\n"
        "• *💬 Chat* — Tanya jawab bebas dalam konteks security/bug bounty\n"
        "• *🧠 AI Parser* — Natural language → command matthunder (dengan konfirmasi dulu sebelum jalan)\n\n"
        "*🛡 Guardrails aktif:*\n"
        "• Topik di-lock ke bug bounty + security recon\n"
        "• Command injection di-block (rm -rf, curl|bash, dll)\n"
        "• Prompt injection di-reject\n"
        "• API key di-redact otomatis di output\n"
        "• Maks 1500 char input / 3500 char output\n\n"
        "Pilih mode."
    )
    await _send(query, text, ai_menu_keyboard())


async def app_ai_chat_prompt(query, context):
    s = _ai_state(context)
    s["flow"] = "chat"
    s["pending"] = True
    text = (
        "💬 *AI Chat Mode*\n\n"
        "Kirim pertanyaan / request lo sekarang.\n"
        "Contoh: `apa itu prototype pollution?` atau `cara nulis report bug yang bener`\n\n"
        "AI akan jawab dalam konteks security recon / bug bounty.\n"
        "Pertanyaan di luar topik akan otomatis di-refuse.\n\n"
        "Ketik /cancel untuk keluar."
    )
    await _send(query, text, back_to_main_button())


async def app_ai_parse_prompt(query, context):
    s = _ai_state(context)
    s["flow"] = "parse"
    s["pending"] = True
    text = (
        "🧠 *AI Parser Mode*\n\n"
        "Kirim perintah dalam bahasa natural, AI akan convert ke command matthunder.\n"
        "Contoh:\n"
        "• `deep scan example.com fast`\n"
        "• `acunetix list semua scan`\n"
        "• `xss test di api.target.com`\n"
        "• `subdomain takeover mass dari file targets.txt`\n\n"
        "AI akan generate command + preview. Lo **harus** klik ✅ Run untuk eksekusi.\n"
        "Tanpa konfirmasi, command TIDAK dijalankan.\n\n"
        "Ketik /cancel untuk keluar."
    )
    await _send(query, text, back_to_main_button())


async def app_ai_handle_chat(update, context, text: str):
    """Send user text to AI chat, return scrubbed response."""
    import ai_guard
    import user_config
    cfg = user_config.get_ai()
    if not cfg["provider"] or not cfg["api_key"]:
        await update.message.reply_text(
            "❌ AI belum di-setup. Buka ⚙️ Setup → 🤖 AI Provider.",
            reply_markup=ai_menu_keyboard(),
        )
        return
    await update.message.chat.send_action(ChatAction.TYPING)
    user_config.apply_env()  # ensure env vars are current
    res = ai_guard.chat_once(
        text,
        provider=cfg["provider"],
        api_key=cfg["api_key"],
        model=cfg["model"],
        timeout=45,
    )
    if not res.get("ok"):
        await update.message.reply_text(
            f"❌ {res.get('error', '?')}",
            reply_markup=ai_menu_keyboard(),
        )
        return
    response = res["text"]
    if len(response) > 3500:
        response = response[:3500] + "\n\n… (truncated)"
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Tanya lagi", callback_data="app:ai:chat")],
        [InlineKeyboardButton("🧠 AI Parser", callback_data="app:ai:parse")],
        [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
    ])
    await update.message.reply_text(response, reply_markup=kb)


async def app_ai_handle_parse(update, context, text: str):
    """Convert natural language to matthunder command, show preview + confirm gate."""
    import ai_guard
    import user_config
    cfg = user_config.get_ai()
    if not cfg["provider"] or not cfg["api_key"]:
        await update.message.reply_text(
            "❌ AI belum di-setup. Buka ⚙️ Setup → 🤖 AI Provider.",
            reply_markup=ai_menu_keyboard(),
        )
        return
    await update.message.chat.send_action(ChatAction.TYPING)
    user_config.apply_env()
    res = ai_guard.ai_parse_to_command(
        text,
        provider=cfg["provider"],
        api_key=cfg["api_key"],
        model=cfg["model"],
    )
    if not res.get("ok"):
        await update.message.reply_text(
            f"❌ {res.get('error', '?')}",
            reply_markup=ai_menu_keyboard(),
        )
        return
    s = _ai_state(context)
    s["parsed"] = res
    cmd = res["cmd_args"]
    preview = res["preview"]
    # Confirm gate
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Run", callback_data=f"app:ai:run:{_ai_state(context).get('id', 0)}")],
        [InlineKeyboardButton("❌ Cancel", callback_data="app:ai")],
    ])
    # Stash cmd_args in context for the Run callback
    context.user_data["_ai_last_cmd"] = cmd
    await update.message.reply_text(
        f"🧠 *AI Parsed Command*\n\n"
        f"```\n{preview}\n```\n"
        f"Args: `{_esc(str(cmd))}`\n\n"
        "Klik ✅ Run untuk eksekusi, ❌ Cancel untuk batal.",
        parse_mode="Markdown",
        reply_markup=kb,
    )


async def app_ai_run(query, context, cmd: list):
    """Execute the parsed command. For now, run via matthunder_cli.py."""
    import subprocess
    py = sys.executable
    script = str(ROOT / "matthunder_cli.py")
    full_cmd = [py, script] + list(cmd)
    # Safety: only allow known scans (already validated in ai_parse_to_command, double-check)
    allowed_prefixes = {
        "lts","dks","dps","tov","sens","blh","tpa","cred","apirecon","params",
        "ssti","cors","xss","sqli","lfi","crlf","openredirect","portscan","waf",
        "jsanalysis","fuzzer","techfingerprint","tech","gfpatterns","gf",
        "gate","validate","attackrank","rank","acunetix",
    }
    if not cmd or cmd[0] not in allowed_prefixes:
        await query.message.reply_text(
            "❌ Refused: unknown command",
            reply_markup=ai_menu_keyboard(),
        )
        return
    # Acunetix special: matthunder_cli.py handles "acunetix" as first arg
    # For other scans, pass the args; if first is just "acunetix", call with action
    # Run async with subprocess so we don't block the bot
    await query.message.reply_text(
        f"🚀 Running: `{_esc(' '.join(full_cmd))}`\n\n"
        "(output mungkin panjang, di-truncate untuk Telegram)",
    )
    try:
        proc = await asyncio.create_subprocess_exec(
            *full_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(BOT_DIR or ROOT),
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        except asyncio.TimeoutError:
            proc.kill()
            await query.message.reply_text(
                "⏱ Command timeout (180s).", reply_markup=ai_menu_keyboard(),
            )
            return
        out = stdout.decode("utf-8", errors="replace")
        # Strip ANSI
        out = ANSI_RE.sub("", out)
        if len(out) > 3000:
            out = out[:3000] + "\n\n… (truncated)"
        await query.message.reply_text(
            f"```\n{out}\n```",
            parse_mode="Markdown",
            reply_markup=ai_menu_keyboard(),
        )
    except Exception as e:
        await query.message.reply_text(
            f"❌ Run error: `{_esc(str(e)[:200])}`",
            reply_markup=ai_menu_keyboard(),
        )


# ─── Dispatcher ──────────────────────────────────────────────────────────────

async def app_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Single dispatcher for app:* callbacks (new top-level menu)."""
    query = update.callback_query
    if not is_owner(update):
        return await safe_query_answer(query, "Access denied", show_alert=True)
    await safe_query_answer(query)
    data = query.data or ""
    parts = data.split(":", 3)
    # app:target | app:scan | app:hasil | app:tutorial | app:home
    section = parts[1] if len(parts) > 1 else "home"
    action = parts[2] if len(parts) > 2 else None
    arg = parts[3] if len(parts) > 3 else None

    if data == "app:home" or section == "home":
        # Returning to main menu — just edit_text to plain text version (no banner resend).
        # Banner only shown on /start for clean look.
        try:
            await query.message.delete()
        except Exception:
            pass
        text = (
            "🦅 <b>Matthunder — Main Menu</b>\n\n"
            "Pilih aksi di bawah ⬇️"
        )
        await query.message.chat.send_message(
            text, parse_mode="HTML",
            reply_markup=main_menu_keyboard(),
        )
        return

    if section == "target":
        if action is None or action == "menu":
            await app_target_menu(query, context)
        elif action == "add":
            await app_target_add(query, context)
        elif action == "list":
            await app_target_list(query, context)
        elif action == "info" and arg:
            await app_target_info(query, context, target=arg)
        elif action == "del" and arg:
            await app_target_del(query, context, target=arg)
        elif action == "del_yes" and arg:
            await app_target_del_yes(query, context, target=arg)
        return

    if section == "scan":
        if action is None:
            await app_scan_menu(query, context)
        elif action == "mat":
            await app_scan_mat(query, context)
        elif action == "matcustom":
            await app_scan_matcustom(query, context)
        elif action == "speedmat" and arg:
            await app_scan_speed_mat(query, context, target=arg)
        elif action == "domat" and arg:
            # app:scan:domat:<target>:<speed>
            target, _, speed = arg.partition(":")
            await app_scan_do_mat(query, context, target=target, speed=speed)
        elif action == "acx":
            await app_scan_acx(query, context)
        return

    if section == "hasil":
        if action is None or action == "menu":
            await app_hasil_menu(query, context)
        elif action == "history":
            await app_hasil_history(query, context)
        elif action == "logs":
            await app_hasil_logs(query, context)
        elif action == "viewlog" and arg:
            await app_hasil_viewlog(query, context, filename=arg)
        elif action == "sendlog" and arg:
            await app_hasil_sendlog(query, context, filename=arg)
        return

    if section == "tutorial":
        await app_tutorial(query, context)
        return

    if section == "ai":
        if action is None:
            await app_ai_menu(query, context)
        elif action == "chat":
            await app_ai_chat_prompt(query, context)
        elif action == "parse":
            await app_ai_parse_prompt(query, context)
        elif action == "run":
            cmd = context.user_data.get("_ai_last_cmd") or []
            await app_ai_run(query, context, cmd)
            context.user_data.pop("_ai_last_cmd", None)
        return

    # Unknown
    await safe_query_answer(query, f"Unknown app action: {data}")


# ─── Text input handler for app flows (add target, custom domain) ───────────

async def app_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text input for app flows that prompt user (e.g. add target, custom scan).

    This is registered BEFORE setup_text_handler and handle_plain_target.
    """
    if not is_owner(update):
        return
    s = context.user_data.get(APP_STATE) or {}
    flow = s.get("flow")
    if not flow:
        return  # no active flow

    raw = (update.message.text or "").strip()
    if raw.lower() in {"/cancel", "cancel", "batal"}:
        s.clear()
        await update.message.reply_text(
            "❌ Cancelled.", reply_markup=main_menu_keyboard(),
        )
        return

    # Best-effort delete the user's message (contains domain/secret-adjacent data)
    try:
        await update.message.delete()
    except Exception:
        pass

    # AI chat / AI parse flows (priority over target flows if both somehow active)
    ai_s = context.user_data.get(AI_STATE) or {}
    if ai_s.get("flow") == "chat" and ai_s.get("pending"):
        ai_s["pending"] = False
        await app_ai_handle_chat(update, context, raw)
        return
    if ai_s.get("flow") == "parse" and ai_s.get("pending"):
        ai_s["pending"] = False
        await app_ai_handle_parse(update, context, raw)
        return

    if flow == "add_target" and s.get("step") == "name":
        target = raw.lower().strip()
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                target = target[len(prefix):]
                break
        target = target.split("/")[0].split("?")[0].split("#")[0].rstrip(".")
        if target.startswith("www."):
            target = target[4:]
        if "." not in target or len(target) > 253:
            await update.message.reply_text(
                "❌ Domain tidak valid.", reply_markup=target_menu_keyboard(),
            )
            s.clear()
            return
        # Add to registry
        targets = _read_targets()
        if any(t.get("name") == target for t in targets):
            await update.message.reply_text(
                f"⚠️ Target `{_esc(target)}` sudah ada di registry.",
                reply_markup=target_menu_keyboard(),
            )
            s.clear()
            return
        targets.append({
            "name": target,
            "addresses": [target],
            "notes": "",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        _write_targets(targets)
        # Auto-create empty subdomain file (so matthunder deep scan finds it)
        sub_dir = ROOT / "subdomain"
        sub_dir.mkdir(exist_ok=True)
        (sub_dir / f"{target}.txt").touch(exist_ok=True)
        s.clear()
        await update.message.reply_text(
            f"✅ Target added: `{_esc(target)}`\n\n"
            f"Saved ke `targets.json` + `subdomain/{_esc(target)}.txt`.\n\n"
            "Sekarang pilih engine di ▶️ Mulai Scan.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("▶️ Mulai Scan sekarang", callback_data="app:scan")],
                [InlineKeyboardButton("🎯 Target Menu", callback_data="app:target")],
                [InlineKeyboardButton("⬅️ Main Menu", callback_data="app:home")],
            ]),
        )
        return

    if flow == "add_acx_target" and s.get("step") == "domain":
        # Reuse acx_do_add_target (it strips protocol, calls add_target, etc.)
        # Replace context.user_data acx_state awaiting with None first to avoid double-handling
        s.clear()
        # Temporarily set acx awaiting to None so the acx handler doesn't intercept
        await acx_do_add_target(update, context, raw)
        return

    if flow == "scan_mat" and s.get("step") == "domain":
        target = raw.lower().strip()
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                target = target[len(prefix):]
                break
        target = target.split("/")[0].split("?")[0].split("#")[0].rstrip(".")
        if target.startswith("www."):
            target = target[4:]
        if "." not in target or len(target) > 253:
            await update.message.reply_text(
                "❌ Domain tidak valid.", reply_markup=scan_mode_keyboard(),
            )
            s.clear()
            return
        # Auto-create subdomain file
        sub_dir = ROOT / "subdomain"
        sub_dir.mkdir(exist_ok=True)
        (sub_dir / f"{target}.txt").touch(exist_ok=True)
        s.clear()
        await update.message.reply_text(
            f"✅ Target: `{_esc(target)}`\n\nPilih speed:",
            reply_markup=matthunder_speed_keyboard(target),
        )
        return

    # Unknown flow
    s.clear()


async def safe_query_answer(query, *args, **kwargs):
    try:
        await query.answer(*args, **kwargs)
    except TimedOut:
        logger.warning("Callback answer timed out; continuing callback flow.")
    except TelegramError as e:
        logger.warning("Callback answer failed: %s", e)


def build_status_text() -> str:
    update_scan_step_from_log_tail()
    checklist, _pct, _analysis = build_stage_checklist()
    target = active_scan.get("target")
    started = active_scan.get("started_at") or time.time()
    duration = int(time.time() - started)
    step = active_scan.get("step") or "🔄 Running"
    detail = active_scan.get("step_detail") or "Scan sedang berjalan."
    log_name = Path(active_scan.get("log_path")).name if active_scan.get("log_path") else "-"
    pct_now = int(active_scan.get("progress_pct") or 0)
    step_age = int(time.time() - (active_scan.get("step_started_at") or started))
    stuck_warn = ""
    if step_age > 600 and pct_now < 100:
        stuck_warn = (
            f"\n\n⚠️ _Step '{step[:60]}' udah jalan {step_age//60} menit tanpa update._\n"
            "_Bisa stuck. Klik ⛔ Stop kalau perlu._"
        )
    elif duration > 300 and pct_now < 30:
        stuck_warn = (
            f"\n\n⚠️ _Scan udah {duration}s tapi progress < 30%._\n"
            "_Kemungkinan hang di tool eksternal. Klik 📄 View Log atau ⛔ Stop._"
        )
    elif duration > 900:
        stuck_warn = (
            f"\n\n⚠️ _Scan udah {duration//60} menit. Kalau stuck, pertimbangkan ⛔ Stop._"
        )
    text = (
        "🔄 Deep Scan running\n\n"
        f"🎯 Target: {target}\n"
        f"⏱ Running: {duration}s\n"
        f"📍 Step: {step}\n"
        f"🕐 Step age: {step_age}s\n"
        f"📊 Progress: {progress_bar_for_step(step)}\n"
        f"📝 {detail}\n"
        f"📄 Log: `{log_name}`"
        f"{stuck_warn}\n\n"
        "🧭 Stage Flow\n"
        + "\n".join(checklist)
    )
    if len(text) > 3900:
        text = text[:3800].rstrip() + "\n\n… (truncated)"
    return text


async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not is_owner(update):
        await safe_query_answer(query, "Access denied", show_alert=True)
        return
    await safe_query_answer(query)
    data = query.data

    if data == "menu_deep":
        pending_target[query.from_user.id] = "awaiting_target"
        await query.message.reply_text(
            "🧬 Start Deep Scan\n\n"
            "Kirim domain target sekarang.\n"
            "Contoh: example.com\n\n"
            "Tidak perlu pakai command."
        )
    elif data == "menu_status":
        if not scan_running():
            await query.message.reply_text("✅ Tidak ada scan berjalan.", reply_markup=status_keyboard())
        else:
            try:
                await query.message.edit_text(build_status_text(), reply_markup=status_keyboard())
            except TelegramError:
                await query.message.reply_text(build_status_text(), reply_markup=status_keyboard())
    elif data == "menu_home":
        await query.message.reply_text(
            "matthunder Deep Bot\n\nPilih menu:",
            reply_markup=main_menu_keyboard()
        )
    elif data == "menu_report":
        zips = sorted(REPORT_DIR.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not zips:
            await query.message.reply_text("Belum ada report ZIP.")
        else:
            latest = zips[0]
            await query.message.reply_document(document=latest.open("rb"), filename=latest.name, caption="📦 Latest report")
    elif data == "menu_log":
        log_path = active_scan.get("log_path")
        if not log_path or not Path(log_path).exists():
            await query.message.reply_text(
                "❌ No log file available. Belum ada scan berjalan atau log udah hilang.",
                reply_markup=status_keyboard(),
            )
            return
        try:
            tail = Path(log_path).read_text(encoding="utf-8", errors="ignore").splitlines()[-30:]
        except Exception as e:
            await query.message.reply_text(f"❌ Read log error: {e}", reply_markup=status_keyboard())
            return
        text = "📄 *Log tail (last 30 lines)*\n\n```\n" + "\n".join(tail) + "\n```"
        if len(text) > 3500:
            text = text[:3500] + "\n… (truncated)"
        try:
            await query.message.edit_text(text, parse_mode="Markdown", reply_markup=status_keyboard())
        except TelegramError:
            await query.message.reply_text(text, parse_mode="Markdown", reply_markup=status_keyboard())
    elif data == "menu_clean":
        if scan_running():
            await query.message.reply_text("⚠️ Jangan cleaning saat scan berjalan. Stop/tunggu scan selesai dulu.", reply_markup=status_keyboard())
        else:
            await query.message.reply_text(
                "🧹 Clean Output\n\n"
                "Ini akan menghapus file output/log/report lama agar laptop tidak berat.\n\n"
                "Yang dibersihkan:\n"
                "• bot_logs / bot_reports lama\n"
                "• output matthunder lama dari folder hasil scan\n"
                "• __pycache__\n\n"
                "Pilih mode cleaning:\n"
                "• Clean Old: hapus file lebih lama dari 7 hari\n"
                "• Clean All: hapus semua output scan/cache sekarang\n\n"
                "Lanjut cleaning?",
                reply_markup=clean_confirm_keyboard()
            )
    elif data in {"clean_confirm", "clean_all_confirm"}:
        if scan_running():
            await query.message.reply_text("⚠️ Cleaning dibatalkan karena scan sedang berjalan.", reply_markup=status_keyboard())
        else:
            clean_all = data == "clean_all_confirm"
            removed_files, removed_bytes, skipped = clean_outputs(days=7, clean_all=clean_all)
            mode = "Clean All Output" if clean_all else "Clean Old >7 Hari"
            msg = (
                f"✅ {mode} selesai\n\n"
                f"🗑 Files removed: {removed_files}\n"
                f"💾 Space freed: {human_size(removed_bytes)}"
            )
            if skipped:
                msg += "\n\n⚠️ Beberapa file dilewati:\n" + "\n".join(skipped)
            await query.message.reply_text(msg, reply_markup=main_menu_keyboard())
    elif data == "menu_stop":
        p = active_scan.get("process")
        if not scan_running():
            await query.message.reply_text("✅ Tidak ada scan berjalan.")
        else:
            try:
                await query.message.reply_text("⛔ Menghentikan scan + child process (nuclei dll)…")
                _kill_proc_tree(p, grace_s=4.0)
                active_scan.update({"process": None, "target": None, "started_at": None, "step": "Idle", "step_detail": "Belum ada scan berjalan.", "progress_pct": 0, "step_started_at": None})
                _clear_scan_state()
                await query.message.reply_text("⛔ Scan dihentikan.")
            except Exception as e:
                await query.message.reply_text(f"❌ Gagal stop scan: {e}")
    elif data == "menu_orphan_kill":
        orphans = _find_orphan_scans()
        if not orphans:
            return await query.message.reply_text("✅ Tidak ada orphan process.", reply_markup=main_menu_keyboard())
        for o in orphans:
            _kill_pid_tree(o["pid"])
        await query.message.reply_text(
            f"🧹 Killed {len(orphans)} orphan process(es). Sekarang bersih.",
            reply_markup=main_menu_keyboard(),
        )
    elif data.startswith("speed:"):
        _, target, speed = data.split(":", 2)
        await start_deep_scan(query.message, context, target, speed)
    elif data == "menu_help":
        await query.message.reply_text(
            "🧭 Help\n\n"
            "Cara pakai tombol:\n"
            "1. Klik 🧬 Start Deep Scan\n"
            "2. Kirim domain target, contoh: example.com\n"
            "3. Pilih speed: Low / Standard / Fast\n"
            "4. Tunggu hasil nuclei + ZIP report\n\n"
            "Gunakan hanya untuk target yang kamu miliki atau punya izin scan.",
            reply_markup=main_menu_keyboard()
        )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    await update.message.reply_text(
        "🧭 Help\n\n"
        "Deep Scan menjalankan:\n"
        "python matthunder.py -dps -t TARGET -s SPEED -ar\n\n"
        "Speed tersedia:\n"
        "low / standard / fast\n\n"
        "Contoh:\n"
        "/deep example.com standard\n\n"
        "Gunakan hanya untuk target yang kamu miliki atau punya izin scan."
    )


# ─── /setup — runtime config for Acunetix + AI ───────────────────────────────

SETUP_STATE = "setup_state"


def _setup_state(context) -> dict:
    s = context.user_data.get(SETUP_STATE)
    if not s:
        s = {"step": None, "acx": {}, "ai": {}}
        context.user_data[SETUP_STATE] = s
    return s


def _setup_reset(context):
    context.user_data[SETUP_STATE] = {"step": None, "acx": {}, "ai": {}}


def setup_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🦅 Acunetix", callback_data="setup:acx"),
         InlineKeyboardButton("🤖 AI Provider", callback_data="setup:ai")],
        [InlineKeyboardButton("📊 Show Status", callback_data="setup:status")],
        [InlineKeyboardButton("🗑️ Clear All", callback_data="setup:clear_all")],
        [InlineKeyboardButton("⬅️ Main Menu", callback_data="menu_home")],
    ])


def setup_acx_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔑 Set URL", callback_data="setup:acx:url"),
         InlineKeyboardButton("🔐 Set API Key", callback_data="setup:acx:key")],
        [InlineKeyboardButton("🔒 TLS Verify (current toggle)", callback_data="setup:acx:verify")],
        [InlineKeyboardButton("🧪 Test Connection", callback_data="setup:acx:test")],
        [InlineKeyboardButton("🗑️ Clear Acunetix", callback_data="setup:acx:clear")],
        [InlineKeyboardButton("⬅️ Setup Menu", callback_data="setup:home")],
    ])


def setup_ai_keyboard() -> InlineKeyboardMarkup:
    rows = []
    for prov in ("openai", "anthropic", "gemini", "openrouter"):
        label = {
            "openai": "🟢 OpenAI",
            "anthropic": "🟣 Anthropic",
            "gemini": "🔵 Gemini",
            "openrouter": "🟠 OpenRouter",
        }[prov]
        rows.append([InlineKeyboardButton(label, callback_data=f"setup:ai:provider:{prov}")])
    rows.append([InlineKeyboardButton("🔐 Set API Key", callback_data="setup:ai:key")])
    rows.append([InlineKeyboardButton("🧠 Set Model", callback_data="setup:ai:model")])
    rows.append([InlineKeyboardButton("🧪 Test AI", callback_data="setup:ai:test")])
    rows.append([InlineKeyboardButton("🗑️ Clear AI", callback_data="setup:ai:clear")])
    rows.append([InlineKeyboardButton("⬅️ Setup Menu", callback_data="setup:home")])
    return InlineKeyboardMarkup(rows)


async def _setup_status_text() -> str:
    import user_config
    s = user_config.status()
    acx = s["acunetix"]
    ai = s["ai"]
    text = "📊 *Current Config*\n\n"
    text += "🦅 *Acunetix*\n"
    if acx["configured"]:
        text += f"  Status: ✅ configured\n"
        text += f"  URL: `{acx['url']}`\n"
        text += f"  Key: `{acx['key_masked']}`\n"
        text += f"  TLS verify: {'true' if acx['verify_ssl'] else 'false'}\n"
    else:
        text += "  Status: ❌ not configured\n"
    text += "\n🤖 *AI Provider*\n"
    if ai["configured"]:
        text += f"  Status: ✅ configured\n"
        text += f"  Provider: `{ai['provider']}`\n"
        text += f"  Model: `{ai['model']}`\n"
        text += f"  Key: `{ai['key_masked']}`\n"
    else:
        text += "  Status: ❌ not configured\n"
    text += f"\n📁 Config file: `{s['file']}`"
    return text


async def setup_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    _setup_state(context)  # init
    text = (
        "⚙️ *Setup — Runtime Config*\n\n"
        "Atur API key Acunetix + AI provider tanpa edit file.\n"
        "Semua tersimpan di `user_config.json` (bukan `config.py`).\n\n"
        "Pilih menu di bawah."
    )
    await update.message.reply_text(
        text, parse_mode="Markdown",
        reply_markup=setup_menu_keyboard(),
    )


async def setup_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not is_owner(update):
        return await safe_query_answer(query, "Access denied", show_alert=True)
    await safe_query_answer(query)
    data = query.data or ""
    parts = data.split(":", 2)
    action = parts[1] if len(parts) > 1 else "home"
    arg = parts[2] if len(parts) > 2 else None

    if action == "home":
        try:
            await query.message.edit_text(
                "⚙️ *Setup Menu*\n\nPilih:",
                parse_mode="Markdown",
                reply_markup=setup_menu_keyboard(),
            )
        except TelegramError:
            await query.message.reply_text(
                "⚙️ *Setup Menu*\n\nPilih:",
                parse_mode="Markdown",
                reply_markup=setup_menu_keyboard(),
            )
    elif action == "status":
        text = await _setup_status_text()
        try:
            await query.message.edit_text(
                text, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Setup Menu", callback_data="setup:home")]]),
            )
        except TelegramError:
            await query.message.reply_text(
                text, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Setup Menu", callback_data="setup:home")]]),
            )
    elif action == "acx" and arg is None:
        # setup:acx  → show Acunetix submenu
        text = "🦅 *Acunetix Setup*\n\n" + await _setup_status_text()
        try:
            await query.message.edit_text(
                text, parse_mode="Markdown",
                reply_markup=setup_acx_keyboard(),
            )
        except TelegramError:
            await query.message.reply_text(
                text, parse_mode="Markdown",
                reply_markup=setup_acx_keyboard(),
            )
    elif action == "ai" and arg is None:
        # setup:ai  → show AI submenu
        text = "🤖 *AI Provider Setup*\n\n" + await _setup_status_text()
        try:
            await query.message.edit_text(
                text, parse_mode="Markdown",
                reply_markup=setup_ai_keyboard(),
            )
        except TelegramError:
            await query.message.reply_text(
                text, parse_mode="Markdown",
                reply_markup=setup_ai_keyboard(),
            )
    elif action == "clear_all":
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Yes, clear all", callback_data="setup:clear_all:yes"),
             InlineKeyboardButton("❌ Cancel", callback_data="setup:home")],
        ])
        try:
            await query.message.edit_text(
                "⚠️ *Clear all config?*\n\n"
                "This will delete Acunetix + AI config from `user_config.json`.\n"
                "Bot will need restart to take effect.",
                parse_mode="Markdown", reply_markup=kb,
            )
        except TelegramError:
            await query.message.reply_text(
                "⚠️ *Clear all config?*",
                parse_mode="Markdown", reply_markup=kb,
            )
    else:
        # Sub-actions: setup:acx:url, setup:ai:provider:openai, etc.
        await _setup_subaction(query, context, action, arg)


async def _setup_subaction(query, context, action: str, arg):
    import user_config

    # setup:acx:url | setup:acx:key | setup:acx:verify | setup:acx:test | setup:acx:clear
    if action == "acx" and arg in {"url", "key", "verify", "test", "clear"}:
        s = _setup_state(context)
        if arg == "url":
            s["step"] = "acx_url"
            await query.message.reply_text(
                "🔑 *Set Acunetix URL*\n\n"
                "Kirim URL lengkap Acunetix, contoh:\n"
                "`https://acunetix.local:3443`\n\n"
                "Ketik /cancel untuk batal.",
                parse_mode="Markdown",
            )
            return
        if arg == "key":
            s["step"] = "acx_key"
            await query.message.reply_text(
                "🔐 *Set Acunetix API Key*\n\n"
                "Kirim API key dari Acunetix UI.\n"
                "Acunetix → Profile → API Key.\n\n"
                "Pesan ini akan dihapus otomatis setelah kamu reply (untuk keamanan).",
                parse_mode="Markdown",
            )
            return
        if arg == "verify":
            cur = user_config.get_acunetix()
            new_val = not cur["verify_ssl"]
            user_config.set_acunetix(cur["url"] or "https://localhost:3443",
                                    cur["api_key"] or "placeholder",
                                    verify_ssl=new_val)
            # re-apply env
            user_config.apply_env()
            await query.message.reply_text(
                f"✅ TLS verify = *{'true' if new_val else 'false'}*\n\n"
                f"_(placeholder URL/key jika baru di-toggle; set ulang via menu)_",
                parse_mode="Markdown",
                reply_markup=setup_acx_keyboard(),
            )
            return
        if arg == "test":
            acx = user_config.get_acunetix()
            if not acx["url"] or not acx["api_key"]:
                await query.message.reply_text(
                    "❌ Acunetix belum di-config. Set URL + key dulu.",
                    reply_markup=setup_acx_keyboard(),
                )
                return
            try:
                import httpx
                r = httpx.get(
                    f"{acx['url']}/api/v1/targets",
                    headers={"X-Auth": acx["api_key"]},
                    verify=acx["verify_ssl"],
                    timeout=10,
                )
                if r.status_code == 200:
                    count = len(r.json().get("targets") or [])
                    await query.message.reply_text(
                        f"✅ *Acunetix OK*\n\nURL: `{acx['url']}`\nTargets visible: {count}",
                        parse_mode="Markdown",
                        reply_markup=setup_acx_keyboard(),
                    )
                else:
                    await query.message.reply_text(
                        f"❌ HTTP {r.status_code}: `{r.text[:200]}`",
                        parse_mode="Markdown",
                        reply_markup=setup_acx_keyboard(),
                    )
            except Exception as e:
                await query.message.reply_text(
                    f"❌ Connection error: `{str(e)[:200]}`",
                    parse_mode="Markdown",
                    reply_markup=setup_acx_keyboard(),
                )
            return
        if arg == "clear":
            user_config.clear_acunetix()
            os.environ.pop(user_config.ENV_ACX_URL, None)
            os.environ.pop(user_config.ENV_ACX_KEY, None)
            await query.message.reply_text(
                "✅ Acunetix config cleared.",
                reply_markup=setup_acx_keyboard(),
            )
            return

    # setup:ai:provider:<name>
    if action == "ai" and arg and arg.startswith("provider:"):
        prov = arg.split(":", 1)[1]
        s = _setup_state(context)
        s["step"] = "ai_key"
        s["ai"]["provider"] = prov
        await query.message.reply_text(
            f"🤖 Provider: *{_esc(prov)}*\n\n"
            f"Env var yang akan di-set: `{user_config.AI_ENV_KEY[prov]}`\n\n"
            "Sekarang kirim API key-nya.\n"
            "Pesan ini akan dihapus otomatis setelah kamu reply (untuk keamanan).",
            parse_mode="Markdown",
        )
        return

    # setup:ai:key
    if action == "ai" and arg == "key":
        s = _setup_state(context)
        cur = user_config.get_ai()
        if not cur["provider"]:
            await query.message.reply_text(
                "❌ Pilih provider dulu (klik tombol provider di atas).",
                reply_markup=setup_ai_keyboard(),
            )
            return
        s["step"] = "ai_key"
        await query.message.reply_text(
            f"🔐 *Set API Key for {cur['provider']}*\n\nKirim API key-nya.\n"
            "Pesan akan dihapus otomatis setelah reply.",
            parse_mode="Markdown",
        )
        return

    # setup:ai:model
    if action == "ai" and arg == "model":
        cur = user_config.get_ai()
        if not cur["provider"]:
            await query.message.reply_text(
                "❌ Pilih provider dulu.",
                reply_markup=setup_ai_keyboard(),
            )
            return
        models = user_config.AI_PROVIDER_MODELS.get(cur["provider"], [])
        rows = []
        row = []
        for m in models:
            row.append(InlineKeyboardButton(m, callback_data=f"setup:ai:model:set:{m}"))
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)
        rows.append([InlineKeyboardButton("✏️ Custom (type)", callback_data="setup:ai:model:custom")])
        rows.append([InlineKeyboardButton("⬅️ AI Menu", callback_data="setup:ai")])
        try:
            await query.message.edit_text(
                f"🧠 *Pick model for {cur['provider']}*\n\nAtau klik Custom untuk ketik sendiri.",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup(rows),
            )
        except TelegramError:
            await query.message.reply_text(
                f"🧠 *Pick model for {cur['provider']}*",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup(rows),
            )
        return

    # setup:ai:model:set:<name>
    if action == "ai" and arg and arg.startswith("model:set:"):
        mname = arg.split(":", 2)[2]
        cur = user_config.get_ai()
        user_config.set_ai(cur["provider"], cur["api_key"], model=mname)
        user_config.apply_env()
        await query.message.reply_text(
            f"✅ Model set: `{_esc(mname)}`",
            parse_mode="Markdown",
            reply_markup=setup_ai_keyboard(),
        )
        return

    # setup:ai:model:custom
    if action == "ai" and arg == "model:custom":
        s = _setup_state(context)
        s["step"] = "ai_model_custom"
        await query.message.reply_text(
            "✏️ *Custom model*\n\nKirim nama model persis (case-sensitive).",
            parse_mode="Markdown",
        )
        return

    # setup:ai:test
    if action == "ai" and arg == "test":
        cur = user_config.get_ai()
        if not cur["provider"] or not cur["api_key"]:
            await query.message.reply_text(
                "❌ AI provider belum lengkap (provider + key).",
                reply_markup=setup_ai_keyboard(),
            )
            return
        try:
            user_config.apply_env()
            from ai_parser import parse_query
            res = parse_query("ping", provider=cur["provider"], model=cur["model"] or None, timeout=15)
            if res.get("source"):
                await query.message.reply_text(
                    f"✅ *AI OK*\n\nProvider: `{cur['provider']}`\nModel: `{res.get('model','?')}`\n"
                    f"Response: `{str(res)[:200]}`",
                    parse_mode="Markdown",
                    reply_markup=setup_ai_keyboard(),
                )
            else:
                err = res.get("error", "?")
                await query.message.reply_text(
                    f"❌ AI test failed: `{_esc(str(err)[:300])}`",
                    parse_mode="Markdown",
                    reply_markup=setup_ai_keyboard(),
                )
        except Exception as e:
            await query.message.reply_text(
                f"❌ Test error: `{_esc(str(e)[:200])}`",
                parse_mode="Markdown",
                reply_markup=setup_ai_keyboard(),
            )
        return

    # setup:ai:clear
    if action == "ai" and arg == "clear":
        user_config.clear_ai()
        for k in user_config.AI_ENV_KEY.values():
            os.environ.pop(k, None)
        os.environ.pop(user_config.ENV_AI_PROVIDER, None)
        os.environ.pop(user_config.ENV_AI_MODEL, None)
        await query.message.reply_text(
            "✅ AI config cleared.",
            reply_markup=setup_ai_keyboard(),
        )
        return

    # setup:clear_all:yes
    if action == "clear_all" and arg == "yes":
        user_config.clear_acunetix()
        user_config.clear_ai()
        for k in [user_config.ENV_ACX_URL, user_config.ENV_ACX_KEY,
                  user_config.ENV_AI_PROVIDER, user_config.ENV_AI_MODEL]:
            os.environ.pop(k, None)
        for k in user_config.AI_ENV_KEY.values():
            os.environ.pop(k, None)
        await query.message.reply_text(
            "✅ All config cleared. Restart bot to take full effect.",
            reply_markup=setup_menu_keyboard(),
        )
        return

    await query.message.reply_text(
        f"⚠️ Unknown setup action: {action}:{arg}",
        reply_markup=setup_menu_keyboard(),
    )


async def setup_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text input during /setup flow.

    This runs BEFORE handle_plain_target (it's added first in the handler list).
    """
    if not is_owner(update):
        return
    s = context.user_data.get(SETUP_STATE) or {}
    step = s.get("step")
    if not step:
        return  # not in setup flow — let other handlers take it

    import user_config
    text = (update.message.text or "").strip()
    if text.lower() in {"/cancel", "cancel", "batal"}:
        _setup_reset(context)
        await update.message.reply_text(
            "❌ Setup cancelled.",
            reply_markup=setup_menu_keyboard(),
        )
        return

    # Try to delete the user message containing the secret (best effort)
    try:
        await update.message.delete()
    except Exception:
        pass

    if step == "acx_url":
        url = text.rstrip("/")
        if not url.startswith(("http://", "https://")):
            await update.message.reply_text(
                "❌ URL harus mulai dengan http:// atau https://",
                reply_markup=setup_acx_keyboard(),
            )
            return
        cur = user_config.get_acunetix()
        user_config.set_acunetix(url, cur["api_key"], cur["verify_ssl"])
        user_config.apply_env()
        _setup_reset(context)
        await update.message.reply_text(
            f"✅ Acunetix URL saved: `{url}`\n\n"
            "_(key belum di-set, klik 🔐 Set API Key)_",
            parse_mode="Markdown",
            reply_markup=setup_acx_keyboard(),
        )
        return

    if step == "acx_key":
        if len(text) < 8:
            await update.message.reply_text(
                "❌ API key terlalu pendek.",
                reply_markup=setup_acx_keyboard(),
            )
            return
        cur = user_config.get_acunetix()
        if not cur["url"]:
            # Save key anyway with placeholder URL — user can set URL later
            user_config.set_acunetix("https://acunetix.example.com", text, cur["verify_ssl"])
            user_config.apply_env()
            _setup_reset(context)
            await update.message.reply_text(
                f"⚠️ API key saved sementara. _URL belum di-set, klik 🔑 Set URL dulu._\n\n"
                f"Key: `{user_config.mask_key(text)}`",
                parse_mode="Markdown",
                reply_markup=setup_acx_keyboard(),
            )
            return
        user_config.set_acunetix(cur["url"], text, cur["verify_ssl"])
        user_config.apply_env()
        _setup_reset(context)
        await update.message.reply_text(
            f"✅ Acunetix API key saved: `{user_config.mask_key(text)}`\n\n"
            "Test koneksi dengan 🧪 Test Connection.",
            parse_mode="Markdown",
            reply_markup=setup_acx_keyboard(),
        )
        return

    if step == "ai_key":
        prov = s.get("ai", {}).get("provider") or user_config.get_ai().get("provider")
        if not prov:
            await update.message.reply_text(
                "❌ Provider belum dipilih.",
                reply_markup=setup_ai_keyboard(),
            )
            return
        if len(text) < 8:
            await update.message.reply_text(
                "❌ API key terlalu pendek.",
                reply_markup=setup_ai_keyboard(),
            )
            return
        cur = user_config.get_ai()
        user_config.set_ai(prov, text, cur["model"])
        user_config.apply_env()
        _setup_reset(context)
        await update.message.reply_text(
            f"✅ AI key saved for `{prov}`: `{user_config.mask_key(text)}`",
            parse_mode="Markdown",
            reply_markup=setup_ai_keyboard(),
        )
        return

    if step == "ai_model_custom":
        prov = user_config.get_ai().get("provider")
        if not prov:
            await update.message.reply_text(
                "❌ Provider belum dipilih.",
                reply_markup=setup_ai_keyboard(),
            )
            return
        cur = user_config.get_ai()
        user_config.set_ai(prov, cur["api_key"], text)
        user_config.apply_env()
        _setup_reset(context)
        await update.message.reply_text(
            f"✅ Model set: `{_esc(text)}`",
            parse_mode="Markdown",
            reply_markup=setup_ai_keyboard(),
        )
        return

    # Unknown step
    _setup_reset(context)


def speed_keyboard(target: str):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🐢 Low", callback_data=f"speed:{target}:low"),
         InlineKeyboardButton("⚖️ Standard", callback_data=f"speed:{target}:standard"),
         InlineKeyboardButton("🚀 Fast", callback_data=f"speed:{target}:fast")],
        [InlineKeyboardButton("⬅️ Menu", callback_data="menu_help")]
    ])


async def handle_plain_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)

    # Acunetix add-target state takes priority
    s = context.user_data.get(ACX_STATE) or {}
    if s.get("awaiting") == "addtarget":
        text = (update.message.text or "").strip()
        if text.lower() in {"/cancel", "cancel", "batal"}:
            s["awaiting"] = None
            return await update.message.reply_text(
                "❌ Add target dibatalkan.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🎯 Back to Targets", callback_data="acx:targets")]]),
            )
        await acx_do_add_target(update, context, text)
        return

    if pending_target.get(update.effective_user.id) != "awaiting_target":
        await send_main_menu(update.message)
        return

    target = normalize_target(update.message.text)
    ok, msg = validate_target(target)
    if not ok:
        return await update.message.reply_text(f"❌ {msg}\n\nKirim ulang domain target, contoh: example.com")

    pending_target[update.effective_user.id] = target
    await update.message.reply_text(
        "✅ Target diterima\n\n"
        f"🎯 Target: {target}\n\n"
        "Pilih speed Deep Scan:",
        reply_markup=speed_keyboard(target)
    )


async def start_deep_scan(message_obj, context: ContextTypes.DEFAULT_TYPE, target: str, speed: str):
    if scan_running():
        return await message_obj.reply_text(
            f"⚠️ Masih ada scan berjalan.\n\nTarget: {active_scan.get('target')}\nKlik 📊 Status atau ⛔ Stop Scan."
        )

    ok, msg = validate_target(target)
    if not ok:
        return await message_obj.reply_text(f"❌ {msg}")
    if speed not in {"low", "standard", "fast"}:
        speed = "standard"

    pending_target.pop(OWNER_ID, None)
    log_path = LOG_DIR / f"deep_{target}_{time.strftime('%Y%m%d_%H%M%S')}.log"
    cmd = [PYTHON_BIN, str(MATTHUNDER), "-dps", "-t", target, "-s", speed, "-ar"]

    await message_obj.reply_text(
        "🚀 Deep Scan started\n\n"
        f"🎯 Target: {target}\n"
        f"⚙️ Speed: {speed}\n\n"
        "Aku kabari kalau selesai. Klik 📊 Status untuk cek progress.",
        reply_markup=main_menu_keyboard()
    )
    await message_obj.chat.send_action(ChatAction.TYPING)

    log_file = open(log_path, "w", encoding="utf-8", errors="ignore")
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["MATTHUNDER_BOT_WRAPPER"] = "1"
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(BOT_DIR or ROOT),
            stdout=log_file,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
    except Exception as e:
        log_file.close()
        return await message_obj.reply_text(f"❌ Gagal menjalankan matthunder: {e}")

    active_scan.update({
        "process": proc,
        "target": target,
        "started_at": time.time(),
        "log_path": str(log_path),
        "message_id": message_obj.message_id,
        "step": "[▶] Starting matthunder Deep Scan",
        "step_detail": "Menunggu output tahap pertama dari matthunder.",
        "progress_pct": 5,
        "last_log_line": "",
        "step_started_at": time.time(),
    })
    _save_scan_state()
    _write_heartbeat()
    context.application.create_task(watch_scan(message_obj.chat_id, proc, target, log_file))
    context.application.create_task(_heartbeat_loop())


async def deep(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    if not context.args:
        pending_target[update.effective_user.id] = "awaiting_target"
        return await update.message.reply_text("🧬 Kirim domain target sekarang.\nContoh: example.com")
    target = normalize_target(context.args[0])
    speed = speed_from_args(context.args)
    await start_deep_scan(update.message, context, target, speed)


# SCAN_STATE_PATH is re-defined at the end of the --bot-dir logic above;
# here we set the legacy default so the variable always exists.
if not BOT_DIR:
    HEARTBEAT_PATH = Path(os.getenv("TEMP", "/tmp")) / "matthunder_bot.heartbeat"
    SCAN_STATE_PATH = ROOT / "bot_logs" / "active_scan.json"
    SCAN_STATE_TMP = ROOT / "bot_logs" / "active_scan.json.tmp"
else:
    # In --bot-dir mode these were already set inside the if BOT_DIR block,
    # but we need to export them as module-level names for the functions below.
    SCAN_STATE_PATH = BOT_DIR / "state" / "active_scan.json"
    SCAN_STATE_TMP = BOT_DIR / "state" / "active_scan.json.tmp"


def _write_heartbeat():
    """Refresh heartbeat file so run_bot.bat knows bot is alive."""
    try:
        HEARTBEAT_PATH.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        pass


def _save_scan_state():
    """Persist active_scan to disk so it survives bot restart.

    The 'process' object isn't serializable; we record its PID and
    reconstruct the reference after a restart by re-checking whether the
    PID is still alive (or attach a fresh asyncio.subprocess.Process).
    """
    try:
        import json as _json
        proc = active_scan.get("process")
        pid = getattr(proc, "pid", None) if proc else None
        payload = {
            "target": active_scan.get("target"),
            "started_at": active_scan.get("started_at"),
            "log_path": active_scan.get("log_path"),
            "message_id": active_scan.get("message_id"),
            "step": active_scan.get("step", "Idle"),
            "step_detail": active_scan.get("step_detail", "Belum ada scan berjalan."),
            "progress_pct": active_scan.get("progress_pct", 0),
            "last_log_line": active_scan.get("last_log_line", ""),
            "step_started_at": active_scan.get("step_started_at"),
            "process_pid": pid,
            "process_alive": proc is not None and getattr(proc, "returncode", 1) is None,
        }
        SCAN_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        text = _json.dumps(payload, ensure_ascii=False, default=str)
        SCAN_STATE_TMP.write_text(text, encoding="utf-8")
        SCAN_STATE_TMP.replace(SCAN_STATE_PATH)
    except Exception as e:
        logger.warning("save_scan_state failed: %s", e)


def _clear_scan_state():
    """Remove the persisted scan state (e.g. when scan finished)."""
    try:
        if SCAN_STATE_PATH.exists():
            SCAN_STATE_PATH.unlink()
        if SCAN_STATE_TMP.exists():
            SCAN_STATE_TMP.unlink()
    except Exception:
        pass


def _pid_alive(pid) -> bool:
    """Return True if a PID is still a live process (best-effort on Windows)."""
    if not pid:
        return False
    try:
        import subprocess as _sp
        rc = _sp.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True, text=True, timeout=5,
        )
        return str(pid) in rc.stdout
    except Exception:
        return False


def _kill_pid_tree(pid):
    """Best-effort process tree kill on Windows."""
    if not pid:
        return
    try:
        import subprocess as _sp
        _sp.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass


def _find_orphan_scans():
    """Find matthunder.py / nuclei.exe / katana.exe processes with no live
    parent bot (i.e. their parent cmd/python chain doesn't include our PID).

    Returns a list of dicts: {pid, name, cmd_short}.
    """
    suspects = []
    try:
        procs = subprocess.run(
            ["wmic", "process", "where",
             "(name='python.exe' and commandline like '%matthunder%') or "
             "name='nuclei.exe' or "
             "(name='python.exe' and commandline like '%katana%') or "
             "(name='python.exe' and commandline like '%httpx%') or "
             "(name='python.exe' and commandline like '%subfinder%')",
             "get", "ProcessId,Name,CommandLine", "/format:list"],
            capture_output=True, text=True, timeout=10,
        )
        if procs.returncode != 0:
            return suspects
        cur = {}
        for line in procs.stdout.splitlines():
            line = line.strip()
            if not line:
                if cur.get("ProcessId"):
                    pid = int(cur["ProcessId"])
                    name = cur.get("Name", "?")
                    cmd = (cur.get("CommandLine") or "").strip()
                    cmd_short = (cmd[:90] + "…") if len(cmd) > 90 else cmd
                    # Skip our own bot process (telegram_deep_bot.py)
                    if "telegram_deep_bot" in cmd:
                        cur = {}
                        continue
                    suspects.append({"pid": pid, "name": name, "cmd_short": cmd_short})
                cur = {}
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                cur[k.strip()] = v.strip()
        if cur.get("ProcessId"):
            pid = int(cur["ProcessId"])
            name = cur.get("Name", "?")
            cmd = (cur.get("CommandLine") or "").strip()
            cmd_short = (cmd[:90] + "…") if len(cmd) > 90 else cmd
            if "telegram_deep_bot" not in cmd:
                suspects.append({"pid": pid, "name": name, "cmd_short": cmd_short})
    except Exception as e:
        logger.debug("find_orphan_scans failed: %s", e)
    return suspects


def _load_scan_state():
    """Re-hydrate active_scan from disk after bot restart.

    If a previous process is still alive, we leave active_scan cleared
    (the prior scan completed / orphaned). We DO report the orphan
    findings so the user knows what happened.
    """
    if not SCAN_STATE_PATH.exists():
        return
    try:
        import json as _json
        data = _json.loads(SCAN_STATE_PATH.read_text(encoding="utf-8", errors="ignore") or "{}")
    except Exception as e:
        logger.warning("load_scan_state: failed to parse %s: %s", SCAN_STATE_PATH, e)
        _clear_scan_state()
        return

    target = data.get("target")
    pid = data.get("process_pid")
    started_at = data.get("started_at")
    log_path = data.get("log_path")

    # If the prior scan's process is still alive, it's an orphan — kill it
    # so the user can start a fresh scan. We don't try to re-attach to a
    # running matthunder.py because we've lost its pipes & watch task.
    if pid and _pid_alive(pid):
        logger.warning("Orphan matthunder PID %s detected; killing tree", pid)
        _kill_pid_tree(pid)
        orphan_msg = (
            f"⚠️ Scan sebelumnya (`{target}`) di-detect sebagai orphan "
            f"(PID {pid} masih jalan padahal bot restart). Sudah di-kill. "
            f"Silakan mulai scan ulang."
        )
        try:
            # Best-effort: notify the owner asynchronously after the loop starts.
            import asyncio
            loop = asyncio.get_event_loop()
            loop.create_task(_notify_orphan(orphan_msg, data))
        except Exception:
            pass
    else:
        logger.info("Previous scan state for %s loaded (process gone)", target)

    _clear_scan_state()


async def _notify_orphan(text: str, data: dict):
    """Send a Telegram message to the owner about the orphaned scan."""
    try:
        chat_id = OWNER_ID
        if chat_id:
            await app.bot.send_message(chat_id=chat_id, text=text)
        # Also try to edit the prior status message so the user sees the
        # situation when they tap "📊 Status".
        msg_id = data.get("message_id")
        if chat_id and msg_id:
            try:
                await app.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=msg_id,
                    text=text + "\n\n_Bot restart di tengah scan — status di-reset._",
                )
            except TelegramError:
                pass
    except Exception as e:
        logger.debug("notify_orphan failed: %s", e)


async def _heartbeat_loop(interval_s: int = 10):
    """Refresh heartbeat while bot is alive. Stops on CancelledError."""
    try:
        while True:
            _write_heartbeat()
            await asyncio.sleep(interval_s)
    except asyncio.CancelledError:
        return
    except Exception:
        return


def _kill_proc_tree(proc, grace_s: float = 3.0):
    """Terminate proc and any subprocess children (e.g. nuclei.exe).

    On Windows, asyncio.create_subprocess_exec spawns a child process group;
    we walk the PID tree and terminate each one to avoid zombie nuclei.
    """
    if proc is None:
        return
    if proc.returncode is not None:
        return
    pid = getattr(proc, "pid", None)
    try:
        if pid:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True, timeout=10,
            )
        else:
            proc.terminate()
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=grace_s)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


async def watch_scan(chat_id: int, proc, target: str, log_file):
    _write_heartbeat()
    try:
        code = await proc.wait()
    finally:
        try:
            log_file.close()
        except Exception:
            pass
        # Remove heartbeat so run_bot knows bot is still alive
        # (it will keep being refreshed by other watch_scan / heartbeat tasks)
    _write_heartbeat()

    duration = int(time.time() - (active_scan.get("started_at") or time.time()))
    zip_path = make_report_zip(target)
    active_scan.update({"process": None, "target": None, "started_at": None, "step": "Idle", "step_detail": "Belum ada scan berjalan.", "progress_pct": 0, "step_started_at": None})
    _clear_scan_state()

    bot = app.bot if 'app' in globals() else None
    if not bot:
        return
    if code == 0:
        await bot.send_message(chat_id, f"✅ Deep Scan completed\n\n🎯 Target: {target}\n⏱ Duration: {duration}s")
    else:
        await bot.send_message(chat_id, f"⚠️ Deep Scan finished with code {code}\n\n🎯 Target: {target}\n⏱ Duration: {duration}s")
    nuclei_summary = build_nuclei_summary(target)
    if nuclei_summary:
        await bot.send_message(chat_id, nuclei_summary)

    if zip_path and zip_path.exists():
        await bot.send_document(chat_id, document=zip_path.open("rb"), filename=zip_path.name, caption="📦 Deep Scan report lengkap")
    else:
        await bot.send_message(chat_id, "📁 Report file target belum ditemukan. Cek /report atau log di bot_logs.")


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    if not scan_running():
        # Also check for orphan matthunder processes that survived a bot crash
        orphans = _find_orphan_scans()
        if orphans:
            lines = ["✅ Tidak ada scan berjalan (bot state).", "",
                     "⚠️ Tapi ada process matthunder/nuclei yang masih jalan:"]
            for o in orphans:
                lines.append(f"  • PID {o['pid']} ({o['name']}) — {o.get('cmd_short','')}")
            lines.append("")
            lines.append("Klik tombol di bawah untuk bersihkan.")
            return await update.message.reply_text(
                "\n".join(lines),
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("🧹 Kill Orphan", callback_data="menu_orphan_kill"),
                ]])
            )
        return await update.message.reply_text("✅ Tidak ada scan berjalan.")
    await update.message.reply_text(build_status_text(), reply_markup=status_keyboard())


async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    p = active_scan.get("process")
    if not scan_running():
        return await update.message.reply_text("✅ Tidak ada scan berjalan.")
    try:
        await update.message.reply_text("⛔ Menghentikan scan + child process (nuclei dll)…")
        _kill_proc_tree(p, grace_s=4.0)
        active_scan.update({"process": None, "target": None, "started_at": None, "step": "Idle", "step_detail": "Belum ada scan berjalan.", "progress_pct": 0, "step_started_at": None})
        _clear_scan_state()
        await update.message.reply_text("⛔ Scan dihentikan.")
    except Exception as e:
        await update.message.reply_text(f"❌ Gagal stop scan: {e}")


async def report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    target = normalize_target(context.args[0]) if context.args else active_scan.get("target")
    if not target:
        zips = sorted(REPORT_DIR.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not zips:
            return await update.message.reply_text("Belum ada report ZIP.")
        latest = zips[0]
        return await update.message.reply_document(document=latest.open("rb"), filename=latest.name, caption="📦 Latest report")
    zip_path = make_report_zip(target)
    if not zip_path:
        return await update.message.reply_text(f"📁 Report untuk {target} belum ditemukan.")
    await update.message.reply_document(document=zip_path.open("rb"), filename=zip_path.name, caption=f"📦 Report {target}")


# ─── Acunetix (button-driven menu) ───────────────────────────────────────────

TELEGRAM_MAX = 3800  # safe under 4096

# Persistent keys for context.user_data
ACX_STATE = "acx_state"  # dict: {scans, targets, vulns, page, current_scan_id, awaiting_vuln_id}


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def _acx_state(context) -> dict:
    s = context.user_data.get(ACX_STATE)
    if not s:
        s = {"scans": [], "targets": [], "vulns": [], "page": 0}
        context.user_data[ACX_STATE] = s
    return s


def acx_main_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📊 Dashboard / Summary", callback_data="acx:summary")],
        [InlineKeyboardButton("📋 List Scans", callback_data="acx:list"),
         InlineKeyboardButton("🎯 List Targets", callback_data="acx:targets")],
        [InlineKeyboardButton("⬅️ Back to Menu", callback_data="menu_home")],
    ])


def acx_scans_keyboard(scans: list[dict], page: int = 0, per_page: int = 8) -> InlineKeyboardMarkup:
    state_pages = max(1, (len(scans) + per_page - 1) // per_page)
    start = page * per_page
    end = min(start + per_page, len(scans))
    rows: list[list[InlineKeyboardButton]] = []
    for s in scans[start:end]:
        sid = s.get("scan_id") or s.get("id")
        addr = s.get("address") or "?"
        rows.append([InlineKeyboardButton(
            f"🔎 {str(addr)[:32]}  ({str(sid)[:10]})",
            callback_data=f"acx:vulns:{sid}",
        )])
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Prev", callback_data=f"acx:listpage:{page-1}"))
    nav.append(InlineKeyboardButton(f"📄 {page+1}/{state_pages}", callback_data="acx:nop"))
    if page < state_pages - 1:
        nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"acx:listpage:{page+1}"))
    rows.append(nav)
    rows.append([InlineKeyboardButton("⬅️ Acunetix Menu", callback_data="acx:home")])
    return InlineKeyboardMarkup(rows)


def acx_targets_keyboard(targets: list[dict]) -> InlineKeyboardMarkup:
    rows = []
    for t in targets[:20]:
        tid = t.get("target_id")
        addr = t.get("address") or "?"
        # Two buttons per row: view target info + start scan
        rows.append([
            InlineKeyboardButton(f"🎯 {str(addr)[:30]}", callback_data=f"acx:targetinfo:{tid}"),
            InlineKeyboardButton(f"🚀 Scan", callback_data=f"acx:startscan:{tid}"),
        ])
    rows.append([InlineKeyboardButton("➕ Add Target", callback_data="acx:addtarget")])
    rows.append([InlineKeyboardButton("⬅️ Acunetix Menu", callback_data="acx:home")])
    return InlineKeyboardMarkup(rows)


ACX_SEVERITY_FILTERS = [
    ("All",            "all"),
    ("🔴 Critical",    "Critical"),
    ("🟠 High",        "High"),
    ("🟡 Medium",      "Medium"),
    ("🔵 Low",         "Low"),
    ("⚪ Info",        "Informational"),
]
ACX_SEVERITY_EMOJI = {
    "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Informational": "⚪",
}


async def acx_send_text(query, text: str, reply_markup=None):
    """Edit or send a long text message safely."""
    text = _strip_ansi(text).strip() or "(no output)"
    if len(text) <= TELEGRAM_MAX:
        try:
            await query.message.edit_text(text, reply_markup=reply_markup)
            return
        except TelegramError:
            pass
    await query.message.reply_text(
        text[:TELEGRAM_MAX] + "\n\n… (truncated)",
        reply_markup=reply_markup,
    )


async def acx_send_long(query, text: str, reply_markup=None):
    """Send a (potentially long) text as new message — doesn't edit."""
    text = _strip_ansi(text).strip() or "(no output)"
    if len(text) <= TELEGRAM_MAX:
        await query.message.reply_text(text, reply_markup=reply_markup)
        return
    await query.message.reply_text(
        text[:TELEGRAM_MAX] + "\n\n… (truncated)",
        reply_markup=reply_markup,
    )


async def acx_show_main(query, context):
    await safe_query_answer(query)
    cfg = _load_acx_cfg()
    if not cfg["url"] or not cfg["key"]:
        await query.message.reply_text(
            "🦅 *Acunetix*\n\n"
            "❌ _ACUNETIX_URL / ACUNETIX_API_KEY belum di-set._\n\n"
            "Isi di `config.py` atau env var, lalu restart bot.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Menu", callback_data="menu_home")]]),
        )
        return
    try:
        await query.message.chat.send_action(ChatAction.TYPING)
        from scanners.acunetix import _client, fetch_scans, fetch_targets
        with _client(cfg) as c:
            scans = fetch_scans(c)
            targets = fetch_targets(c)
        s = _acx_state(context)
        s["scans"] = scans
        s["targets"] = targets
        s["page"] = 0
        text = (
            "🦅 *Acunetix — Main Menu*\n\n"
            f"URL: `{_esc(cfg['url'])}`\n"
            f"Scans: *{len(scans)}*   |   Targets: *{len(targets)}*\n\n"
            "Pilih aksi:"
        )
        try:
            await query.message.edit_text(text, parse_mode="Markdown", reply_markup=acx_main_keyboard())
        except TelegramError:
            await query.message.reply_text(text, parse_mode="Markdown", reply_markup=acx_main_keyboard())
    except Exception as e:
        logger.warning("Acunetix main menu error: %s", e)
        await query.message.reply_text(
            f"❌ Gagal connect Acunetix: `{_esc(str(e)[:200])}`",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Menu", callback_data="menu_home")]]),
        )


async def acx_show_summary(query, context):
    await safe_query_answer(query)
    await query.message.chat.send_action(ChatAction.TYPING)
    try:
        from scanners.acunetix import run_subcommand
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            res = run_subcommand("summary")
        if isinstance(res, dict) and not res.get("ok"):
            await query.message.reply_text(
                f"❌ {_esc(res.get('error', '?'))}",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Acunetix", callback_data="acx:home")]]),
            )
            return
        text = buf.getvalue()
        await acx_send_long(query, text, reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔄 Refresh", callback_data="acx:summary")],
            [InlineKeyboardButton("⬅️ Acunetix Menu", callback_data="acx:home")],
        ]))
    except Exception as e:
        await query.message.reply_text(f"❌ Summary error: `{_esc(str(e)[:200])}`", parse_mode="Markdown")


async def acx_show_list(query, context, page: int = 0):
    await safe_query_answer(query)
    s = _acx_state(context)
    scans = s.get("scans") or []
    if not scans:
        await query.message.reply_text("📋 Belum ada scan di Acunetix (atau klik Acunetix Menu dulu).")
        return
    s["page"] = page
    # Render header text manually (page slice)
    per_page = 8
    start = page * per_page
    end = min(start + per_page, len(scans))
    lines = [
        "📋 *Acunetix Scans*",
        f"Total: *{len(scans)}*   |   Showing: {start+1}-{end}",
        "",
    ]
    for sc in scans[start:end]:
        sid = sc.get("scan_id") or sc.get("id") or "?"
        target = (sc.get("target") or {}).get("address") if isinstance(sc.get("target"), dict) else (sc.get("address") or "?")
        status = sc.get("status") or "?"
        started = (sc.get("start_date") or "").replace("T", " ").rstrip("Z")[:19]
        lines.append(f"• `{_esc(str(sid)[:18])}`  `{_esc(status)}`  {_esc(str(target)[:32])}")
        if started:
            lines.append(f"    🕐 {_esc(started)}")
    text = "\n".join(lines)
    try:
        await query.message.edit_text(
            text,
            parse_mode="Markdown",
            reply_markup=acx_scans_keyboard(scans, page=page, per_page=per_page),
        )
    except TelegramError:
        await query.message.reply_text(
            text,
            parse_mode="Markdown",
            reply_markup=acx_scans_keyboard(scans, page=page, per_page=per_page),
        )


async def acx_show_targets(query, context):
    await safe_query_answer(query)
    s = _acx_state(context)
    targets = s.get("targets") or []
    text_lines = ["🎯 *Acunetix Targets*", f"Total: *{len(targets)}*", ""]
    if targets:
        for t in targets[:30]:
            tid = t.get("target_id") or "?"
            addr = t.get("address") or "?"
            desc = t.get("description") or ""
            text_lines.append(f"• `{_esc(str(tid)[:18])}`  {_esc(str(addr)[:35])}")
            if desc:
                text_lines.append(f"    📝 {_esc(str(desc)[:60])}")
        text_lines.append("")
        text_lines.append("Klik 🎯 untuk lihat detail, 🚀 untuk start scan.")
    else:
        text_lines.append("_(belum ada target — klik ➕ Add Target di bawah)_")
    text = "\n".join(text_lines)
    kb = acx_targets_keyboard(targets)
    kb.inline_keyboard.insert(0, [InlineKeyboardButton("🔄 Refresh Targets", callback_data="acx:targets")])
    try:
        await query.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
    except TelegramError:
        await query.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)


async def acx_show_vulns(query, context, scan_id: str, filter_sev: str = "all", page: int = 0):
    await safe_query_answer(query, "Fetching vulns…")
    await query.message.chat.send_action(ChatAction.TYPING)
    s = _acx_state(context)
    s["current_scan_id"] = scan_id
    s["vulns_filter"] = filter_sev
    s["vulns_page"] = page

    # Re-use cache if available (so filter/page don't re-fetch)
    vulns = s.get("vulns_by_scan", {}).get(scan_id)
    if vulns is None:
        try:
            from scanners.acunetix import _client, fetch_vulnerabilities
            cfg = _load_acx_cfg()
            with _client(cfg) as c:
                vulns = fetch_vulnerabilities(c, scan_id)
            s.setdefault("vulns_by_scan", {})[scan_id] = vulns
        except Exception as e:
            await query.message.reply_text(
                f"❌ Vulns error: `{_esc(str(e)[:200])}`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="acx:list")]]),
            )
            return

    # Counts by severity
    counts = {sev: 0 for sev in ("Critical", "High", "Medium", "Low", "Informational")}
    for v in vulns:
        sev = v.get("severity") or "Informational"
        if sev not in counts:
            sev = "Informational"
        counts[sev] += 1
    if filter_sev == "all":
        shown = vulns
    else:
        shown = [v for v in vulns if (v.get("severity") or "Informational") == filter_sev]

    # Header text (counts + filter info)
    lines = [
        f"🐞 *Vulnerabilities — scan `{_esc(scan_id[:18])}`*",
        f"Total: *{len(vulns)}*   |   Showing: *{len(shown)}* ({_esc(filter_sev)})",
        f"🔴 {counts['Critical']}  🟠 {counts['High']}  🟡 {counts['Medium']}  🔵 {counts['Low']}  ⚪ {counts['Informational']}",
        "",
    ]
    if not shown:
        lines.append("_(no vulnerabilities match this filter)_")
    else:
        lines.append("Klik tombol vuln di bawah untuk lihat detail.")
    text = "\n".join(lines)

    # Build keyboard: filter row + per-vuln rows
    per_page = 6
    state_pages = max(1, (len(shown) + per_page - 1) // per_page)
    page = max(0, min(page, state_pages - 1))
    start = page * per_page
    end = min(start + per_page, len(shown))
    rows: list[list[InlineKeyboardButton]] = []
    # severity filter row
    filt_row: list[InlineKeyboardButton] = []
    for label, sev in ACX_SEVERITY_FILTERS:
        filt_row.append(InlineKeyboardButton(label, callback_data=f"acx:vulnsfilter:{scan_id}:{sev}"))
        if len(filt_row) == 3:
            rows.append(filt_row)
            filt_row = []
    if filt_row:
        rows.append(filt_row)
    # vuln rows
    for v in shown[start:end]:
        vid = v.get("vuln_id") or v.get("id")
        if not vid:
            continue
        sev = v.get("severity") or "Informational"
        name = (v.get("vuln_name") or v.get("name") or "?")[:24]
        emoji = ACX_SEVERITY_EMOJI.get(sev, "⚪")
        label = f"{emoji} {name}  [{str(vid)[:8]}]"
        rows.append([InlineKeyboardButton(label, callback_data=f"acx:detail:{vid}")])
    # nav
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Prev", callback_data=f"acx:vulnspage:{scan_id}:{filter_sev}:{page-1}"))
    nav.append(InlineKeyboardButton(f"📄 {page+1}/{state_pages}", callback_data="acx:nop"))
    if page < state_pages - 1:
        nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"acx:vulnspage:{scan_id}:{filter_sev}:{page+1}"))
    rows.append(nav)
    rows.append([
        InlineKeyboardButton("🔄 Refresh", callback_data=f"acx:vulns:{scan_id}"),
        InlineKeyboardButton("⬅️ Scans", callback_data="acx:list"),
    ])
    rows.append([InlineKeyboardButton("🦅 Acunetix Menu", callback_data="acx:home")])
    kb = InlineKeyboardMarkup(rows)

    try:
        await query.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
    except TelegramError:
        await query.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)


async def acx_target_info(query, context, target_id: str):
    await safe_query_answer(query, "Loading…")
    s = _acx_state(context)
    target = None
    for t in (s.get("targets") or []):
        if str(t.get("target_id")) == str(target_id):
            target = t
            break
    if not target:
        await query.message.reply_text("❌ Target tidak ditemukan di cache. Kembali ke Acunetix Menu.")
        return
    addr = target.get("address") or "?"
    desc = target.get("description") or ""
    text = (
        f"🎯 *Target Detail*\n\n"
        f"ID: `{_esc(str(target_id))}`\n"
        f"Address: `{_esc(addr)}`\n"
    )
    if desc:
        text += f"Description: {_esc(desc)}\n"
    if target.get("criticality") is not None:
        text += f"Criticality: *{target.get('criticality')}*\n"
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🚀 Start Scan on this target", callback_data=f"acx:startscan:{target_id}")],
        [InlineKeyboardButton("🗑️ Delete Target", callback_data=f"acx:delete_target_confirm:{target_id}")],
        [InlineKeyboardButton("⬅️ Back to Targets", callback_data="acx:targets")],
        [InlineKeyboardButton("🦅 Acunetix Menu", callback_data="acx:home")],
    ])
    try:
        await query.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
    except TelegramError:
        await query.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)


async def acx_start_scan(query, context, target_id: str):
    await safe_query_answer(query, "Starting scan…")
    await query.message.chat.send_action(ChatAction.TYPING)
    try:
        from scanners.acunetix import _client, start_scan as acu_start
        cfg = _load_acx_cfg()
        with _client(cfg) as c:
            res = acu_start(c, target_id)
        if not res.get("ok"):
            await query.message.reply_text(
                f"❌ Gagal start scan: `{_esc(res.get('error', '?'))}`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("⬅️ Back to Targets", callback_data="acx:targets")],
                ]),
            )
            return
        scan_id = res.get("scan_id") or "?"
        # Find target address
        s = _acx_state(context)
        addr = target_id
        for t in (s.get("targets") or []):
            if str(t.get("target_id")) == str(target_id):
                addr = t.get("address") or target_id
                break
        s["current_scan_id"] = scan_id
        text = (
            f"✅ *Scan started*\n\n"
            f"Target: `{_esc(addr)}`\n"
            f"Scan ID: `{_esc(scan_id)}`\n"
            f"Profile: `{_esc(res.get('profile_id', '?'))}`\n\n"
            "Tunggu beberapa menit, lalu klik 'View Vulns' untuk lihat hasil."
        )
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🐞 View Vulns (now)", callback_data=f"acx:vulns:{scan_id}")],
            [InlineKeyboardButton("📡 Check Status", callback_data=f"acx:scanstatus:{scan_id}")],
            [InlineKeyboardButton("📋 Back to Scans", callback_data="acx:list")],
            [InlineKeyboardButton("🎯 Back to Targets", callback_data="acx:targets")],
            [InlineKeyboardButton("🦅 Acunetix Menu", callback_data="acx:home")],
        ])
        try:
            await query.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
        except TelegramError:
            await query.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)
    except Exception as e:
        await query.message.reply_text(
            f"❌ Start scan error: `{_esc(str(e)[:200])}`",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="acx:targets")]]),
        )


async def acx_show_detail(query, context, vuln_id: str):
    await safe_query_answer(query, "Fetching detail…")
    await query.message.chat.send_action(ChatAction.TYPING)
    try:
        from scanners.acunetix import run_subcommand
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            res = run_subcommand("detail", vuln_id)
        if isinstance(res, dict) and not res.get("ok"):
            await query.message.reply_text(
                f"❌ {_esc(res.get('error', '?'))}",
                parse_mode="Markdown",
            )
            return
        text = buf.getvalue()
        back_scan = _acx_state(context).get("current_scan_id")
        kb_rows = [
            [InlineKeyboardButton("⛔ Mark as False-Positive", callback_data=f"acx:ignore:{vuln_id}")],
            [InlineKeyboardButton("⬅️ Acunetix Menu", callback_data="acx:home")],
        ]
        if back_scan:
            kb_rows.insert(1, [InlineKeyboardButton("⬅️ Back to Scan Vulns", callback_data=f"acx:vulns:{back_scan}")])
        await acx_send_long(query, text, reply_markup=InlineKeyboardMarkup(kb_rows))
    except Exception as e:
        await query.message.reply_text(
            f"❌ Detail error: `{_esc(str(e)[:200])}`",
            parse_mode="Markdown",
        )


async def acx_prompt_add_target(query, context):
    """User clicked [➕ Add Target] — set flag and ask for domain."""
    await safe_query_answer(query)
    s = _acx_state(context)
    s["awaiting"] = "addtarget"
    text = (
        "➕ *Add New Target to Acunetix*\n\n"
        "Kirim domain target sekarang.\n"
        "Contoh: `example.com` atau `https://app.example.com`\n\n"
        "Format: FQDN, IP, atau URL. Hindari path.\n\n"
        "Ketik /cancel untuk batal."
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Cancel", callback_data="acx:targets")],
    ])
    try:
        await query.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
    except TelegramError:
        await query.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)


async def acx_do_add_target(update, context, address: str):
    """Called by handle_plain_target when state.awaiting == 'addtarget'."""
    s = _acx_state(context)
    s["awaiting"] = None
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        from scanners.acunetix import _client, add_target as acu_add
        cfg = _load_acx_cfg()
        # Strip protocol if any
        clean = address.strip()
        for p in ("https://", "http://"):
            if clean.lower().startswith(p):
                clean = clean[len(p):]
        clean = clean.split("/")[0].strip()
        if not clean:
            await update.message.reply_text("❌ Domain kosong.", reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔁 Coba Lagi", callback_data="acx:addtarget")],
                [InlineKeyboardButton("⬅️ Targets", callback_data="acx:targets")],
            ]))
            return
        with _client(cfg) as c:
            res = acu_add(c, clean, description="added via matthunder telegram bot")
        if not res.get("ok"):
            await update.message.reply_text(
                f"❌ Gagal add target: `{_esc(res.get('error', '?'))}`",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔁 Coba Lagi", callback_data="acx:addtarget")],
                    [InlineKeyboardButton("⬅️ Targets", callback_data="acx:targets")],
                ]),
            )
            return
        target_id = res.get("target_id")
        # Update cache
        s.setdefault("targets", []).append({
            "target_id": target_id,
            "address": res.get("address") or clean,
            "description": "added via matthunder telegram bot",
        })
        await update.message.reply_text(
            f"✅ *Target added*\n\n"
            f"Address: `{_esc(res.get('address', clean))}`\n"
            f"Target ID: `{_esc(str(target_id))}`\n\n"
            "Mau langsung start scan target ini?",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🚀 Start Scan Now", callback_data=f"acx:startscan:{target_id}")],
                [InlineKeyboardButton("➕ Add Another", callback_data="acx:addtarget")],
                [InlineKeyboardButton("🎯 Back to Targets", callback_data="acx:targets")],
                [InlineKeyboardButton("🦅 Acunetix Menu", callback_data="acx:home")],
            ]),
        )
    except Exception as e:
        await update.message.reply_text(
            f"❌ Add target error: `{_esc(str(e)[:200])}`",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="acx:targets")]]),
        )


_ACX_FINISHED_STATUSES = {"completed", "failed", "aborted", "stopped", "terminated", "done"}


def _acx_cancel_poll(context):
    """Cancel any in-flight scan-status auto-poll task."""
    task = context.user_data.pop("_acx_poll_task", None)
    if task and not task.done():
        task.cancel()


def _acx_start_poll(context, query, scan_id: str, interval_s: int = 30):
    """Spawn a background task that polls scan status every interval_s and edits
    the message in place until the scan finishes (or task is cancelled).
    """
    _acx_cancel_poll(context)

    async def _loop():
        try:
            while True:
                await asyncio.sleep(interval_s)
                try:
                    from scanners.acunetix import _client, _get
                    cfg = _load_acx_cfg()
                    with _client(cfg) as c:
                        try:
                            s = _get(c, f"scans/{scan_id}")
                        except Exception:
                            continue
                    sess = s.get("current_session") or {}
                    cs = (sess.get("status") or s.get("status") or "unknown").lower()
                    started = sess.get("start_date") or s.get("start_date") or ""
                    # Re-render current message
                    is_finished = cs in _ACX_FINISHED_STATUSES
                    text = f"📡 *Scan Status — `{_esc(scan_id[:18])}`*\n\nStatus: *{_esc(cs)}*"
                    if started:
                        text += f"\nStarted: `{_esc(started.replace('T',' ').rstrip('Z')[:19])}`"
                    if is_finished:
                        text += "\n\n✅ _Scan selesai — klik View Vulns._"
                    else:
                        text += f"\n\n_Auto-refresh tiap {interval_s}s. Klik ⏹ Stop untuk berhenti._"
                    kb_rows: list[list[InlineKeyboardButton]] = []
                    if is_finished:
                        kb_rows.append([InlineKeyboardButton("🐞 View Vulns", callback_data=f"acx:vulns:{scan_id}")])
                    else:
                        kb_rows.append([
                            InlineKeyboardButton("🔄 Refresh Now", callback_data=f"acx:scanstatus:{scan_id}"),
                            InlineKeyboardButton("⏹ Stop Auto-Refresh", callback_data=f"acx:scanstop:{scan_id}"),
                        ])
                    kb_rows.append([InlineKeyboardButton("📋 Back to Scans", callback_data="acx:list")])
                    kb_rows.append([InlineKeyboardButton("🦅 Acunetix Menu", callback_data="acx:home")])
                    try:
                        await query.message.edit_text(
                            text, parse_mode="Markdown",
                            reply_markup=InlineKeyboardMarkup(kb_rows),
                        )
                    except TelegramError:
                        # Message unchanged or deleted — stop polling
                        return
                    if is_finished:
                        return
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # Network blip — keep trying
                    continue
        except asyncio.CancelledError:
            return

    task = asyncio.create_task(_loop())
    context.user_data["_acx_poll_task"] = task
    return task


async def acx_show_scan_status(query, context, scan_id: str):
    """One-shot status check + offer to start auto-refresh."""
    await safe_query_answer(query, "Checking status…")
    await query.message.chat.send_action(ChatAction.TYPING)
    _acx_cancel_poll(context)
    try:
        from scanners.acunetix import _client, _get
        cfg = _load_acx_cfg()
        with _client(cfg) as c:
            s = _get(c, f"scans/{scan_id}")
        sess = s.get("current_session") or {}
        cs = (sess.get("status") or s.get("status") or "unknown").lower()
        started = sess.get("start_date") or s.get("start_date") or ""
        is_finished = cs in _ACX_FINISHED_STATUSES
        text = f"📡 *Scan Status — `{_esc(scan_id[:18])}`*\n\nStatus: *{_esc(cs)}*"
        if started:
            text += f"\nStarted: `{_esc(started.replace('T',' ').rstrip('Z')[:19])}`"
        if is_finished:
            text += "\n\n✅ _Scan selesai._"
        else:
            text += "\n\n_Scan masih jalan. Klik 🔄 Auto-Refresh untuk monitor otomatis._"
        kb_rows: list[list[InlineKeyboardButton]] = []
        if is_finished:
            kb_rows.append([InlineKeyboardButton("🐞 View Vulns", callback_data=f"acx:vulns:{scan_id}")])
        else:
            kb_rows.append([
                InlineKeyboardButton("🔄 Refresh Now", callback_data=f"acx:scanstatus:{scan_id}"),
                InlineKeyboardButton("⏱ Auto-Refresh (30s)", callback_data=f"acx:scanpoll:{scan_id}"),
            ])
        kb_rows.append([InlineKeyboardButton("📋 Back to Scans", callback_data="acx:list")])
        kb_rows.append([InlineKeyboardButton("🦅 Acunetix Menu", callback_data="acx:home")])
        try:
            await query.message.edit_text(
                text, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup(kb_rows),
            )
        except TelegramError:
            await query.message.reply_text(
                text, parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup(kb_rows),
            )
    except Exception as e:
        await query.message.reply_text(
            f"❌ Status check error: `{_esc(str(e)[:200])}`",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="acx:list")]]),
        )


async def acx_ignore_vuln(query, context, vuln_id: str):
    """Mark vulnerability as false_positive."""
    await safe_query_answer(query, "Marking as false-positive…")
    await query.message.chat.send_action(ChatAction.TYPING)
    try:
        from scanners.acunetix import _client, update_vuln_status as acu_update
        cfg = _load_acx_cfg()
        with _client(cfg) as c:
            res = acu_update(c, vuln_id, "false_positive")
        if not res.get("ok"):
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 Back to Detail", callback_data=f"acx:detail:{vuln_id}")],
            ])
            await query.message.reply_text(
                f"❌ Gagal mark false-positive: `{_esc(res.get('error', '?'))}`",
                parse_mode="Markdown", reply_markup=kb,
            )
            return
        text = (
            f"✅ *Vulnerability marked as false-positive*\n\n"
            f"Vuln ID: `{_esc(vuln_id)}`\n\n"
            "Status di Acunetix sudah di-update. Vulnerability ini tidak akan muncul di report lagi."
        )
        # Update cache
        s = _acx_state(context)
        cur = s.get("current_scan_id")
        by_scan = s.get("vulns_by_scan") or {}
        if cur and cur in by_scan:
            for v in by_scan[cur]:
                if str(v.get("vuln_id") or v.get("id")) == str(vuln_id):
                    v["status"] = "false_positive"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⬅️ Back to Scan Vulns", callback_data=f"acx:vulns:{cur}" if cur else "acx:list")],
            [InlineKeyboardButton("🦅 Acunetix Menu", callback_data="acx:home")],
        ])
        try:
            await query.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
        except TelegramError:
            await query.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)
    except Exception as e:
        await query.message.reply_text(
            f"❌ Ignore error: `{_esc(str(e)[:200])}`",
            parse_mode="Markdown",
        )


async def acx_delete_target_confirm(query, context, target_id: str):
    """Show a confirm page before deleting a target."""
    await safe_query_answer(query)
    s = _acx_state(context)
    target = next((t for t in (s.get("targets") or []) if str(t.get("target_id")) == str(target_id)), None)
    if not target:
        await query.message.reply_text(
            "❌ Target tidak ada di cache. Kembali ke Targets.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🎯 Targets", callback_data="acx:targets")]]),
        )
        return
    addr = target.get("address") or target_id
    text = (
        f"🗑️ *Delete target?*\n\n"
        f"Address: `{_esc(addr)}`\n"
        f"Target ID: `{_esc(str(target_id))}`\n\n"
        "⚠️ _Menghapus target juga menghapus semua scan + vulnerability history-nya._\n\n"
        "Yakin?"
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Yes, delete", callback_data=f"acx:delete_target:{target_id}"),
         InlineKeyboardButton("❌ Cancel", callback_data=f"acx:targetinfo:{target_id}")],
    ])
    try:
        await query.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
    except TelegramError:
        await query.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)


async def acx_delete_target(query, context, target_id: str):
    """Actually delete the target from Acunetix."""
    await safe_query_answer(query, "Deleting…")
    await query.message.chat.send_action(ChatAction.TYPING)
    try:
        from scanners.acunetix import _client, delete_target as acu_delete
        cfg = _load_acx_cfg()
        with _client(cfg) as c:
            res = acu_delete(c, target_id)
        if not res.get("ok"):
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("⬅️ Back", callback_data=f"acx:targetinfo:{target_id}")],
            ])
            await query.message.reply_text(
                f"❌ Gagal delete: `{_esc(res.get('error', '?'))}`",
                parse_mode="Markdown", reply_markup=kb,
            )
            return
        # Update cache
        s = _acx_state(context)
        s["targets"] = [t for t in (s.get("targets") or []) if str(t.get("target_id")) != str(target_id)]
        # also drop vulns_by_scan entries for this target's scans — keep them, harmless
        text = (
            f"✅ *Target deleted*\n\n"
            f"Target ID: `{_esc(str(target_id))}`\n\n"
            "Kembali ke Targets."
        )
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🎯 Back to Targets", callback_data="acx:targets")],
            [InlineKeyboardButton("🦅 Acunetix Menu", callback_data="acx:home")],
        ])
        try:
            await query.message.edit_text(text, parse_mode="Markdown", reply_markup=kb)
        except TelegramError:
            await query.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)
    except Exception as e:
        await query.message.reply_text(
            f"❌ Delete error: `{_esc(str(e)[:200])}`",
            parse_mode="Markdown",
        )


async def acx_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Single dispatcher for all acx:* callbacks."""
    query = update.callback_query
    if not is_owner(update):
        return await safe_query_answer(query, "Access denied", show_alert=True)
    data = query.data or ""
    # data: acx:<action>[:arg]   (arg may itself contain ':' — rejoin)
    parts = data.split(":", 2)
    action = parts[1] if len(parts) > 1 else "home"
    arg = parts[2] if len(parts) > 2 else None

    if action == "home":
        await acx_show_main(query, context)
    elif action == "summary":
        await acx_show_summary(query, context)
    elif action == "list":
        await acx_show_list(query, context, page=0)
    elif action == "listpage":
        try:
            page = int(arg or 0)
        except ValueError:
            page = 0
        await acx_show_list(query, context, page=page)
    elif action == "targets":
        await acx_show_targets(query, context)
    elif action == "targetinfo":
        if not arg:
            return await safe_query_answer(query, "Missing target id", show_alert=True)
        await acx_target_info(query, context, target_id=arg)
    elif action == "startscan":
        if not arg:
            return await safe_query_answer(query, "Missing target id", show_alert=True)
        await acx_start_scan(query, context, target_id=arg)
    elif action == "addtarget":
        await acx_prompt_add_target(query, context)
    elif action == "scanstatus":
        if not arg:
            return await safe_query_answer(query, "Missing scan id", show_alert=True)
        await acx_show_scan_status(query, context, scan_id=arg)
    elif action == "scanpoll":
        if not arg:
            return await safe_query_answer(query, "Missing scan id", show_alert=True)
        await safe_query_answer(query, "Auto-refresh started")
        _acx_start_poll(context, query, scan_id=arg, interval_s=30)
    elif action == "scanstop":
        if not arg:
            return await safe_query_answer(query, "Missing scan id", show_alert=True)
        _acx_cancel_poll(context)
        await safe_query_answer(query, "Auto-refresh stopped")
        await acx_show_scan_status(query, context, scan_id=arg)
    elif action == "ignore":
        if not arg:
            return await safe_query_answer(query, "Missing vuln id", show_alert=True)
        await acx_ignore_vuln(query, context, vuln_id=arg)
    elif action == "delete_target_confirm":
        if not arg:
            return await safe_query_answer(query, "Missing target id", show_alert=True)
        await acx_delete_target_confirm(query, context, target_id=arg)
    elif action == "delete_target":
        if not arg:
            return await safe_query_answer(query, "Missing target id", show_alert=True)
        await acx_delete_target(query, context, target_id=arg)
    elif action == "vulns":
        if not arg:
            return await safe_query_answer(query, "Missing scan id", show_alert=True)
        await acx_show_vulns(query, context, scan_id=arg)
    elif action == "vulnsfilter":
        # acx:vulnsfilter:<scan_id>:<severity>
        if not arg:
            return await safe_query_answer(query, "Missing args", show_alert=True)
        fparts = arg.split(":", 1)
        scan_id = fparts[0]
        sev = fparts[1] if len(fparts) > 1 else "all"
        await acx_show_vulns(query, context, scan_id=scan_id, filter_sev=sev, page=0)
    elif action == "vulnspage":
        # acx:vulnspage:<scan_id>:<severity>:<page>
        if not arg:
            return await safe_query_answer(query, "Missing args", show_alert=True)
        fparts = arg.split(":")
        scan_id = fparts[0] if len(fparts) > 0 else ""
        sev = fparts[1] if len(fparts) > 1 else "all"
        try:
            page = int(fparts[2]) if len(fparts) > 2 else 0
        except ValueError:
            page = 0
        if not scan_id:
            return await safe_query_answer(query, "Missing scan id", show_alert=True)
        await acx_show_vulns(query, context, scan_id=scan_id, filter_sev=sev, page=page)
    elif action == "detail":
        if not arg:
            return await safe_query_answer(query, "Missing vuln id", show_alert=True)
        await acx_show_detail(query, context, vuln_id=arg)
    elif action == "nop":
        await safe_query_answer(query)
    else:
        await safe_query_answer(query, f"Unknown acx action: {action}", show_alert=True)


def _load_acx_cfg() -> dict:
    """Read Acunetix config (mirror of scanners.acunetix._load_config)."""
    url = os.getenv("ACUNETIX_URL")
    key = os.getenv("ACUNETIX_API_KEY")
    verify = os.getenv("ACUNETIX_VERIFY_SSL", "true").lower() not in ("0", "false", "no")
    try:
        import config as lazy
        url = url or getattr(lazy, "ACUNETIX_URL", None)
        key = key or getattr(lazy, "ACUNETIX_API_KEY", None)
        if hasattr(lazy, "ACUNETIX_VERIFY_SSL"):
            verify = bool(getattr(lazy, "ACUNETIX_VERIFY_SSL"))
    except Exception:
        pass
    return {"url": (url or "").rstrip("/"), "key": (key or "").strip(), "verify": verify}


def _esc(text: str) -> str:
    """Escape Telegram Markdown special chars in a single line of user text."""
    if text is None:
        return ""
    out = []
    for ch in str(text):
        if ch in "_*`[]()~>#+-=|{}.!\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    err = context.error
    if err:
        logger.warning("Telegram/API/network error: %s", err)


def main():
    global app
    if (not BOT_TOKEN) or BOT_TOKEN in {"YOUR_BOT_TOKEN", "YOUR_BOT_TOKEN_FROM_BOTFATHER", "TOKEN_BOTFATHER_KAMU"}:
        raise SystemExit(f"Isi BOT_TOKEN di {ROOT / 'config.py'} atau env MATTHUNDER_BOT_TOKEN dulu.")
    # Apply user_config.json into os.environ (Acunetix + AI)
    try:
        import user_config
        user_config.apply_env()
    except Exception as e:
        logger.warning("user_config load failed: %s", e)
    # Recover from a previous bot restart: clear orphan matthunder/nuclei
    # processes and notify the user. active_scan is in-memory only — we don't
    # re-attach to a running scan because we've lost its pipes + watch task.
    try:
        _load_scan_state()
    except Exception as e:
        logger.debug("load_scan_state on startup failed: %s", e)
    # Disable JobQueue/APScheduler because this bot does not use scheduled jobs.
    # This avoids APScheduler timezone errors on some Windows/Python environments.
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .job_queue(None)
        .connect_timeout(30)
        .read_timeout(30)
        .write_timeout(30)
        .pool_timeout(30)
        .build()
    )
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(app_callback, pattern=r"^app:"))
    app.add_handler(CallbackQueryHandler(menu_callback, pattern="^(menu_|speed:|clean_confirm|clean_all_confirm)"))
    app.add_handler(CallbackQueryHandler(setup_callback, pattern=r"^setup:"))
    app.add_handler(CallbackQueryHandler(acx_callback, pattern=r"^acx:"))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("setup", setup_cmd))
    app.add_handler(CommandHandler("deep", deep))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("stop", stop))
    app.add_handler(CommandHandler("report", report))
    # app_text_handler MUST run first (highest priority) — handles target/scan flows
    # Then setup_text_handler for /setup prompts
    # Then handle_plain_target for old deep-scan target flow
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, app_text_handler), group=-3)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, setup_text_handler), group=-2)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_plain_target), group=-1)
    app.add_error_handler(error_handler)

    # Start periodic heartbeat so botman.py can detect liveness.
    # Only meaningful in --bot-dir mode; harmless in legacy mode.
    import threading as _thr
    def _bg_heartbeat():
        _write_heartbeat()
        _thr.Timer(10, _bg_heartbeat).start()
    _bg_heartbeat()

    print("matthunder Deep Telegram Bot running...")
    app.run_polling(
        drop_pending_updates=True,
        poll_interval=2,
        timeout=60,
        bootstrap_retries=-1,
    )


if __name__ == "__main__":
    main()
