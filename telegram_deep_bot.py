import asyncio
import ipaddress
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
LOG_DIR = ROOT / "bot_logs"
REPORT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

DEFAULT_SPEED = os.getenv("MATTHUNDER_DEEP_SPEED", "standard").lower()
PYTHON_BIN = os.getenv("MATTHUNDER_PYTHON", sys.executable or "python")

try:
    import config as lazy_config
except Exception:
    lazy_config = None

OWNER_ID = int(os.getenv("MATTHUNDER_OWNER_ID") or getattr(lazy_config, "OWNER_ID", getattr(lazy_config, "CHAT_ID", "0")) or "0")
BOT_TOKEN = (os.getenv("MATTHUNDER_BOT_TOKEN") or getattr(lazy_config, "BOT_TOKEN", "") or "").strip()

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
        "failed", "unknown scan mode", "error", "successfully sent", "scan finished",
    ]
    tool_markers = ["subfinder", "assetfinder", "httpx", "wayback", "gau", "katana", "nuclei"]
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


def build_stage_checklist(max_items: int = 17):
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
    active_scan["progress_pct"] = pct
    if analysis.get("last_stage_line"):
        active_scan["step"] = analysis["last_stage_line"]
        active_scan["step_detail"] = "Mengikuti urutan tahapan asli matthunder."
        active_scan["last_log_line"] = analysis["last_stage_line"]
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
            active_scan["step"] = step
            active_scan["step_detail"] = "Mengikuti tahapan/output asli dari matthunder."
            active_scan["progress_pct"] = pct2
            active_scan["last_log_line"] = raw
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
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🧬 Start Deep Scan", callback_data="menu_deep")],
        [InlineKeyboardButton("📊 Status", callback_data="menu_status"), InlineKeyboardButton("📦 Latest Report", callback_data="menu_report")],
        [InlineKeyboardButton("🧹 Clean Output", callback_data="menu_clean"), InlineKeyboardButton("⛔ Stop Scan", callback_data="menu_stop")],
        [InlineKeyboardButton("🧭 Help", callback_data="menu_help")],
    ])


def status_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Refresh Status", callback_data="menu_status")],
        [InlineKeyboardButton("📦 Latest Report", callback_data="menu_report"), InlineKeyboardButton("🧹 Clean Output", callback_data="menu_clean")],
        [InlineKeyboardButton("⛔ Stop Scan", callback_data="menu_stop"), InlineKeyboardButton("⬅️ Menu", callback_data="menu_home")],
    ])


def clean_confirm_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🧹 Clean Old >7 Hari", callback_data="clean_confirm")],
        [InlineKeyboardButton("🔥 Clean All Output", callback_data="clean_all_confirm")],
        [InlineKeyboardButton("❌ Cancel", callback_data="menu_home")],
    ])


async def send_main_menu(message_obj):
    await message_obj.reply_text(
        "matthunder Deep Bot\n\n"
        "Bot private untuk menjalankan Deep Scan dari Telegram.\n\n"
        "Pilih tombol di bawah, atau langsung kirim:\n"
        "/deep example.com\n"
        "/deep example.com fast",
        reply_markup=main_menu_keyboard()
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    await send_main_menu(update.message)


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
    text = (
        "🔄 Deep Scan running\n\n"
        f"🎯 Target: {target}\n"
        f"⏱ Running: {duration}s\n"
        f"📍 Current Step:\n{step}\n"
        f"📊 Progress: {progress_bar_for_step(step)}\n"
        f"📝 Detail: {detail}\n"
        f"📄 Log: {log_name}\n\n"
        "🧭 Stage Flow\n"
        + "\n".join(checklist)
    )
    if len(text) > 3900:
        text = text[:3800].rstrip() + "\n\n...status dipotong karena batas Telegram."
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
                p.terminate()
                await asyncio.sleep(3)
                if p.returncode is None:
                    p.kill()
                await query.message.reply_text("⛔ Scan dihentikan.")
            except Exception as e:
                await query.message.reply_text(f"❌ Gagal stop scan: {e}")
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
            cwd=str(ROOT),
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
    })
    context.application.create_task(watch_scan(message_obj.chat_id, proc, target, log_file))


async def deep(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    if not context.args:
        pending_target[update.effective_user.id] = "awaiting_target"
        return await update.message.reply_text("🧬 Kirim domain target sekarang.\nContoh: example.com")
    target = normalize_target(context.args[0])
    speed = speed_from_args(context.args)
    await start_deep_scan(update.message, context, target, speed)


async def watch_scan(chat_id: int, proc, target: str, log_file):
    try:
        code = await proc.wait()
    finally:
        try:
            log_file.close()
        except Exception:
            pass

    duration = int(time.time() - (active_scan.get("started_at") or time.time()))
    zip_path = make_report_zip(target)
    active_scan.update({"process": None, "target": None, "started_at": None, "step": "Idle", "step_detail": "Belum ada scan berjalan.", "progress_pct": 0})

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
        return await update.message.reply_text("✅ Tidak ada scan berjalan.")
    await update.message.reply_text(build_status_text(), reply_markup=status_keyboard())


async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update):
        return await deny(update)
    p = active_scan.get("process")
    if not scan_running():
        return await update.message.reply_text("✅ Tidak ada scan berjalan.")
    try:
        p.terminate()
        await asyncio.sleep(3)
        if p.returncode is None:
            p.kill()
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


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    err = context.error
    if err:
        logger.warning("Telegram/API/network error: %s", err)


def main():
    global app
    if (not BOT_TOKEN) or BOT_TOKEN in {"YOUR_BOT_TOKEN", "YOUR_BOT_TOKEN_FROM_BOTFATHER", "TOKEN_BOTFATHER_KAMU"}:
        raise SystemExit(f"Isi BOT_TOKEN di {ROOT / 'config.py'} atau env MATTHUNDER_BOT_TOKEN dulu.")
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
    app.add_handler(CallbackQueryHandler(menu_callback, pattern="^(menu_|speed:|clean_confirm|clean_all_confirm)"))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("deep", deep))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("stop", stop))
    app.add_handler(CommandHandler("report", report))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_plain_target))
    app.add_error_handler(error_handler)
    print("matthunder Deep Telegram Bot running...")
    app.run_polling(
        drop_pending_updates=True,
        poll_interval=2,
        timeout=60,
        bootstrap_retries=-1,
    )


if __name__ == "__main__":
    main()
