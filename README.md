# matthunder

```text
███╗   ███╗ █████╗ ████████╗████████╗██╗  ██╗██╗   ██╗███╗   ██╗██████╗ ███████╗██████╗
████╗ ████║██╔══██╗╚══██╔══╝╚══██╔══╝██║  ██║██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██╔████╔██║███████║   ██║      ██║   ███████║██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██║╚██╔╝██║██╔══██║   ██║      ██║   ██╔══██║██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║   ██║      ██║   ██║  ██║╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

**matthunder** is a CLI-first recon automation toolkit with AI-assisted query parsing (BYOK), an optional Telegram bot controller, and an inline scanner family for broken-link discovery, third-party resource hunting, and credential/config URL detection. Built for bug bounty hunters and authorized security testing.

> Use only on targets you own or have explicit permission to test.

---

## Author

**Matt (hmad28)**

- GitHub: [@hmad28](https://github.com/hmad28)
- Repository: [hmad28/matthunder](https://github.com/hmad28/matthunder)

---

## Features

- **CLI-first** — interactive menu (`matthunder_cli.py`) and one-shot flag mode.
- **8 scan modes**:
  - `light` / `dark` / `deep` — Go-tool-based recon (subfinder, assetfinder, httpx, waybackurls, gau, katana, nuclei).
  - `takeover` — Nuclei takeover checks (single target or mass file).
  - `sensitive` — sensitive URL discovery.
  - `blh` — **Broken Link Hunter**: discover social/profile links and classify account status (alive / broken / redirect / blocked / timeout / unknown) across 10 platforms.
  - `tpa` / `thirdparty` — **3rd Party Asset Links**: discover third-party resource links (Google Drive, SharePoint, GitHub, Notion, Trello, Figma, Dropbox, Atlassian). (Note: NOT "Broken Access Control" — that OWASP term is intentionally avoided here.)
  - `cred` — **Credential/Config URL finder**: match sensitive paths across 10 categories (config, docker, database dumps, archives, logs, source control, API docs, PHP info, IDE meta, CI/CD).
- **AI query parser (BYOK)** — natural language → CLI args, supports OpenAI, Anthropic, Gemini, OpenRouter. Offline heuristic fallback when no API key set.
- **Optional Telegram bot** — opt-in via `--telegram`. Owner-gated, IP/private target validation, real-time status cards, ZIP report delivery.
- **Self-update** — pulls latest from `hmad28/matthunder` via GitHub raw.
- **Cross-platform** — Windows, Linux, macOS. Kali/Debian-safe via local `.venv`.
- **SQLite-backed scanners** — BLH/BAC/Cred results stored in `matthunder_scans.db` for offline query.

---

## Quick Start

```bash
git clone https://github.com/hmad28/matthunder.git
cd matthunder
```

### CLI Mode (recommended)

```bash
# Interactive menu
python matthunder_cli.py

# One-shot flag
python matthunder_cli.py deep example.com standard
python matthunder_cli.py blh hackerone.com
python matthunder_cli.py cred example.com fast

# AI query parser (heuristic fallback if no API key)
python matthunder_cli.py --ai "deep scan example.com fast"
python matthunder_cli.py --ai "broken link hunter on example.com"
```

### Telegram Bot Mode (optional)

```bash
python matthunder_cli.py --telegram
```

Bot only responds to your `CHAT_ID` (owner gate). Setup token first — see [Configuration](#configuration).

---

## Installation

### Windows

```bat
setup.bat
```

### Linux / macOS

```bash
chmod +x setup.sh run_cli.sh
./setup.sh
```

The setup script:
1. Creates a local `.venv` (PEP 668-safe on Kali/Debian).
2. Installs Python dependencies from `requirements.txt` + `requirements_bot.txt`.
3. Installs Go-based recon tools via `go install`:
   `subfinder`, `assetfinder`, `httpx`, `waybackurls`, `gau`, `katana`, `nuclei`.
4. Updates Nuclei templates.
5. Adds `~/go/bin` to `PATH` (current session + shell rc).

If Go is not installed, the script prompts for `winget install GoLang.Go` (Windows) or directs you to https://go.dev/dl/.

### Manual Python Install (no setup script)

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -r requirements_bot.txt
```

---

## CLI Usage

### Interactive Menu

```text
    Choose Feature:
  [0]  Feature Information
  [1]  Light Scan
  [2]  Dark Scan
  [3]  Deep Scan (TOP FEATURE)
  [4]  Scan Subdomain Takeover
  [5]  find Sensitive Data
  [6]  Broken Link Hunter (social/profile)
  [7]  Business Asset Collab (3rd-party links)
  [8]  Credential / Config URLs
  [9]  Setup Configuration
  [99] Out
  [999] Update Tool
```

### Flag Mode

```bash
# Recon scans (require Go tools)
python matthunder_cli.py light <target> <speed>
python matthunder_cli.py dark <target> <speed>
python matthunder_cli.py deep <target> <speed>

# Takeover (needs target or -l file)
python matthunder_cli.py takeover -l subdomain.txt
python matthunder_cli.py takeover -t example.com

# Inline scanners (no Go tools required)
python matthunder_cli.py blh <target>
python matthunder_cli.py tpa <target>     # 3rd Party Asset Links
python matthunder_cli.py cred <target>

# Common flags
-ac / --auto-continue    # continue previous scan if files exist
-ar / --auto-restart     # always restart
-i  / --interactive      # force menu mode
--ai "QUERY"             # natural language scan (AI or heuristic)
--ai-provider {openai|anthropic|gemini|openrouter}
--ai-model MODEL         # override default model
--telegram               # also start Telegram bot
--update                 # self-update from GitHub
--info                   # show version + AI/Telegram status
```

### Speed Values

`low` | `standard` | `fast` (or `1` / `2` / `3`)

### Examples

```bash
# AI parser (no API key — uses heuristic)
python matthunder_cli.py --ai "quick light scan on example.com"
# -> {"scan":"lts","target":"example.com","speed":"standard",...}

# AI parser with OpenAI
export OPENAI_API_KEY=sk-...
python matthunder_cli.py --ai "do a deep scan on example.com fast"

# AI parser with Anthropic
export ANTHROPIC_API_KEY=sk-ant-...
python matthunder_cli.py --ai "blh scan example.com"

# Show current config
python matthunder_cli.py --info
```

---

## AI Query Parser (BYOK)

Bring-your-own-key. No paid service bundled. Set **one** of these env vars:

| Provider | Env Var | Default Model |
|---|---|---|
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` |
| Anthropic | `ANTHROPIC_API_KEY` | `claude-3-5-haiku-latest` |
| Gemini | `GEMINI_API_KEY` | `gemini-1.5-flash` |
| OpenRouter | `OPENROUTER_API_KEY` | `meta-llama/llama-3.1-8b-instruct` |

Override provider or model:

```bash
export MATTHUNDER_AI_PROVIDER=anthropic
export MATTHUNDER_AI_MODEL=claude-3-5-sonnet-latest
```

When no API key is set, `ai_parser.py` falls back to a regex-based **heuristic parser** that handles common phrasings like:
- `"deep scan example.com fast"` → `dps`
- `"broken link hunter on example.com"` → `blh`
- `"find sensitive config files"` → `cred`

Set them directly in `config.py` (gitignored) if you prefer not to use env vars.

---

## Scanners (BLH / BAC / Cred)

Three new inline scanners ported from [BLH-Hunter](https://github.com/your-org/blh-hunter)'s scanner logic, no FastAPI/web UI overhead.

### BLH — Broken Link Hunter

- Crawls in-scope pages, extracts anchor tags.
- Matches against 10 platform account URL patterns.
- Reserved-path guards (skips `/login`, `/explore`, etc.).
- HTTP probes each candidate → classifies as `alive` / `broken` / `redirect` / `blocked` / `timeout` / `unknown`.

### TPA — 3rd Party Asset Links (formerly "BAC")

- Crawls in-scope pages.
- Matches outbound links to 3rd-party service domains.
- Stores discovered URLs for manual verification (does not probe target services).

> **Note on naming:** Originally called "BAC" (Business Asset Collab) when ported from BLH-Hunter, but renamed to **TPA / 3rd Party Asset Links** to avoid collision with the OWASP **Broken Access Control** term. Both `tpa` and `thirdparty` work as CLI flags.

### Cred — Credential / Config URL Finder

- Crawls in-scope pages.
- Regex-matches sensitive path patterns across 10 categories.
- No active probing — pure pattern discovery.

### Storage

All three write to `matthunder_scans.db` (SQLite, local, gitignored).

```bash
# Inspect results
sqlite3 matthunder_scans.db "SELECT scanner, domain, status, total_links FROM scans ORDER BY created_at DESC LIMIT 10"
sqlite3 matthunder_scans.db "SELECT category, target_url, status FROM results WHERE scan_id='<id>'"
```

Schema:

```sql
scans(id, scanner, domain, params, status, created_at, finished_at, total_sources, total_links)
results(id, scan_id, category, target_url, source_url, anchor, status, http_code, detail, extracted_at)
scan_log(id, scan_id, message, logged_at)
```

---

## Telegram Bot (Optional)

Owner-gated, IP-blocked-target validation, real-time status cards, ZIP report delivery.

### Setup

1. Chat [@BotFather](https://t.me/BotFather), create a bot, copy the token.
2. Get your numeric user ID from [@userinfobot](https://t.me/userinfobot).
3. Set credentials — **never commit them**:

```bash
# Option A: env vars (recommended)
export MATTHUNDER_BOT_TOKEN="123456:ABC..."
export MATTHUNDER_OWNER_ID="123456789"

# Option B: edit config.py (gitignored)
cp config.example.py config.py
# then fill BOT_TOKEN and CHAT_ID
```

4. Start:

```bash
python matthunder_cli.py --telegram
# or
python telegram_deep_bot.py
```

5. From Telegram, send `/start`. Use the inline menu or commands:

```text
/deep example.com standard
/status
/report
/stop
/help
```

### Security Notes

- Bot only responds to the configured owner `CHAT_ID`. Other users get "Access denied".
- Target validation rejects local/private IPs, `*.local`, `*.lan`, and malformed domains.
- Token in chat history = compromised. **Revoke immediately** via `/mybots` → API Token → Revoke.

---

## Configuration

`config.example.py` is the template. Copy to `config.py` (gitignored):

```python
# Telegram (optional)
BOT_TOKEN = "YOUR_BOT_TOKEN_FROM_BOTFATHER"
CHAT_ID = "YOUR_TELEGRAM_USER_ID"

# Recon tuning
KATANA_LIMIT = 20
RESUME_SCAN_MODE = "ask"  # ask | continue | restart
SCAN_SPEED = "standard"

# Self-update source
GITHUB_USER = "hmad28"
GITHUB_REPO = "matthunder"

# AI parser (BYOK) — set as env vars or hardcode
# OPENAI_API_KEY = ""
# ANTHROPIC_API_KEY = ""
# GEMINI_API_KEY = ""
# OPENROUTER_API_KEY = ""
# MATTHUNDER_AI_PROVIDER = "openai"
# MATTHUNDER_AI_MODEL = "gpt-4o-mini"
```

### Environment Variables

| Variable | Purpose |
|---|---|
| `MATTHUNDER_BOT_TOKEN` | Telegram bot token |
| `MATTHUNDER_OWNER_ID` | Numeric Telegram user ID (owner gate) |
| `MATTHUNDER_DEEP_SPEED` | Default speed for Telegram-initiated deep scans |
| `MATTHUNDER_PYTHON` | Python interpreter path (default: `sys.executable`) |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `OPENROUTER_API_KEY` | AI parser keys |
| `MATTHUNDER_AI_PROVIDER` | Force provider (else auto-detect) |
| `MATTHUNDER_AI_MODEL` | Override default model |

---

## Output Folders

### Go-tool-based scans (light / dark / deep / takeover / sensitive)

```text
subdomain/         # raw subdomain lists
active/            # httpx-validated live hosts
crawled/           # raw URL lists (wayback, gau, katana)
crawled_filtered/  # deduped + in-scope URLs
nuclei/            # nuclei findings (basic, js, dast, takeover)
take_over/         # takeover check results
sensitive_data/    # sensitive URL findings
bot_logs/          # telegram bot log files (gitignored)
bot_reports/       # zip report staging
```

### Inline scanners (blh / bac / cred)

```text
matthunder_scans.db    # SQLite (gitignored) — query directly
```

---

## Project Structure

```text
matthunder.py              # Core recon engine (Go-tool orchestration)
matthunder_cli.py          # CLI entrypoint (menu + flags + AI dispatcher)
telegram_deep_bot.py       # Optional Telegram bot controller
ai_parser.py               # Multi-provider AI query parser + heuristic fallback
scanners/
  __init__.py              # Scanner registry
  common.py                # Crawler, anchor extraction, SQLite schema
  blh.py                   # Broken Link Hunter
  bac.py                   # Business Asset Collab
  cred.py                  # Credential/Config URL finder
config.example.py          # Config template
requirements.txt           # CLI deps
requirements_bot.txt       # Telegram bot deps
setup.sh / setup.bat       # Cross-platform installer
run_cli.sh / run_cli.bat   # CLI launchers
run_deep_bot.sh / .bat     # Legacy Telegram bot launcher
```

---

## `.gitignore`

Already covers `config.py`, `.venv/`, output folders, `matthunder_scans.db`, and any test DBs.

---

## Security Notice

This tool is for **authorized security testing only**. You are responsible for how you use it. Do not scan targets without explicit permission. The author (`hmad28`) is not liable for misuse.

Be aware:
- The self-update feature (`menu 999` / `--update`) downloads files from `https://raw.githubusercontent.com/hmad28/matthunder/`. If that repo or your DNS is compromised, malicious code can be executed locally. Disable the feature or fork the repo to a trusted namespace if this concerns you.
- The `go install @latest` step in setup pulls binaries without checksum verification. Use a Go toolchain you trust.
- Never share bot tokens, API keys, or scan results publicly.
