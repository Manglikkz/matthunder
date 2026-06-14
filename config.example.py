# config.py
# Telegram Configuration (optional — bot only used if --telegram flag set)
BOT_TOKEN = "YOUR_BOT_TOKEN_FROM_BOTFATHER"
CHAT_ID = "YOUR_TELEGRAM_USER_ID"

KATANA_LIMIT = 20

# Resume scan configuration
# Options: "ask" (always ask), "continue" (auto continue), "restart" (auto restart)
RESUME_SCAN_MODE = "ask"

# NOTE: DO NOT CHANGE ABOVE THIS!!!
# GitHub Configuration (for tool updates)
GITHUB_USER = "hmad28"
GITHUB_REPO = "matthunder"

SCAN_SPEED = "standard"

# AI Parser (BYOK) — set ONE of these env vars, or hardcode below
# OPENAI_API_KEY = ""
# ANTHROPIC_API_KEY = ""
# GEMINI_API_KEY = ""
# OPENROUTER_API_KEY = ""

# Optional overrides
# MATTHUNDER_AI_PROVIDER = "openai"   # openai | anthropic | gemini | openrouter
# MATTHUNDER_AI_MODEL = "gpt-4o-mini"
