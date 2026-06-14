import json
import os
import re
import sys
from typing import Optional

try:
    import requests
except ImportError:
    requests = None


ALLOWED_SPEEDS = {"low", "standard", "fast"}
ALLOWED_SCANS = {"lts", "dks", "dps", "tov", "sens", "blh", "bac", "cred", "apirecon", "params", "ssti", "cors", "xss"}

PROVIDERS = {
    "openai": {
        "env_key": "OPENAI_API_KEY",
        "url": "https://api.openai.com/v1/chat/completions",
        "model_default": "gpt-4o-mini",
        "build": lambda prompt, model, key: {
            "url": "https://api.openai.com/v1/chat/completions",
            "headers": {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            "payload": {
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are a CLI parser. Output strict JSON only."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0,
            },
            "extract": lambda r: r.json()["choices"][0]["message"]["content"],
        },
    },
    "anthropic": {
        "env_key": "ANTHROPIC_API_KEY",
        "url": "https://api.anthropic.com/v1/messages",
        "model_default": "claude-3-5-haiku-latest",
        "build": lambda prompt, model, key: {
            "url": "https://api.anthropic.com/v1/messages",
            "headers": {
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            "payload": {
                "model": model,
                "max_tokens": 256,
                "messages": [{"role": "user", "content": prompt}],
            },
            "extract": lambda r: r.json()["content"][0]["text"],
        },
    },
    "gemini": {
        "env_key": "GEMINI_API_KEY",
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "model_default": "gemini-1.5-flash",
        "build": lambda prompt, model, key: {
            "url": f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}",
            "headers": {"Content-Type": "application/json"},
            "payload": {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0, "response_mime_type": "application/json"},
            },
            "extract": lambda r: r.json()["candidates"][0]["content"]["parts"][0]["text"],
        },
    },
    "openrouter": {
        "env_key": "OPENROUTER_API_KEY",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "model_default": "meta-llama/llama-3.1-8b-instruct",
        "build": lambda prompt, model, key: {
            "url": "https://openrouter.ai/api/v1/chat/completions",
            "headers": {
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/hmad28/matthunder",
            },
            "payload": {
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are a CLI parser. Output strict JSON only."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0,
            },
            "extract": lambda r: r.json()["choices"][0]["message"]["content"],
        },
    },
}


SYSTEM_PROMPT = """You translate natural language recon requests into CLI args for matthunder.

Scan modes (use the code):
- lts  = Light Scan
- dks  = Dark Scan
- dps  = Deep Scan
- tov  = Subdomain Takeover (requires -list)
- sens = Sensitive Data
- blh  = Broken Link Hunter (social/profile account check)
- bac  = Business Asset Collab (3rd-party resource links)
- cred = Credential/Config URL finder
- apirecon = API endpoint discovery (kiterunner wrapper)
- params   = Hidden parameter discovery (arjun wrapper)
- ssti     = Server-Side Template Injection probe
- cors     = CORS misconfiguration probe
- xss      = Reflected/DOM XSS (dalfox wrapper)

Speed: low | standard | fast

Output STRICT JSON only, no prose, no markdown:
{"scan":"<mode>","target":"<domain>","speed":"<speed>","list":"<file or null>","resume":"ask|continue|restart"}
"""


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")


def detect_provider() -> Optional[str]:
    for name in PROVIDERS:
        if os.getenv(PROVIDERS[name]["env_key"]):
            return name
    return None


def _extract_json(text: str) -> dict:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    brace = re.search(r"\{.*\}", text, re.S)
    if brace:
        text = brace.group(0)
    return json.loads(text)


def parse_query(query: str, provider: Optional[str] = None, model: Optional[str] = None, timeout: int = 30) -> dict:
    if requests is None:
        return {"error": "requests not installed"}
    provider = provider or os.getenv("MATTHUNDER_AI_PROVIDER") or detect_provider()
    if not provider or provider not in PROVIDERS:
        return {
            "error": "No AI provider configured. Set one of: "
            + ", ".join(f"{p['env_key']}" for p in PROVIDERS.values())
        }
    cfg = PROVIDERS[provider]
    api_key = os.getenv(cfg["env_key"])
    if not api_key:
        return {"error": f"Missing {cfg['env_key']}"}
    model = model or os.getenv("MATTHUNDER_AI_MODEL") or cfg["model_default"]

    req = cfg["build"](f"{SYSTEM_PROMPT}\n\nUser: {query}", model, api_key)
    try:
        resp = requests.post(req["url"], headers=req["headers"], json=req["payload"], timeout=timeout)
        if resp.status_code >= 400:
            return {"error": f"{provider} {resp.status_code}: {resp.text[:200]}"}
        raw = req["extract"](resp)
    except Exception as e:
        return {"error": f"{provider} request failed: {e}"}

    try:
        data = _extract_json(raw)
    except Exception as e:
        return {"error": f"AI returned non-JSON: {e}", "raw": raw[:300]}

    return _validate(data)


def _validate(data: dict) -> dict:
    scan = str(data.get("scan", "")).lower().strip()
    if scan not in ALLOWED_SCANS:
        return {"error": f"invalid scan: {scan!r}"}
    target = str(data.get("target", "")).strip().lower()
    target = target.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0].rstrip(".")
    if target.startswith("www."):
        target = target[4:]
    if not target or not DOMAIN_RE.match(target):
        return {"error": f"invalid target: {target!r}"}
    speed = str(data.get("speed", "standard")).lower().strip()
    if speed not in ALLOWED_SPEEDS:
        speed = "standard"
    resume = str(data.get("resume", "ask")).lower().strip()
    if resume not in {"ask", "continue", "restart"}:
        resume = "ask"
    lst = data.get("list")
    if scan == "tov" and (not lst or not isinstance(lst, str)):
        return {"error": "tov scan requires 'list' (path to subdomain file)"}
    if scan != "tov":
        lst = None
    return {
        "scan": scan,
        "target": target,
        "speed": speed,
        "list": lst,
        "resume": resume,
    }


def heuristic_parse(query: str) -> Optional[dict]:
    """Offline fallback when no API key set. Handles common phrasings."""
    q = query.lower().strip()
    scan = None
    for code, kw in [
        ("lts", "light"),
        ("dks", "dark"),
        ("dps", "deep"),
        ("tov", "takeover"),
        ("sens", "sensitive"),
        ("blh", "broken link"),
        ("blh", "social"),
        ("bac", "collab"),
        ("bac", "sharepoint"),
        ("bac", "google drive"),
        ("cred", "credential"),
        ("cred", "config"),
        ("cred", "sensitive file"),
        ("apirecon", "api endpoint"),
        ("apirecon", "kiterunner"),
        ("apirecon", "api recon"),
        ("params", "parameter discovery"),
        ("params", "hidden parameter"),
        ("ssti", "template injection"),
        ("ssti", "ssti"),
        ("cors", "cors"),
        ("cors", "cross-origin"),
        ("xss", "xss"),
        ("xss", "cross site scripting"),
    ]:
        if kw in q:
            scan = code
            break
    if not scan:
        return None
    speed = "standard"
    for s in ("fast", "standard", "low"):
        if s in q:
            speed = s
            break
    m = re.search(r"\b((?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63})\b", query)
    if not m:
        return None
    target = m.group(1).lower().lstrip("https://").lstrip("http://")
    return _validate({"scan": scan, "target": target, "speed": speed, "list": None, "resume": "ask"})


def main():
    if len(sys.argv) < 2:
        print("usage: python ai_parser.py '<natural language query>'")
        sys.exit(1)
    query = " ".join(sys.argv[1:])
    result = parse_query(query)
    if "error" in result and not result.get("scan"):
        fallback = heuristic_parse(query)
        if fallback:
            result = fallback
            result["source"] = "heuristic"
    print(json.dumps(result, indent=2))
    sys.exit(0 if "error" not in result or result.get("scan") else 2)


if __name__ == "__main__":
    main()
