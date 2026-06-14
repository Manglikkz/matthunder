#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "══════════════════════════════════════════════"
echo " matthunder Linux/macOS Setup"
echo "══════════════════════════════════════════════"

if [ ! -f config.py ] && [ -f config.example.py ]; then
  cp config.example.py config.py
  echo "[OK] config.py dibuat dari config.example.py"
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  if command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "[ERROR] Python tidak ditemukan. Install Python 3.10+ dulu."
    exit 1
  fi
fi

echo "[*] System Python: $($PYTHON_BIN --version)"

# Kali/Debian modern memakai PEP668 (externally-managed-environment).
# Agar tidak merusak system Python, matthunder selalu memakai virtualenv lokal.
if [ ! -d ".venv" ]; then
  echo "[*] Membuat virtual environment lokal: .venv"
  if ! "$PYTHON_BIN" -m venv .venv; then
    echo "[ERROR] Gagal membuat venv. Install dulu paket venv."
    echo "Debian/Ubuntu/Kali: sudo apt install python3-venv python3-pip"
    echo "Kali Python 3.13: sudo apt install python3.13-venv python3-pip"
    exit 1
  fi
fi

if [ -x ".venv/bin/python" ]; then
  PYTHON_BIN=".venv/bin/python"
else
  echo "[ERROR] .venv/bin/python tidak ditemukan."
  exit 1
fi

echo "[*] Venv Python: $($PYTHON_BIN --version)"
echo "[*] Upgrade pip di venv..."
"$PYTHON_BIN" -m pip install --upgrade pip

if [ -f requirements.txt ]; then
  echo "[*] Installing requirements.txt ke venv..."
  "$PYTHON_BIN" -m pip install -r requirements.txt
fi

if [ -f requirements_bot.txt ]; then
  echo "[*] Installing requirements_bot.txt ke venv..."
  "$PYTHON_BIN" -m pip install -r requirements_bot.txt
else
  "$PYTHON_BIN" -m pip install python-telegram-bot
fi

if ! command -v go >/dev/null 2>&1; then
  echo "[ERROR] Go/Golang belum terinstall."
  echo "Install Go dulu: https://go.dev/dl/"
  echo "Ubuntu/Debian contoh: sudo apt install golang-go"
  echo "macOS contoh: brew install go"
  exit 1
fi

echo "[*] Go: $(go version)"
mkdir -p "$HOME/go/bin"
export PATH="$PATH:$HOME/go/bin"

add_path_line='export PATH="$PATH:$HOME/go/bin"'
case "$(basename "$SHELL")" in
  zsh) rc="$HOME/.zshrc" ;;
  bash) rc="$HOME/.bashrc" ;;
  *) rc="$HOME/.profile" ;;
esac
if [ -n "$rc" ] && ! grep -q 'go/bin' "$rc" 2>/dev/null; then
  echo "$add_path_line" >> "$rc"
  echo "[OK] Go bin ditambahkan ke $rc"
fi

install_go_tool() {
  name="$1"
  pkg="$2"
  echo "[*] Installing $name..."
  go install "$pkg"
}

install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@latest
install_go_tool gau github.com/lc/gau/v2/cmd/gau@latest
install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest
install_go_tool assetfinder github.com/tomnomnom/assetfinder@latest

echo "[*] Updating nuclei templates..."
"$HOME/go/bin/nuclei" -update-templates || nuclei -update-templates || true

echo ""
echo "══════════════════════════════════════════════"
echo " Verifying tools"
echo "══════════════════════════════════════════════"
for t in subfinder assetfinder httpx waybackurls gau katana nuclei; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "[OK] $t -> $(command -v "$t")"
  elif [ -x "$HOME/go/bin/$t" ]; then
    echo "[OK] $t -> $HOME/go/bin/$t"
  else
    echo "[MISSING] $t"
  fi
done

echo ""
echo "[SUCCESS] Setup selesai."
echo "Next step: edit config.py isi BOT_TOKEN dan CHAT_ID, lalu jalankan ./run_deep_bot.sh"
