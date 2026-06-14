@echo off
setlocal EnableExtensions EnableDelayedExpansion

title matthunder Windows Setup

echo.
echo ======================================================
echo   matthunder Windows Setup
echo ======================================================
echo.

cd /d "%~dp0"

if not exist config.py (
    if exist config.example.py (
        copy config.example.py config.py >nul
        echo [OK] config.py dibuat dari config.example.py
    ) else (
        echo [WARN] config.example.py tidak ditemukan. Buat config.py manual sebelum menjalankan bot.
    )
)

set "GO_BIN=%USERPROFILE%\go\bin"
set "TOOLS_OK=1"

echo [1/7] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    py --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python tidak ditemukan.
        echo Install Python 3.10+ dulu dari https://www.python.org/downloads/
        echo Pastikan centang "Add Python to PATH".
        pause
        exit /b 1
    ) else (
        set "PY=py"
    )
) else (
    set "PY=python"
)
%PY% --version

echo.
echo [2/7] Upgrading pip...
%PY% -m pip install --upgrade pip
if errorlevel 1 (
    echo [WARN] Gagal upgrade pip, lanjut install dependency...
)

echo.
echo [3/7] Installing matthunder Python requirements...
if exist requirements.txt (
    %PY% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Gagal install requirements.txt
        pause
        exit /b 1
    )
) else (
    echo [WARN] requirements.txt tidak ditemukan.
)

echo.
echo [4/7] Installing Telegram bot requirements...
if exist requirements_bot.txt (
    %PY% -m pip install -r requirements_bot.txt
    if errorlevel 1 (
        echo [ERROR] Gagal install requirements_bot.txt
        pause
        exit /b 1
    )
) else (
    echo [WARN] requirements_bot.txt tidak ditemukan, install manual python-telegram-bot...
    %PY% -m pip install python-telegram-bot
)

echo.
echo [5/7] Checking Go / Golang...
go version >nul 2>&1
if errorlevel 1 (
    echo [WARN] Go belum ditemukan di PATH.
    echo.
    echo Setup ini butuh Go untuk install tools berikut:
    echo - subfinder
    echo - httpx
    echo - nuclei
    echo - katana
    echo - gau
    echo - waybackurls
    echo - assetfinder
    echo.
    echo Opsi install Go:
    echo 1. Download manual: https://go.dev/dl/
    echo 2. Jika ada winget, jalankan: winget install GoLang.Go
    echo.
    choice /C YN /M "Coba install Go otomatis via winget?"
    if errorlevel 2 (
        echo [ERROR] Go belum tersedia. Install Go dulu lalu jalankan setup.bat lagi.
        pause
        exit /b 1
    )
    winget --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] winget tidak tersedia. Install Go manual: https://go.dev/dl/
        pause
        exit /b 1
    )
    winget install --id GoLang.Go -e --source winget
    echo.
    echo Jika go masih belum terbaca, tutup terminal lalu buka lagi dan jalankan setup.bat ulang.
    go version >nul 2>&1
    if errorlevel 1 (
        pause
        exit /b 1
    )
)
go version

echo.
echo [6/7] Adding Go bin to PATH for current user...
if not exist "%GO_BIN%" mkdir "%GO_BIN%" >nul 2>&1
echo Current Go bin: %GO_BIN%
set "PATH=%PATH%;%GO_BIN%"
echo %PATH% | find /I "%GO_BIN%" >nul
reg query HKCU\Environment /v Path >nul 2>&1
if errorlevel 1 (
    setx Path "%PATH%" >nul
) else (
    for /f "tokens=2,*" %%A in ('reg query HKCU\Environment /v Path 2^>nul ^| find /I "Path"') do set "USER_PATH=%%B"
    echo !USER_PATH! | find /I "%GO_BIN%" >nul
    if errorlevel 1 (
        setx Path "!USER_PATH!;%GO_BIN%" >nul
    )
)

echo.
echo [7/7] Installing external recon tools via go install...
echo This may take several minutes.
echo.

call :go_install subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
call :go_install httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
call :go_install nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
call :go_install katana github.com/projectdiscovery/katana/cmd/katana@latest
call :go_install gau github.com/lc/gau/v2/cmd/gau@latest
call :go_install waybackurls github.com/tomnomnom/waybackurls@latest
call :go_install assetfinder github.com/tomnomnom/assetfinder@latest

echo.
echo Updating nuclei templates...
nuclei -update-templates
if errorlevel 1 echo [WARN] nuclei template update gagal/di-skip. Bisa dijalankan manual nanti: nuclei -update-templates

echo.
echo ======================================================
echo   Verifying installed tools
echo ======================================================
call :check_tool subfinder
call :check_tool assetfinder
call :check_tool httpx
call :check_tool katana
call :check_tool gau
call :check_tool waybackurls
call :check_tool nuclei

echo.
if "%TOOLS_OK%"=="1" (
    echo [SUCCESS] Setup selesai. Semua tool utama terdeteksi.
) else (
    echo [WARN] Setup selesai, tapi ada tool yang belum terdeteksi.
    echo Tutup terminal, buka lagi, lalu jalankan setup.bat ulang.
)

echo.
echo Next step:
echo 1. Edit config.py lalu isi BOT_TOKEN dan CHAT_ID
echo 2. Jalankan: run_deep_bot.bat
echo 3. Dari Telegram: /deep example.com standard
echo.
pause
exit /b 0

:go_install
set "TOOL_NAME=%~1"
set "GO_PACKAGE=%~2"
echo Installing %TOOL_NAME%...
go install %GO_PACKAGE%
if errorlevel 1 (
    echo [WARN] Gagal install %TOOL_NAME% dari %GO_PACKAGE%
    set "TOOLS_OK=0"
) else (
    echo [OK] %TOOL_NAME% installed.
)
exit /b 0

:check_tool
set "TOOL=%~1"
where %TOOL% >nul 2>&1
if errorlevel 1 (
    echo [MISSING] %TOOL%
    set "TOOLS_OK=0"
) else (
    for /f "delims=" %%P in ('where %TOOL% 2^>nul') do echo [OK] %TOOL% - %%P
)
exit /b 0
