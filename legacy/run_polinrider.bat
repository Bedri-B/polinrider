@echo off
REM ===== PolinRider Control Panel launcher (double-click me) =====
REM Runs the server in its own window, independent of any Claude session.
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [setup] Creating virtual environment ...
  python -m venv .venv || ( echo Python not found on PATH. & pause & exit /b 1 )
  echo [setup] Installing dependencies ^(one time^) ...
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
)

set PORT=%1
if "%PORT%"=="" set PORT=7860

echo.
echo   PolinRider Control Panel  ->  http://localhost:%PORT%
echo   (Keep this window open. Press Ctrl+C or close it to stop the server.)
echo.
start "" http://localhost:%PORT%
set PYTHONUTF8=1
".venv\Scripts\python.exe" polinrider_app.py --port %PORT%
pause
