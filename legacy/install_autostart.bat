@echo off
REM Double-click to install PolinRider as an auto-start (runs hidden at every logon).
cd /d "%~dp0"

REM make sure the venv exists first
if not exist ".venv\Scripts\python.exe" (
  echo [setup] Creating virtual environment ...
  python -m venv .venv || ( echo Python not found on PATH. & pause & exit /b 1 )
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
)

schtasks /create /tn "PolinRiderPanel" /tr "wscript.exe \"%~dp0run_hidden.vbs\"" /sc onlogon /f
if %errorlevel%==0 (
  echo.
  echo Installed. Starting it now ...
  schtasks /run /tn "PolinRiderPanel"
  timeout /t 6 >nul
  start "" http://localhost:7860
  echo Open http://localhost:7860  ^(it will also auto-start at every logon^)
) else (
  echo.
  echo Could not register the task. Right-click this file ^> "Run as administrator" and retry.
)
pause
