@echo off
REM Double-click to stop the server and remove the auto-start task.
call "%~dp0stop_polinrider.bat"
schtasks /delete /tn "PolinRiderPanel" /f
echo Removed auto-start.
pause
