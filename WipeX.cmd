@echo off
rem WipeX desktop launcher for Windows: double-click to start.
rem Reading and erasing drives directly needs Administrator rights, so WipeX asks for them (UAC).
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
if not exist "dist\index.html" (
  echo Building the user interface once...
  call npm install && call npm run build
)
python wipex.py --window
if errorlevel 1 pause
