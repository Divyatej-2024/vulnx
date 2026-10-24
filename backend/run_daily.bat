@echo off
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs
if not exist .venv\Scripts\python.exe (
  echo Create the backend environment first: py -m venv .venv
  exit /b 1
)
.venv\Scripts\python.exe -m app.update_nvd >> logs\scheduled_update.log 2>&1
exit /b %ERRORLEVEL%
