@echo off
cd /d "%~dp0"
:loop
echo Running ingest + scoring at %DATE% %TIME%
.\.venv\Scripts\Activate.ps1
python -c "from app.ingest.nvd_ingest import ingest_nvd_gz; ingest_nvd_gz('data\\nvdcve-1.1-recent.json.gz')"
python app/score/score_vulns.py
timeout /t 86400
goto loop
