@echo off
title MITRE ATT^&CK Navigator for Dummies
cd /d "%~dp0"
where python >nul 2>nul || (
    echo Python was not found. Install Python 3.10+ from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during setup, then run this again.
    pause
    exit /b 1
)
python -c "import openpyxl, reportlab" 2>nul || (
    echo Installing required Python packages...
    python -m pip install --quiet -r requirements.txt
)
python attack_overlap.py %*
