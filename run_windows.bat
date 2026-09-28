@echo off
REM SentiNet launcher for Windows. Double-click this file.
REM First run: creates a virtual environment and installs dependencies (needs internet once).
REM Later runs start the app straight away and work fully offline.
setlocal
cd /d "%~dp0"

set PY=
where py >nul 2>nul && set PY=py -3
if "%PY%"=="" where python >nul 2>nul && set PY=python
if "%PY%"=="" goto nopython

if not exist ".venv\Scripts\python.exe" (
  echo [SentiNet] Creating a virtual environment in .venv ...
  %PY% -m venv .venv || goto nopython
)
if not exist ".venv\installed.txt" (
  echo [SentiNet] Installing dependencies - first run only, about 5 minutes ...
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto failed
  echo ok> ".venv\installed.txt"
)
echo [SentiNet] Starting on http://localhost:8501  (close this window to stop)
".venv\Scripts\python.exe" -m sentinet app
goto end

:nopython
echo.
echo Python 3.10 - 3.13 is required. Install it from https://www.python.org/downloads/
echo and tick "Add python.exe to PATH" during setup, then run this file again.
pause
goto end

:failed
echo.
echo Installing the dependencies failed. Check your internet connection and run this file again.
pause

:end
endlocal
