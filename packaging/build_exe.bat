@echo off
rem Builds a standalone portable HookIP_<arch>.exe with PyInstaller.
setlocal
cd /d "%~dp0.."

python -m pip show pyinstaller >nul 2>&1 || python -m pip install pyinstaller

rem Detect architecture for the output name
set ARCH=x64
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set ARCH=ARM64

python -m PyInstaller --onefile --windowed --clean ^
  --name "HookIP_%ARCH%" ^
  --hidden-import hookip ^
  --hidden-import hookip.app ^
  --hidden-import hookip.config ^
  --hidden-import hookip.dnsmsg ^
  --hidden-import hookip.doh ^
  --hidden-import hookip.logutil ^
  --hidden-import hookip.proxy ^
  --hidden-import hookip.tlsfrag ^
  --hidden-import hookip.watchdog ^
  --hidden-import hookip.winproxy ^
  run_hookip.py

echo.
echo Done: dist\HookIP_%ARCH%.exe
endlocal
