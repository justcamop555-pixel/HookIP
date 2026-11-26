@echo off
rem Builds the portable HookIP_<arch>.exe with PyInstaller.
rem Make sure hookip.ico exists in the project root before building.
setlocal
cd /d "%~dp0.."

python -c "import PyInstaller" 2>nul || python -m pip install pyinstaller

rem Detect architecture for the output name
set ARCH=x64
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set ARCH=ARM64

python -m PyInstaller --onefile --windowed --clean ^
  --name "HookIP_%ARCH%" ^
  --icon hookip.ico ^
  --version-file packaging\version_info.txt ^
  --add-data "hookip.ico;." ^
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
