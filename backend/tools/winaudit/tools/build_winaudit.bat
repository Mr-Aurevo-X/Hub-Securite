@echo off
cd /d "%~dp0.."
set ROOT=%CD%

if not exist "%ROOT%\tools" mkdir "%ROOT%\tools"
python -c "from PIL import Image; im=Image.open(r'%ROOT%\ui\brand-icon.png').convert('RGBA'); im.save(r'%ROOT%\tools\winaudit.ico', format='ICO', sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])"

python -m PyInstaller --noconfirm --clean "%ROOT%\host\WinAudit.spec"
if exist "%ROOT%\host\dist\WinAudit.exe" (
  copy /Y "%ROOT%\host\dist\WinAudit.exe" "%ROOT%\WinAudit.exe" >nul
  echo.
  echo OK: %ROOT%\WinAudit.exe
) else if exist "%ROOT%\dist\WinAudit.exe" (
  copy /Y "%ROOT%\dist\WinAudit.exe" "%ROOT%\WinAudit.exe" >nul
  echo.
  echo OK: %ROOT%\WinAudit.exe
) else (
  echo Build failed.
  exit /b 1
)
