@echo off
title AegisVault Sag Tik Menusu Kurulumu
cd /d "%~dp0"
python aegis_vault\setup_windows.py --install
echo.
echo Islem tamamlandi. Windows Gezgininde sag tik menusunu kontrol edebilirsiniz.
pause
