:: wwqgtxx-goagent.bat
:: Main Batch File
   
@echo off
title greatagent-esr

set PYTHONDONTWRITEBYTECODE=x
cd /D "%~dp0"

:: autoupdate.inc.bat
:: Step1 - Try to generate hash table until success

python27.exe autoupdate.py

start runner.bat

pause