@echo off
cd /D "%~dp0"
:: startgoagent.inc.bat
:: Step2 - Start GoAgent
echo Starting GoAgent...
cd goagent-local
rem python27.exe check_google_ip.py
start goagent.exe
cd..

:: startfirefox.inc.bat
:: Step3 - Start PortableBroswer
echo Starting PortableBroswer...
python27.exe startbroswer.py

pause

exit