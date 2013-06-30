@echo off
:: startgoagent.inc.bat
:: Step5 - Start GoAgent
echo Starting GoAgent...
cd goagent-local
python27.exe check_google_ip.py
start goagent.exe
cd..

:: startfirefox.inc.bat
:: Step6 - Start Firefox
echo Starting FirefoxPortable...
start utility\php\php.exe -c utility\php\php.ini startfirefox.inc.php
exit