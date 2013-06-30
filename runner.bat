@echo off
:: clean-old-file.inc.bat
:: Step4 - Old file cleanup

utility\php\php.exe -c utility\php\php.ini clean-old-file.php

utility\sleep.exe -m 1000

:: startgoagent.inc.bat
:: Step5 - Start GoAgent

echo Starting GoAgent...
cd goagent-local
python27.exe check_google_ip.py
start goagent.exe

:: startfirefox.inc.bat
:: Step6 - Start Firefox
echo Starting FirefoxPortable...
start utility\php\php.exe -c utility\php\php.ini startfirefox.inc.php


:: get-last-kown-good.inc.bat
:: Step7 - Start get-last-kown-good
utility\php\php.exe -c utility\php\php.ini get-last-kown-good.inc.php

pause
