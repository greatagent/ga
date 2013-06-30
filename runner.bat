@echo off
:: clean-old-file.inc.bat
:: Step4 - Old file cleanup

utility\php\php.exe -c utility\php\php.ini clean-old-file.php

utility\sleep.exe -m 1000

:: startgoagent.inc.bat
:: Step5 - Start GoAgent

echo Starting GoAgent...
start runner2.bat

:: get-last-kown-good.inc.bat
:: Step6 - Start get-last-kown-good
utility\php\php.exe -c utility\php\php.ini get-last-kown-good.inc.php

:: startfirefox.inc.bat
:: Step7 - Start Firefox
utility\sleep.exe -m 1000
echo Starting FirefoxPortable...
utility\php\php.exe -c utility\php\php.ini startfirefox.inc.php

pause
