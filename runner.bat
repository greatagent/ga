@echo off
:: miscellaneous.inc.bat
:: Step4 - Old file cleanup

utility\php\php.exe miscellaneous.php

utility\sleep.exe -m 1000

:: startgoagent.inc.bat
:: Step5 - Start GoAgent

echo Starting GoAgent...
start goagent-local\goagent.exe

:: get-last-kown-good.inc.bat
:: Step6 - Start get-last-kown-good
utility\php\php.exe get-last-kown-good.inc.php

:: startfirefox.inc.bat
:: Step7 - Start Firefox
echo Starting FirefoxPortable...
utility\php\php.exe startfirefox.inc.php
