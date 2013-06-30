@echo off
:: clean-old-file.inc.bat
:: Step4 - Old file cleanup

utility\php\php.exe -c utility\php\php.ini clean-old-file.php

utility\sleep.exe -m 1000

:: startgoagentfirefox.inc.bat
:: Step5 - Start GoAgent And Firefox

start runner2.bat


:: get-last-kown-good.inc.bat
:: Step7 - Start get-last-kown-good
utility\php\php.exe -c utility\php\php.ini get-last-kown-good.inc.php

pause
