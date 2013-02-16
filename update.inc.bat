:: update.inc.bat
:: Step2 - Clean up hash file and do update

echo Checking for update...
utility\php\php.exe cleanhash.php
utility\php\php.exe updategc.php
utility\sleep.exe -m 1000