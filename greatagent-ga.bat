:: wwqgtxx-goagent.bat
:: Main Batch File
   
@echo off
title wwqgtxx-goagent

:: genhash.inc.bat
:: Step1 - Try to generate hash table until success

echo Generating SHA1 table...

:try
del hash.sha1
if %PROCESSOR_ARCHITECTURE%==x86 (
	utility\sha1deep.exe -rl . > hash.sha1
) else (
	utility\sha1deep64.exe -rl . > hash.sha1
)

if not exist hash.sha1 (
	echo "FAIL TO GENERATE HASH FILE! RETRY..."
	sleep 1 
	goto try
)


for %%a in (hash.sha1) do (
	set length=%%~za
)

if "%length%"=="0" (
	echo "FAIL TO GENERATE HASH FILE! RETRY... "
	sleep 1 
	goto try
) 

:: update.inc.bat
:: Step2 - Clean up hash file and do update

echo Checking for new update...
utility\php\php.exe -c utility\php\php.ini clean-sha1.php
utility\php\php.exe -c utility\php\php.ini updategc.php
utility\sleep.exe -m 1000

:: runner.bat
:: Step3 - Run main file
runner.bat
