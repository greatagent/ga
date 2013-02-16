:: genhash.inc.bat
:: Step1 - Try to generate hash table until success

echo Generating hash table...

:try
del hash.dat
if %PROCESSOR_ARCHITECTURE%==x86 (
	utility\md5deep.exe -rl . > hash.dat
) else (
	utility\md5deep64.exe -rl . > hash.dat
)

if not exist hash.dat (
	echo "FAIL TO GENERATE HASH FILE! RETRY..."
	sleep 1 
	goto try
)


for %%a in (hash.dat) do (
	set length=%%~za
)

if "%length%"=="0" (
	echo "FAIL TO GENERATE HASH FILE! RETRY... "
	sleep 1 
	goto try
) 