:: startgoagent.inc.bat
:: Step6 - Start GoAgent

echo Starting GoAgent...
::goagent-local\proxy.bat
::goagent-local\proxy.exe
start goagent-local\goagent.exe
::Start proxy.exe if connot load proxy.bat