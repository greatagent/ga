@echo off
( 
    @cd /d "%~dp0" 
) && (
    "%~dp0python27.exe" -c "import proxy;proxy.generate_RSA();"
)
pause