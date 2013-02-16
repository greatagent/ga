:: startfirefox.inc.bat
:: Step5 - Start Firefox

echo Starting FirefoxPortable...

if not exist data\customhomepage (
	start firefox\FirefoxPortable.exe "https://gfangqiang.googlecode.com/svn/home.html"
) else (
	start firefox\FirefoxPortable.exe
)

utility\sleep.exe -m 1000