<?php
if(file_exists("./FirefoxPortable/FirefoxPortable.exe")){
	exec('start ./FirefoxPortable/FirefoxPortable.exe "https://wwqgtxx-goagent.googlecode.com/git-history/web/ifanqiang.htm"');
}
else{
echo "Don't Have FirefoxPortable.";
}
?>