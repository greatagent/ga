<?php
#  greatagent-ga   - Software suite for breakthrough GFW
#  greatagent-wp - Software suite for breakthrough GFW
#  
#  startfirefox.inc.php - Start Firefox
function deldir($dir) { 
	//先删除目录下的文件： 
	$dh=opendir($dir); 
	while ($file=readdir($dh)) { 
		if($file!="." && $file!="..") { 
		$fullpath=$dir."/".$file; 
			if(!is_dir($fullpath)) { 
				unlink($fullpath); 
			} else { 
				deldir($fullpath); 
			} 
		} 
	} 
      
	closedir($dh); 
	//删除当前文件夹： 
	if(rmdir($dir)) { 
		return true; 
	} else { 
		return false; 
	} 
} 

if(file_exists("./FirefoxPortable/FirefoxPortable.exe")){
	exec('start ./FirefoxPortable/FirefoxPortable.exe "https://greatagent-ga.googlecode.com/git-history/web/ifanqiang.htm"');
}
else{
	echo "Don't Have FirefoxPortable.\r\n";
	if(file_exists("./FirefoxPortable/Data/profile/cert8.db")){
		@unlink("FirefoxPortable\Data\profile\cert8.db");
		deldir("FirefoxPortable\Data\profile");
		deldir("FirefoxPortable\Data");
		deldir("FirefoxPortable");
}
}
?>