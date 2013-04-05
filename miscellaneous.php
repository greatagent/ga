<?php
#  wwqgtxx-goagent   - Software suite for breakthrough GFW
#  wwqgtxx-wallproxy - Software suite for breakthrough GFW
#  
#  miscellaneous.php - Last cleanup

delete("goagent-local/check_google_ip.pyo");
delete("goagent-local/ip.txt");
delete("goagent-local/certmgr.exe");
delete("goagent-local/msvcr100.dll");
delete("goagent-local/CA.key");


delete("hash.dat");
delete("sign.dat");
delete("utility/md5deep.exe");
delete("utility/md5deep64.exe");
delete("git.txt");
delete("utility/certenc.dll");
delete("utility/certutil.exe");

delete("firefox.inc.php");
delete("startfirefox.inc.bat");
delete("startgoagent.inc.bat");
delete("update.inc.bat");
delete("miscellaneous.inc.bat");
delete("genhash.inc.bat");
delete(".gitattributes");
delete("wwqgtxx-goagent-standalone.bat");


/* 20121207 Remove incorrect Pinyin Filename */
delete("wwqgtxx-goagent-debug.bat");
delete("wwqgtxx-goagent-donotupdate.bat");
delete("wwqgtxx-goagent-donotupdate-debug.bat");


/* 20121218 Remove proxy.custom */
/* You may edit the FindProxyForURL() section in /goagent-local/proxy.pac to create custom rules */
if(file_exists('data/proxy.custom')){
	@unlink('data/proxy.custom');
}


function delete($link) {
	if(file_exists($link)){
		echo "Delete : ";
		echo $link;
		@unlink($link);
		echo "OK!\r\n"
	}

}

function set_flag($seq){
	touch("data/flag/{$seq}.flag");
}

function _unlink($target){
	echo $target;
	return unlink($target);
}

function unlinkglob($dir){
	$files = glob($dir);
	var_dump($files);
	array_walk($files,'_unlink');
}

/* 20130214 */
@unlink("makensi.php");
?>