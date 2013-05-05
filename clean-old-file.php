<?php
#  wwqgtxx-goagent   - Software suite for breakthrough GFW
#  wwqgtxx-wallproxy - Software suite for breakthrough GFW
#  
#  clean-old-file.php - Last cleanup

@unlink("cleanhash.php");
@unlink("makegservers.inc.php");
@unlink("miscellaneous.php");

@unlink("goagent-local/check_google_ip.pyo");
@unlink("goagent-local/ip.txt");
@unlink("goagent-local/certmgr.exe");
@unlink("goagent-local/msvcr100.dll");
@unlink("goagent-local/CA.key");


@unlink("hash.dat");
@unlink("sign.dat");
@unlink("utility/md5deep.exe");
@unlink("utility/md5deep64.exe");
@unlink("git.txt");
@unlink("utility/certenc.dll");
@unlink("utility/certutil.exe");

@unlink("firefox.inc.php");
@unlink("startfirefox.inc.bat");
@unlink("startgoagent.inc.bat");
@unlink("update.inc.bat");
@unlink("miscellaneous.inc.bat");
@unlink("genhash.inc.bat");
@unlink(".gitattributes");
@unlink("wwqgtxx-goagent-standalone.bat");


/* 20121207 Remove incorrect Pinyin Filename */
@unlink("wwqgtxx-goagent-debug.bat");
@unlink("wwqgtxx-goagent-donotupdate.bat");
@unlink("wwqgtxx-goagent-donotupdate-debug.bat");


/* 20121218 Remove proxy.custom */
/* You may edit the FindProxyForURL() section in /goagent-local/proxy.pac to create custom rules */
if(file_exists('data/proxy.custom')){
	@unlink('data/proxy.custom');
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