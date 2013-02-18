<?php
#  wwqgtxx-goagent - Software suite for breakthrough GFW
#  
#  miscellaneous.php - Last cleanup

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