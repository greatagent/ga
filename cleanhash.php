<?php
#  wwqgtxx-goagent - Software suite for breakthrough GFW
#  
#  cleanhash.php - Cleanup hash table
#  some files do not need to appear in hash table

/* Set Current Directory */
preg_match('/(.*?)\\\cleanhash\.php$/',__FILE__,$currentdir); 
chdir($currentdir[1]);

function cleanup($line) {
  if(base64_encode($line)=="ZTc4NDhiZTgzNzBmNTg3Y2E1NTJkOGE0ZjIxNmI4NDIgIC5c5LiA6ZSu57+75aKZLmJhdA=="){
    return false;
  }
  if (preg_match('/  \.\\\\.git\\\/',$line)) {
    return false;
  }
   if (preg_match('/  \.\\\git\.txt$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\cert8\.db$/',$line)) {
    return true;
  }
  if (preg_match('/  \.\\\firefox\\\/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\data\\\flag\\\/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\goagent-local\\\certs\\\/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\\.settings\\\/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\chrome\\\/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\utility\\\md5deep\.exe$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\utility\\\md5deep64\.exe$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\hash\.sha1$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\sign\.sha1$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\hash\.dat$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\sign\.dat$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\data\\\last-known-good$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\data\\\host$/',$line)) {
    return false;
  }
  if (preg_match('/\\\proxy\.pac$/',$line)) {
    return false;
  }
  if (preg_match('/\\\update.inc\.bat$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\custom\.ini$/',$line)) {
    return false;
  }
  if (preg_match('/  \.\\\Ò»¼ü·­Ç½\.bat$/',$line)) {
    return false;
  } 
  if (preg_match('/\.lnk$/',$line)) {
    return false;
  } 
  if (preg_match('/^4e82d30356a6fcb5f19b5cbff629c162/',$line)) {
    return false;
  } 
  
  return true;
}


/* Check local hash.dat exists or not*/
if(file_exists("hash.dat")){
	$hashtable=file_get_contents("hash.dat");
	$hashtable=explode("\r\n",$hashtable);
	$hashtable=array_filter($hashtable,"cleanup");
	sort($hashtable);
	$hashtable=implode("\r\n",$hashtable);

	/* Output hash.dat */
	if(! file_put_contents("hash.dat",$hashtable)){ echo "ERROR to wrtie hash.dat!"; }
}


/* Check local hash.dat exists or not*/
if(! file_exists("hash.sha1")){
	die("Fatal Error: hash.sha1 not exists!");
}

$hashtable=file_get_contents("hash.sha1");
$hashtable=explode("\r\n",$hashtable);
$hashtable=array_filter($hashtable,"cleanup");
sort($hashtable);
$hashtable=implode("\r\n",$hashtable);

/* Output hash.sha1 */
if(! file_put_contents("hash.sha1",$hashtable)){ echo "ERROR to wrtie hash.sha1!"; }
?>