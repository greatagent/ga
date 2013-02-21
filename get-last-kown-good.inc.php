<?php
#  wwqgtxx-goagent   - Software suite for breakthrough GFW
#  wwqgtxx-wallproxy - Software suite for breakthrough GFW
#  
#  get-last-kown-good.inc.php - Grabbing last-known-good file from SmartHosts and Huhamhire-Hosts
echo "\r\n";
echo "Grabbing last-known-good file from SmartHosts and Huhamhire-Hosts:\r\n";

/* FUNCTION */
require_once("makegservers.inc.php");

echo "Grabbing SmartHosts hosts:\r\n";
$googleip1=array();
$host=request("GET /svn/trunk/hosts HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n","smarthosts.googlecode.com");
$host=explode("\n",str_replace("\r\n","\n",$host));
foreach($host as $hostkey=>$hoststring){
	//talk.google.com is special case. We cannot use it as G-Server
	if(preg_match('/(.*?)\ttalk\.google\.com$/',$hoststring,$hostmatch)){
	}elseif(preg_match('/(.*?)\t.*?\.google\.com$/',$hoststring,$hostmatch)){
		if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
			$googleip1[]=$hostmatch[1];
		}
	}
}
echo "Grabbing Huhamhire-Hosts hosts:\r\n";
$googleip2=array();
$host=request("GET /git/downloads/raw/ipv4_mobile_utf8/hosts HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n","huhamhire-hosts.googlecode.com");
$host=explode("\n",str_replace("\r\n","\n",$host));
foreach($host as $hostkey=>$hoststring){
	//talk.google.com is special case. We cannot use it as G-Server
	if(preg_match('/(.*?)\ttalk\.google\.com$/',$hoststring,$hostmatch)){
	}elseif(preg_match('/(.*?)\t.*?\.google\.com$/',$hoststring,$hostmatch)){
		if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
			$googleip2[]=$hostmatch[1];
		}
	}
}

$googleip = $googleip1 +$googleip2;

if(count($googleip)){
	$googleip=array_unique($googleip);
	@unlink("data/last-known-good");
	file_put_contents("data/last-known-good",implode("\r\n",$googleip));
	echo " last-known-good=".implode(",",$googleip)."\r\n";
}else{
	###
}

echo "\r\n";
?>