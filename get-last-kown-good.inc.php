<?php
#  wwqgtxx-goagent - Software suite for breakthrough GFW
#  
#  makegserver.inc.php - Reslove Google Server IP
echo "\r\n";
echo "Grabbing last-known-good file from smarthosts and huhamhire-hosts:\r\n";

/* FUNCTION */
require_once("makegservers.inc.php");
function request($query,$host){
	global $gservers;
	$success=false;
	foreach($gservers as $gkey=>$gserver){ 
		if(! $success){
			echo " Trying\t".$gserver."...";
			$fp = fsockopen('ssl://'.$gserver, 443,$errno,$errstr,3);
			if($fp){
				if ( fwrite($fp, str_replace('{host}',$host,$query)) ) {
					$response=NULL;
					while ( !feof($fp) ) {
						$response .= fgets($fp, 1024);
					}	
					if(preg_match('/HTTP\/1.1 200 OK/',$response)){
						$response=explode("\r\n\r\n",$response);
						unset($response[0]); $response=implode("\r\n\r\n",$response);
						$success=true;
						echo "OK!\r\n";
					}else{
						echo "Walled!\r\n";
						unset($gservers[$gkey]);
					}
				}
				fclose($fp);
			}else{
				echo "Walled!\r\n";
				unset($gservers[$gkey]);
				@fclose($fp);
			}
		} 
	}
	
	return $response;
} 
echo "Grabbing smarthosts hosts:\r\n";
$googleip=array();
$host=request("GET /svn/trunk/hosts HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n","smarthosts.googlecode.com");
$host=explode("\r\n",$host);
foreach($host as $hostkey=>$hoststring){
	//talk.google.com is special case. We cannot use it as G-Server
	if(preg_match('/(.*?)\ttalk\.google\.com$/',$hoststring,$hostmatch)){
	}elseif(preg_match('/(.*?)\t.*?\.google\.com$/',$hoststring,$hostmatch)){
		if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
			$googleip[]=$hostmatch[1];
		}
	}
}
echo "Grabbing huhamhire-hosts hosts:\r\n";
$host=request("GET /git/downloads/raw/ipv4_mobile_utf8/hosts HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n","huhamhire-hosts.googlecode.com");
$host=explode("\r\n",$host);
foreach($host as $hostkey=>$hoststring){
	//talk.google.com is special case. We cannot use it as G-Server
	if(preg_match('/(.*?)\ttalk\.google\.com$/',$hoststring,$hostmatch)){
	}elseif(preg_match('/(.*?)\t.*?\.google\.com$/',$hoststring,$hostmatch)){
		if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
			$googleip[]=$hostmatch[1];
		}
	}
}

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