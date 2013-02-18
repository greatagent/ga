<?php
#  wwqgtxx-goagent - Software suite for breakthrough GFW
#  
#  makegserver.inc.php - Reslove Google Server IP

$gservers=array();
$gdomains=array("www.google.com","mail.google.com","www.l.google.com","mail.l.google.com","www.google.cn","www.g.cn");

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

echo "Grab GServer using DNS...\r\n";

/* Grab GServer using DNS */
foreach($gdomains as $gdomain){
	$dns_responses=dns_get_record($gdomain,DNS_A);
	foreach($dns_responses as $dns_response){
		array_push($gservers,$dns_response["ip"]);
	}
}

//sort($gservers);
$gservers=array_unique($gservers);

echo "GServer=".implode(",",$gservers)."\r\n";
echo "Finish Grab GServer using DNS.\r\n";

echo "Get Last known good...";
if($lkg=@file_get_contents("data/last-known-good")){
	echo "Exists!\r\n";
	$lkg=explode("\n",str_replace("\r\n","\n",$lkg));
	echo " LAST-KNOWN-GOOD=".implode(",",$lkg)."\r\n";
	foreach($lkg as $value){
		if(($key = array_search($value, $gservers)) !== false) {
			unset($gservers[$key]);
		}
		array_unshift($gservers,$value);
	}
	array_unique($gservers);
}else{
	echo "Not exists!\r\n";
}
?>