<?php
#  wwqgtxx-goagent - Software suite for breakthrough GFW
#  
#  updategc.php - Bootstrap Phase 1
#  "gc" is stand for googleCode. In the old version, we use GAE for update, not GoogleCode.

/* Set Current Directory */
preg_match('/(.*?)\\\updategc\.php$/',__FILE__,$currentdir); 
chdir($currentdir[1]);

/* Define update server*/
$host = "goagent.wwqgtxx-goagent.googlecode.com";

/* */
file_exists("string.inc.php") && require_once("string.inc.php");
require_once("makegservers.inc.php");

/* */
echo " Last known good...";
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

/* FUNCTION */
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

function update($filename,$hash){
	global $gservers,$host;
	$request="GET /git/{$filename} HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n";
	$request=str_replace('./','',$request);
	$success=false;
	foreach($gservers as $gkey=>$gserver){ 
		if(! $success){
			echo "Update\t".$filename;
			echo "\t@".$gserver."\t";
			if($fp = fsockopen('ssl://'.$gserver, 443,$errno,$errstr,3)){
				if ( fwrite($fp, str_replace('{host}',$host,$request)) ) {
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
	
	if(md5($response)==$hash){
		if(dirname($filename)!="." && ! file_exists(dirname($filename))){
			mkdir(dirname($filename),0,true);
		}
		file_put_contents($filename,$response);
	}else{
		echo $str["hash_sign_incorrect"];
		echo $str["anykeytocontinue"];
		fgets(STDIN);
	}

}

/* Load ignore update file list. e.g. Standalone Version */
$ignore=array();
if(file_exists("data/updateignore")){
	$ignore=explode("\n",str_replace("\r\n","\n",file_get_contents("data/updateignore")));
}

/* Check local hash.dat exists */
if(! file_exists("hash.dat")){
	die("Fatal Error: hash.dat not exists!");
}

/* Remote Hash Table */
$query="GET /git/sign.dat HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n";
echo "Grabbing sign.dat:\r\n";
$sign=request($query,$host);
$sign=base64_decode($sign);

$query="GET /git/hash.dat HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n";
echo "Grabbing hash.dat:\r\n";
$response=request($query,$host);

if(!file_exists("data/wwqgtxx-goagent.pubkey")){
	echo $str["cert_notexists"];
	echo $str["anykeytocontinue"];
	fgets(STDIN);
}else{

	if($pubkey=openssl_get_publickey(file_get_contents("data/wwqgtxx-goagent.pubkey"))){
		while($verify=openssl_verify(md5($response),$sign,$pubkey,OPENSSL_ALGO_MD5)){
			echo "\r\nVerifying signature of hash.dat, result=";
			if($verify == "1"){
				echo "OK!\r\n";
				break;
			}else{
				echo "FAIL!\r\n";
				echo $str["sign_incorrect"];
				echo $str["retryin3seconds"];
				sleep(3);
			}
		}
	}else{
		echo $str["cert_corrupted"];
		echo $str["anykeytocontinue"];
		fgets(STDIN);
	}
}

$response=explode("\r\n",$response);
foreach($response as $value){
	unset($remotefilename,$remotefilehash);
	$value=explode("  ",$value);
	$remotefilehash=$value[0];
	unset($value[0]);
	$remotefilename=implode("  ",$value);
	$remotefilename=str_replace("\\","/",$remotefilename);
	$remotefile[$remotefilename]=$remotefilehash;
}

/* Local Hash Table */
unset($response);
$response=file_get_contents("hash.dat");
$response=explode("\r\n",$response);
foreach($response as $value){
	unset($localfilename,$localfilehash);
	$value=explode("  ",$value);
	$localfilehash=$value[0];
	unset($value[0]);
	$localfilename=implode("  ",$value);
	$localfilename=str_replace("\\","/",$localfilename);
	$localfile[$localfilename]=$localfilehash;
}

/* Proceed Hash Checking */
foreach($remotefile as $remotekey=>$remotevalue){
	if($remotevalue != $localfile[$remotekey]){
		if(preg_match('/\.\/data\/wwqgtxx-goagent\.pubkey/',$remotekey)){
			if(file_exists('data/wwqgtxx-goagent.pubkey')){
				continue; //Protect public key
			}
		}
		
		if(! preg_match('/\.\/\.svn\//',$remotekey)){
			if(! in_array($remotekey,$ignore)){
				update($remotekey,$remotevalue);
			}
		}
	}
}

echo "\r\n";