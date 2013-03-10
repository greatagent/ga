<?php
#  wwqgtxx-goagent   - Software suite for breakthrough GFW
#  wwqgtxx-wallproxy - Software suite for breakthrough GFW
#  
#  updategc.php - Updata Our Files From GoogleCode
#  "gc" is stand for googleCode.

/* Set Current Directory */
preg_match('/(.*?)\\\updategc\.php$/',__FILE__,$currentdir); 
chdir($currentdir[1]);



if(file_exists("data/usegctest")){
	$host = "goagenttest.wwqgtxx-goagent.googlecode.com";
}else if(file_exists("data/usegc2")){
	$host = "goagent.wwqgtxx-wallproxy.googlecode.com";
}else{
	$host = "goagent.wwqgtxx-goagent.googlecode.com";
}



/* */
file_exists("string.inc.php") && require_once("string.inc.php");
require_once("makegservers.inc.php");

/* FUNCTION */
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
	
	if(sha1($response)==$hash){
		if(dirname($filename)!="." && ! file_exists(dirname($filename))){
			mkdir(dirname($filename),0,true);
		}
		file_put_contents($filename,$response);
	}else{
		echo $str["hash_sign_incorrect"];
		echo $str["anykeytocontinue"];
		echo ">"; fgets(STDIN);
	}

}

/* Load ignore update file list. e.g. Standalone Version */
$ignore=array();
if(file_exists("data/updateignore")){
	$ignore=explode("\n",str_replace("\r\n","\n",file_get_contents("data/updateignore")));
}

/* Check local hash.sha1 exists */
if(! file_exists("hash.sha1")){
	die("Fatal Error: hash.sha1 not exists!");
}

echo "Update Server:";
echo $host;
echo "\r\n";

/* Remote Hash Table */
$query="GET /git/sign.sha1 HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n";
echo "Grabbing sign.sha1:\r\n";
$sign=request($query,$host);
$sign=base64_decode($sign);

$query="GET /git/hash.sha1 HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n";
echo "Grabbing hash.sha1:\r\n";
$response=request($query,$host);

if(!file_exists("data/wwqgtxx-goagent.pubkey")){
	echo $str["cert_notexists"];
	echo $str["anykeytocontinue"];
	echo ">"; fgets(STDIN);
}else{

	if($pubkey=openssl_get_publickey(file_get_contents("data/wwqgtxx-goagent.pubkey"))){
		while($verify=openssl_verify(sha1($response),$sign,$pubkey,OPENSSL_ALGO_SHA1)){
			echo "\r\nVerifying signature of hash.sha1, result=";
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
		echo ">"; fgets(STDIN);
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
$response=file_get_contents("hash.sha1");
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
		
		if(! preg_match('/\.\/\.git\//',$remotekey)){
			if(! in_array($remotekey,$ignore)){
				update($remotekey,$remotevalue);
			}
		}
	}
}

echo "\r\n";

echo "Show Version Message:\r\n";
if($file=@file_get_contents("data/version")){
	echo $file;
	echo "\r\n";
}else{
	echo "Not Version Message!\r\n";
}

echo "\r\n";

?>