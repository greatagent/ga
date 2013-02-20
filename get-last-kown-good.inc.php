<?php
#  wwqgtxx-goagent - Software suite for breakthrough GFW
#  wwqgtxx-wallproxy - Software suite for breakthrough GFW
#  
#  get-last-kown-good.inc.php - Grabbing last-known-good file from SmartHosts and Huhamhire-Hosts
echo "\r\n";
echo "Grabbing last-known-good file from SmartHosts ,SmartLadder and Huhamhire-Hosts:\r\n";

require_once("makegservers.inc.php");
$googleip=array();

/* FUNCTION */
function update($host){
	$host=explode("\r\n",$host);
	foreach($host as $hostkey=>$hoststring){
		//talk.google.com is special case. We cannot use it as G-Server
		if(preg_match('/(.*?)\ttalk\.google\.com$/',$hoststring,$hostmatch)){
		}elseif(preg_match('/(.*?)\t.*?\.google\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.google\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.googleusercontent\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.gstatic\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.ggpht\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.appspot\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.googleapis\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.googlecode\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.google\.cn$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.blogger\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.googlesource\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.android\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.google-analytics\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.googleadservices\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.gmail\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.youtube\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}elseif(preg_match('/(.*?)\t.*?\.ytimg\.com$/',$hoststring,$hostmatch)){
			if(filter_var($hostmatch[1],FILTER_VALIDATE_IP)){
				$googleip[]=$hostmatch[1];
			}
		}
	}

}


echo "Grabbing SmartHosts hosts:\r\n";
update(request("GET /svn/trunk/hosts HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n","smarthosts.googlecode.com"));

echo "Grabbing SmartHosts mobile hosts:\r\n";
update(request("GET /svn/trunk/mobile_devices/hosts HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n","smarthosts.googlecode.com"));

echo "Grabbing SmartLadder hosts:\r\n";
update(request("GET /svn/trunk/hosts HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n","smartladder.googlecode.com"));

echo "Grabbing Huhamhire-Hosts hosts:\r\n";
update(request("GET /git/downloads/raw/ipv4_mobile_utf8/hosts HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n","huhamhire-hosts.googlecode.com"));

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