<?php
#  wwqgtxx-goagent - Software suite for breakthrough GFW
#  
#  makegserver.inc.php - Reslove Google Server IP

$gservers=array();
$gdomains=array("www.google.com","mail.google.com","www.l.google.com","mail.l.google.com");

/* Grab GServer using DNS */
foreach($gdomains as $gdomain){
	$dns_responses=dns_get_record($gdomain,DNS_A);
	foreach($dns_responses as $dns_response){
		array_push($gservers,$dns_response["ip"]);
	}
}

//sort($gservers);
$gservers=array_unique($gservers);
?>