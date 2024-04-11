<?php
require_once "sdatabase/main.php";

$scrt_config = array(
	"version" => "1.0.0",
	"scrt_directory" => $_SERVER['DOCUMENT_ROOT']."/scrt-system_v4_host",
	"password" => "password",
	"db" => new SCRTDatabase(),
);

$sdb = $scrt_config['db'];
$rowNum = mysqli_num_rows($sdb->sendSQLRequest("SHOW TABLES LIKE 'SCRTSessions'"));
if($rowNum <= 0){
	$sdb->createTable(
		"SCRTSessions", 
		array("id", "aesKey"), 
		array("TEXT", "TEXT")
	);
}

?>