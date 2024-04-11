<?php
include("config.php");
ini_set('display_errors', 1);

$database = $scrt_config['db'];

$rowNum = mysqli_num_rows($database->sendSQLRequest("SHOW TABLES LIKE 'SCRTSessions'"));
if($rowNum <= 0){
	$database->createTable(
		"SCRTSessions", 
		array("id", "aesKey"), 
		array("TEXT", "TEXT")
	);
}

if(isset($_GET['data']) && isset($_GET['sym'])){
	$result = $database->sendSQLRequest("SELECT * FROM SCRTprivateCertificate");
	$result = mysqli_fetch_assoc($result);
	$privateKey = openssl_pkey_get_private($result['cert']);
	$session = hash('sha256', $_SERVER['REMOTE_ADDR'].time().rand(0, 99999));
	$size = (int) $_GET['sym'];
	if(!isset($_GET['platform']) && openssl_private_decrypt(hex2bin($_GET['data']), $decryptedData, $privateKey, OPENSSL_NO_PADDING) != false){
		$decryptedData = substr($decryptedData, $size * -1);
		$counter = 0;
		$dbres = false;
		while(!$dbres && $counter < 5){
			$dbres = $database->sendSQLRequest("INSERT INTO SCRTSessions (id, aesKey) VALUES ('$session', '$decryptedData')");
			$counter++;
		}
		if(!$dbres) echo "The handshake is not completed ".mysqli_error($database->db);
		else echo $session;
	} else if($_GET['platform'] == "cpp" && openssl_private_decrypt(hex2bin($_GET['data']), $decryptedData, $privateKey, OPENSSL_NO_PADDING) != false){
		$decryptedData = substr($decryptedData, $size * -1);
		$counter = 0;
		$dbres = false;
		while(!$dbres && $counter < 5){
			$dbres = $database->sendSQLRequest("INSERT INTO SCRTSessions (id, aesKey) VALUES ('$session', '$decryptedData')");
			$counter++;
		}
		if(!$dbres) echo "The handshake is not completed ".mysqli_error($database->db);
		else echo $session;
	} else if($_GET['platform'] == "php" && openssl_private_decrypt(hex2bin($_GET['data']), $decryptedData, $privateKey) != false){
		$decryptedData = substr($decryptedData, $size * -1);
		$counter = 0;
		$dbres = false;
		while(!$dbres && $counter < 5){
			$dbres = $database->sendSQLRequest("INSERT INTO SCRTSessions (id, aesKey) VALUES ('$session', '$decryptedData')");
			$counter++;
		}
		if(!$dbres) echo "The handshake is not completed ".mysqli_error($database->db);
		else echo $session;
	} else {
		echo "The handshake is not completed ".openssl_error_string();
	}
} else {
	echo "The handshake is not completed";
}

?>