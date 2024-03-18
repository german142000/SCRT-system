<?php
include("config.php");
ini_set('display_errors', 1);

if(isset($_GET['data']) && isset($_GET['sym'])){
	$privateKey = openssl_pkey_get_private("file://".$scrt_config["scrt_directory"]."/certificate/private_key.pem");
	$session = hash('sha256', $_SERVER['REMOTE_ADDR'].time());
	$sessionDirectory = $scrt_config["scrt_directory"]."/sessions";
	$sessionPath = $sessionDirectory."/".$session.".ss";
	$size = (int) $_GET['sym'];
	if(!isset($_GET['platform']) && openssl_private_decrypt(hex2bin($_GET['data']), $decryptedData, $privateKey, OPENSSL_NO_PADDING) != false){
		$decryptedData = substr($decryptedData, $size * -1);
		file_put_contents($sessionPath, $decryptedData);
		echo $session;
	} else if($_GET['platform'] == "cpp" && openssl_private_decrypt(hex2bin($_GET['data']), $decryptedData, $privateKey, OPENSSL_NO_PADDING) != false){
		$decryptedData = substr($decryptedData, $size * -1);
		file_put_contents($sessionPath, $decryptedData);
		echo $session;
	} else {
		echo "The handshake is not completed ".openssl_error_string();
	}
} else {
	echo "The handshake is not completed";
}

?>