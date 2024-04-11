<?php
ini_set('display_errors', 1);
include("config.php");
include("AES256.php");
include("AESCPP.php");

use mervick\aesEverywhere\AES256;

$database = $scrt_config["db"];

if(isset($_GET['data']) && isset($_GET['session'])){
	$session = $_GET['session'];
	$result = $database->sendSQLRequest("SELECT * FROM SCRTSessions WHERE id = '$session'");
	$key = mysqli_fetch_assoc($result)['aesKey'];
	if(!isset($_GET['platform'])){
		$dres = AES256::decrypt($_GET['data'], $key);
		if($dres == null){
			echo "error";
		} else {
			echo $dres;
		}
	} else if($_GET['platform'] == "cpp"){
		$dres = AES128_decrypt($_GET['data'], $key);
		if($dres == null){
			echo "error " . openssl_error_string();
		} else {
			echo $dres;
		}
	}
} else {
	echo "error";
}
?>