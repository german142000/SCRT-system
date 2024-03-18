<?php
ini_set('display_errors', 1);
include("config.php");
include("AES256.php");
include("AESCPP.php");

use mervick\aesEverywhere\AES256;

if(isset($_GET['data']) && isset($_GET['session'])){
	$sessionDirectory = $scrt_config["scrt_directory"]."/sessions";
	$sessionPath = $sessionDirectory."/".$_GET['session'].".ss";
	if(file_exists($sessionPath)){
		$key = file_get_contents($sessionPath);
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
} else {
	echo "error";
}
?>