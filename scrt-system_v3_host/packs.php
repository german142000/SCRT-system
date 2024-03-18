<?php
//ini_set('display_errors', 1);
include("AES256.php");
include("AESCPP.php");
use mervick\aesEverywhere\AES256;

function unpackData($data){
	include("config.php");
	$data = json_decode($data, true);
	$session = $data["session"];
	$sessionDirectory = $scrt_config["scrt_directory"]."/sessions";
	$sessionPath = $sessionDirectory."/".$session.".ss";
	if(file_exists($sessionPath)){
		$aesKey = file_get_contents($sessionPath);
		$dec = AES256::decrypt($data["data"], $aesKey);
		return array("session" => $session, "data" => $dec);
	} else {
		return false;
	}	
}

function packData($data, $session){
	include("config.php");
	$sessionDirectory = $scrt_config["scrt_directory"]."/sessions";
	$sessionPath = $sessionDirectory."/".$session.".ss";
	if(file_exists($sessionPath)){
		$aesKey = file_get_contents($sessionPath);
		$enc = AES256::encrypt($data, $aesKey);
		return json_encode(array("session" => $session, "data" => $enc));
	} else {
		return false;
	}	
}

function unpackData_CPP($data){
	include("config.php");
	$data = json_decode($data, true);
	//print_r($data);
	$session = $data["session"];
	$sessionDirectory = $scrt_config["scrt_directory"]."/sessions";
	$sessionPath = $sessionDirectory."/".$session.".ss";
	if(file_exists($sessionPath)){
		$aesKey = file_get_contents($sessionPath);
		$dec = AES128_decrypt($data["data"], $aesKey);
		return array("session" => $session, "data" => $dec);
	} else {
		return false;
	}	
}

function packData_CPP($data, $session){
	include("config.php");
	$sessionDirectory = $scrt_config["scrt_directory"]."/sessions";
	$sessionPath = $sessionDirectory."/".$session.".ss";
	if(file_exists($sessionPath)){
		$aesKey = file_get_contents($sessionPath);
		$enc = AES128_encrypt($data, $aesKey);
		return json_encode(array("session" => $session, "data" => $enc));
	} else {
		return false;
	}	
}

function getData(){
	if(isset($_GET['platform']) && $_GET['platform'] == "cpp"){
		$res = unpackData_CPP($_GET['data']);
		if($res['data'] == "") {
			header($_SERVER["SERVER_PROTOCOL"] . " 500 Data decryption error");
			exit;
		}
		return $res;
	} else {
		$res = unpackData($_GET['data']);
		return $res;
	}
}

function sendData($data, $session){
	if(isset($_GET['platform']) && $_GET['platform'] == "cpp"){
		echo packData_CPP($data, $session);
	} else {
		echo packData($data, $session);
	}
}

?>