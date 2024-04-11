<?php
//ini_set('display_errors', 1);
include("AES256.php");
include("AESCPP.php");
use mervick\aesEverywhere\AES256;

function unpackData($data){
	include("config.php");
	$sdb = $scrt_config["db"];
	$data = json_decode($data, true);
	$session = $data["session"];
	$result = $sdb->sendSQLRequest("SELECT * FROM SCRTSessions WHERE id = '$session'");
	if(mysqli_num_rows($result) == 0) return "session_not_found";
	$aesKey = mysqli_fetch_assoc($result)['aesKey'];
	$dec = AES256::decrypt($data["data"], $aesKey);
	return array("session" => $session, "data" => $dec);
}

function packData($data, $session){
	include("config.php");
	$sdb = $scrt_config["db"];
	$result = $sdb->sendSQLRequest("SELECT * FROM SCRTSessions WHERE id = '$session'");
	if(mysqli_num_rows($result) == 0) return "session_not_found";
	$aesKey = mysqli_fetch_assoc($result)['aesKey'];
	$enc = AES256::encrypt($data, $aesKey);
	return json_encode(array("session" => $session, "data" => $enc));
}

function unpackData_CPP($data){
	include("config.php");
	$sdb = $scrt_config["db"];
	$data = json_decode($data, true);
	//print_r($data);
	$session = $data["session"];
	$result = $sdb->sendSQLRequest("SELECT * FROM SCRTSessions WHERE id = '$session'");
	if(mysqli_num_rows($result) == 0) return "session_not_found";
	$aesKey = mysqli_fetch_assoc($result)['aesKey'];
	$dec = AES128_decrypt($data["data"], $aesKey);
	return array("session" => $session, "data" => $dec);
}

function packData_CPP($data, $session){
	include("config.php");
	$sdb = $scrt_config["db"];
	$result = $sdb->sendSQLRequest("SELECT * FROM SCRTSessions WHERE id = '$session'");
	if(mysqli_num_rows($result) == 0) return "session_not_found";
	$aesKey = mysqli_fetch_assoc($result)['aesKey'];
	$enc = AES128_encrypt($data, $aesKey);
	return json_encode(array("session" => $session, "data" => $enc));	
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