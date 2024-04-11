<?php
include("config.php");
if(isset($_GET['product']) && isset($_GET['month']) && isset($_GET['keeper']) && isset($_GET['pass'])){
	if($_GET['pass'] != $scrt_config["password"]){
		echo "wrong password";
		exit(0);
	}
	if(!filter_var($_GET['keeper'], FILTER_VALIDATE_IP)){
		echo "\"keeper\" must be an IP address";
		exit(0);
	}
	$ctime = time();
	$exTime = $ctime + (int) $_GET['month'] * 2592000;
	$keyId = hash('sha256', $_GET['product'].$ctime);
	$keyParam = array(
		"keyId" => $keyId,
		"created" => $ctime,
		"expire" => $exTime,
		"product" => $_GET['product'],
		"keyBits" => $scrt_config["keyBits"],
		"keeper" => $_GET['keeper'],
		"trust" => "yes"
	);	
	mkdir($scrt_config["scrt_directory"]."/certificates/".$keyId, 0777, true);
	$config = array(
		"private_key_bits" => $scrt_config["keyBits"],
		"private_key_type" => OPENSSL_KEYTYPE_RSA,
	);
	$privateKey = openssl_pkey_new($config);
	openssl_pkey_export_to_file($privateKey, $scrt_config["scrt_directory"]."/certificates/".$keyId."/private_key.pem");
	$publicKey = openssl_pkey_get_details($privateKey);
	file_put_contents($scrt_config["scrt_directory"]."/certificates/".$keyId."/public_key.pem", $publicKey['key']);
	file_put_contents($scrt_config["scrt_directory"]."/certificates/".$keyId."/param.json", json_encode($keyParam, JSON_PRETTY_PRINT));
	openssl_free_key($privateKey);
	if(isset($_GET['sql']) && $_GET['sql'] == true){
		$privateKeyString = file_get_contents($scrt_config["scrt_directory"]."/certificates/".$keyId."/private_key.pem");
		$productString = $_GET['product'];
		$keyBits = $scrt_config["keyBits"];
		$keeper = $_GET['keeper'];
		$sqlFile = "DROP TABLE IF EXISTS SCRTprivateCertificate;";
		$sqlFile .= "CREATE TABLE SCRTprivateCertificate (cert TEXT, keyId TEXT, created TEXT, expire TEXT, 
														product TEXT, keyBits INT, keeper TEXT, trust TEXT);";
		$sqlFile .= "INSERT INTO SCRTprivateCertificate (cert, keyId, created, expire, product, keyBits, keeper, trust)
					 VALUES ('$privateKeyString', '$keyId', '$ctime', '$exTime', '$productString', $keyBits, '$keeper', 'yes');";
		file_put_contents($scrt_config["scrt_directory"]."/certificates/".$keyId."/private_key.sql", $sqlFile);
	}
	echo $keyId;
	exit(0);
} else {
	echo "not all parameters are specified";
	exit(0);
}
?>