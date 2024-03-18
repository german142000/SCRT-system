<?php
//getCertificate.php?id=27f00f31290841ca5686fd0f0cc7ba81c15d46dc46070e34d90a12be097fdacf&keeper=185.185.69.85
include("config.php");

function base64url_encode($data) {
    $base64 = base64_encode($data);
    $base64url = str_replace(array('+', '/', '='), array('-', '_', ''), $base64);
    return $base64url;
}

if(isset($_GET['id']) && isset($_GET['keeper'])){
	if(!filter_var($_GET['keeper'], FILTER_VALIDATE_IP)){
		echo "\"keeper\" must be an IP address";
		exit(0);
	}
	if(file_exists($scrt_config["scrt_directory"]."/certificates/".$_GET['id'])){
		$param = file_get_contents($scrt_config["scrt_directory"]."/certificates/".$_GET['id']."/param.json");
		$param = json_decode($param, true);
		if($param['keeper'] == $_GET['keeper'] && $param['trust'] == "yes" && $param['expire'] > time()){
			$key = file_get_contents($scrt_config["scrt_directory"]."/certificates/".$_GET['id']."/public_key.pem");
			$keyrc = openssl_pkey_get_public($key);
			$details = openssl_pkey_get_details($keyrc);
			$jwk = [
    			'kty' => 'RSA',
    			'n' => base64_encode($details['rsa']['n']),
    			'e' => base64_encode($details['rsa']['e'])
			];
			$jwkJson = json_encode($jwk);
			echo $jwkJson;
		} else {
			echo "not found";
			exit(0);
		}
	} else {
		echo "not found";
		exit(0);
	}
} else {
	echo "not found";
	exit(0);
}
?>