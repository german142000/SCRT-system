<?php
include("config.php");
if(isset($_GET['id']) && isset($_GET['keeper'])){
	if(!filter_var($_GET['keeper'], FILTER_VALIDATE_IP)){
		echo "\"keeper\" must be an IP address";
		exit(0);
	}
	if(file_exists($scrt_config["scrt_directory"]."/certificates/".$_GET['id'])){
		$param = file_get_contents($scrt_config["scrt_directory"]."/certificates/".$_GET['id']."/param.json");
		$param = json_decode($param, true);
		if($param['keeper'] == $_GET['keeper'] && $param['trust'] == "yes" && $param['expire'] > time()){
			$key = explode("\n", file_get_contents($scrt_config["scrt_directory"]."/certificates/".$_GET['id']."/public_key.pem"));
			echo json_encode($key);
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