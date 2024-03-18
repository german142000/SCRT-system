<?php
include("config.php");
ini_set('display_errors', 1);
$param = json_decode(file_get_contents($scrt_config["scrt_directory"]."/certificate/param.json"), true);
$data = json_encode(array("scrt_version" => $scrt_config["version"], "keyId" => $param["keyId"]));
echo $data;
?>