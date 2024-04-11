<?php
include("config.php");
ini_set('display_errors', 1);
$database = $scrt_config['db'];
$result = $database->sendSQLRequest("SELECT * FROM SCRTprivateCertificate");
$result = mysqli_fetch_assoc($result);
$data = json_encode(array("scrt_version" => $scrt_config["version"], "keyId" => $result['keyId']));
echo $data;
?>