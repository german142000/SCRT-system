<?php
//ini_set('display_errors', 1);

function base64url_encode($input) {
 	return strtr(base64_encode($input), '+/=', '-_.');
}

function base64url_decode($input) {
	return base64_decode(strtr($input, '-_.', '+/='));
}

function AES128_encrypt($data, $key) {
    $buf_length = 0;
    $out_length = 0;
    $size = strlen($data);
    $padding = 0;
    while ($size % 16 != 0) {
        $size++;
        $padding++;
    }
	//$iv = "0000000000000000";
    $iv = openssl_random_pseudo_bytes(16);
    $ctx = openssl_encrypt($data, "AES-128-CBC", base64_decode($key), OPENSSL_RAW_DATA, $iv);
    $encrypted_data = $ctx . $iv . chr($padding);
    $base64_encoded = base64url_encode($encrypted_data);
    return $base64_encoded;
}

function AES128_decrypt($data, $key) {
    $data = base64url_decode($data);
	$padding = ord(substr($data, -1));
	$iv = substr($data, -17, -1);
	$encrypt_data = substr($data, 0, -17);
    $decrypted_data = openssl_decrypt($encrypt_data, 'aes-128-cbc', base64_decode($key), OPENSSL_RAW_DATA, $iv);
    return $decrypted_data;
}
?>