<?php
if(!class_exists("mervick\aesEverywhere\AES256")){
	require_once "AES256.php";
}

class HttpResponse {
	private $status = false;
    private $data;
    private $url;
    function getData() {
        return $this->data;
    }
    function setData($data) {
        $this->data = $data;
    }
    function getUrl(){
    	return $this->url;
    }
	function setUrl($url){
    	$this->url = $url;
    }
	function error(){
		$this->status = true;
	}
	function getStatus(){
		return $this->status;
	}
}

class HttpUtils {
	 static function get($url){
	 	$options = [
    		'http' => [
        		'method' => 'GET',
        		'timeout' => 10,
    		],
		];
		$response = new HttpResponse();
	 	$response->setUrl($url);
	 	$gres = file_get_contents($url, false, stream_context_create($options));
	 	if ($gres === false) {
    		$response->error();
			return $response;
		} else {
    		$response->setData($gres);
			return $response;
		}
	}
}

class SCRT_pack {
	public $error = false;
	public $data = "";
}

class SCRT_config {
	private $scrt_version = "1.0.0";
	public $scrt_cert_address = "http://127.0.0.1/scrt-system_v3";
	public $scrt_host_address = "http://127.0.0.1/scrt-system_v3_host";
	public $keeper = "127.0.0.1";
	function get_version(){
		return $scrt_version;
	}
}

class SCRT_session {
    
    private $error;
    private $erb = false;
    private $session_id = "";
    private $aes_key = "";
    private $cnf;

	private function grs($bytes) {
    	$binaryString = random_bytes($bytes);
    	$base64String = base64_encode($binaryString);
    	$randomString = substr($base64String, 0, $bytes);
    	return $randomString;
	}

	function __construct($config){
		$this->cnf = $config;
		$res = HttpUtils::get($this->cnf->scrt_host_address."/getKeyId.php");
		if($res->getStatus()){
			$this->error = "http error - ".$res->getUrl();
			$this->erb = true;
			return;
		}
		$kino = json_decode($res->getData(), true);
		if($kino['scrt_version'] != "1.0.0"){
			$this->error = "incompatible SCRT server and client versions";
			$this->erb = true;
			return;
		}
		$keyId = $kino["keyId"];
		$res = HttpUtils::get($this->cnf->scrt_cert_address."/getVersion.php");
		if($res->getStatus()){
			$this->error = "http error - ".$res->getUrl();
			$this->erb = true;
			return;
		}
		if($res->getData() != "1.0.0"){
			$this->error = "incompatible SCRT certificate server and client versions";
			$this->erb = true;
			return;
		}
		$res = HttpUtils::get($this->cnf->scrt_cert_address."/getPEMpublicKey.php?id=".$keyId."&keeper=".$this->cnf->keeper);
		if($res->getStatus()){
			$this->error = "http error - ".$res->getUrl();
			$this->erb = true;
			return;
		}
		$cert = implode("\n", json_decode($res->getData(), true));
		$aesKey = $this->grs(64);
		$publicKey = openssl_pkey_get_public($cert);
		$sym = strlen($aesKey);
		if(!openssl_public_encrypt($aesKey, $encAESkey, $publicKey)){
			$this->error = "openssl error - ".openssl_error_string()." ".$aesKey;
			$this->erb = true;
			return;
		}
		$res = HttpUtils::get($this->cnf->scrt_host_address."/handshake.php?data=".bin2hex($encAESkey)."&sym=".$sym."&platform=php");
		if($res->getStatus()){
			$this->error = "http error - ".$res->getUrl();
			$this->erb = true;
			return;
		}
		$session = $res->getData();
		$verData = rand(0, 99999);
		$encVerData = mervick\aesEverywhere\AES256::encrypt($verData, $aesKey);
		$res = HttpUtils::get($this->cnf->scrt_host_address."/verification.php?data=".$encVerData."&session=".$session);
		if($res->getStatus()){
			$this->error = "http error - ".$res->getUrl();
			$this->erb = true;
			return;
		}
		if($verData != $res->getData()){
            $this->error = "server don't trust. try to create a new session";
            $this->erb = true;
            return;
        } else {
            $this->session_id = $session;
            $this->aes_key = $aesKey;
        }
	}

	function getErrorStatus(){
    	return $this->erb;
    }
    
    function getError(){
    	return $this->error;
    }

	function sendData($url, $data){
		$resPack = new SCRT_pack();
		$endData = mervick\aesEverywhere\AES256::encrypt($data, $this->aes_key);
		$packData = array("session" => $this->session_id, "data" => $endData);
		$res = HttpUtils::get($url."?data=".urlencode(json_encode($packData)));
		if($res->getStatus()){
			$resPack->data = "http error - ".$res->getUrl();
			$resPack->error = true;
			return $resPack;
		}
		$sres = json_decode($res->getData(), true);
		$encData = mervick\aesEverywhere\AES256::decrypt($sres['data'], $this->aes_key);
		$resPack->data = $encData;
		return $resPack;
	}
};
?>