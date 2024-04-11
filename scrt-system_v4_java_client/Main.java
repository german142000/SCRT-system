import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

import java.security.SecureRandom;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.github.mervick.aes_everywhere.Aes256;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import java.util.Scanner;
import java.net.URLEncoder;

class RSA {
	
	public static String openc(String data, String publicKeyJWK) throws Exception {
        JSONParser json = new JSONParser();
        JSONObject jwk = (JSONObject) json.parse(publicKeyJWK);
        String modulus = (String) jwk.get("n");
        String exponent = (String) jwk.get("e");
        BigInteger modulusBigInt = new BigInteger(1, Base64.getDecoder().decode(modulus));
        BigInteger exponentBigInt = new BigInteger(1, Base64.getDecoder().decode(exponent));
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulusBigInt, exponentBigInt);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : encryptedBytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}

class HttpResponse {
    private int status;
    private String data;
    private String url;
    
    public int getStatus() {
        return status;
    }
    public void setStatus(int status) {
        this.status = status;
    }
    public String getData() {
        return data;
    }
    public void setData(String data) {
        this.data = data;
    }
    public void setUrl(String url){
    	this.url = url;
    }
    public String getUrl(){
    	return url;
    }
}

class HttpUtils {
    
    public static HttpResponse get(String url) {
        HttpResponse response = new HttpResponse();
        response.setUrl(url);
        try {
            URL requestUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) requestUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            response.setStatus(responseCode);
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder data = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                data.append(line);
            }
            reader.close();
            response.setData(data.toString());
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return response;
    }
}

class SCRT_pack {
	boolean error = false;
	String data = "";
}

class SCRT_config {
	private String scrt_version = "1.0.0";
	public String scrt_cert_address = "http://127.0.0.1/scrt-system_v3";
	public String scrt_host_address = "http://127.0.0.1/scrt-system_v3_host";
	public String keeper = "127.0.0.1";
	
	public String get_version(){
		return scrt_version;
	}
}

class SCRT_session {
    
    private String error;
    private boolean erb = false;
    private String session_id = "";
    private String aes_key = "";
    private SCRT_config cnf;
    
    public String encodeBase64Url(String input) {
        return input.replace('+', '-').replace('/', '_').replace('=', '.');
    }

    public String decodeBase64Url(String input) {
        return input.replace('-', '+').replace('_', '/').replace('.', '=');
    }
    
    public String grnas(int min, int max) {
        Random random = new Random();
        int randomNumber = random.nextInt((max - min) + 1) + min;
        return String.valueOf(randomNumber);
    }
    
    public String grs(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : randomBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
	}
    
    public SCRT_session(){
        try {
            JSONParser json = new JSONParser();
            cnf = new SCRT_config();
            HttpResponse res = HttpUtils.get(cnf.scrt_host_address + "/getKeyId.php");
            if(res.getStatus() != 200){
            	this.error = "http error - " + res.getUrl() + " - " + res.getStatus();
            	this.erb = true;
            	return;
            }
            JSONObject kino = (JSONObject) json.parse(res.getData());
            if(!kino.get("scrt_version").equals("1.0.0")){
            	this.error = "incompatible SCRT server and client versions";
            	this.erb = true;
            	return;
            }
            String keyId = (String) kino.get("keyId");
            res = HttpUtils.get(cnf.scrt_cert_address + "/getVersion.php");
            if(res.getStatus() != 200){
            	this.error = "http error - " + res.getUrl() + " - " + res.getStatus();
            	this.erb = true;
            	return;
            }
            if(!res.getData().equals("1.0.0")){
            	this.error = "incompatible SCRT certificate server and client versions";
            	this.erb = true;
            	return;
            }
            res = HttpUtils.get(cnf.scrt_cert_address + "/getJWKpublicKey.php?id=" + keyId + "&keeper=" + cnf.keeper);
        	if(res.getStatus() != 200){
            	this.error = "http error - " + res.getUrl() + " - " + res.getStatus();
            	this.erb = true;
            	return;
            }
            String aeskey = this.grs(16);
            String encAESkey = RSA.openc(aeskey, res.getData());
            int sym = aeskey.length();
            res = HttpUtils.get(cnf.scrt_host_address + "/handshake.php?data=" + encAESkey + "&sym=" + sym);
        	if(res.getStatus() != 200){
            	this.error = "http error - " + res.getUrl() + " - " + res.getStatus();
            	this.erb = true;
            	return;
            }
            String session = res.getData();
            String verData = grnas(0, 99999);
            String enc = Aes256.encrypt(verData, aeskey);
            res = HttpUtils.get(cnf.scrt_host_address + "/verification.php?data=" + enc + "&session=" + session);
        	if(res.getStatus() != 200){
            	this.error = "http error - " + res.getUrl() + " - " + res.getStatus();
            	this.erb = true;
            	return;
            }
            if(!verData.equals(res.getData())){
            	this.error = "server don't trust. try to create a new session";
            	this.erb= true;
            	return;
            } else {
            	this.session_id = session;
            	this.aes_key = aeskey;
            }
        } catch (Exception e) {
        	System.out.println(e);
        	e.printStackTrace();
        }
    }
    
    public boolean getErrorStatus(){
    	return erb;
    }
    
    public String getError(){
    	return error;
    }
    
    public SCRT_pack sendData(String url, String data){
    	SCRT_pack resPack = new SCRT_pack();
    	try {
    		String encData = Aes256.encrypt(data, aes_key);
    		JSONObject pack = new JSONObject();
    		pack.put("session", session_id);
    		pack.put("data", encData);
    		String jsonPack = pack.toJSONString();
    		HttpResponse res = HttpUtils.get(url + "?data=" + URLEncoder.encode(jsonPack, "UTF-8") + "&platform=java");
        	if(res.getStatus() != 200){
        		resPack.data = "http error - " + res.getUrl() + " - " + res.getStatus();
        		resPack.error = true;
        		return resPack;
        	}
        	if(res.getData().equals("error")){
        		return this.sendData(url, data);
       	 }
        	JSONParser json = new JSONParser();
        	JSONObject reqpack = (JSONObject) json.parse(res.getData());
        	String edt = (String) reqpack.get("data");
        	String decData = Aes256.decrypt(edt, aes_key);
        	resPack.data = decData;
        	return resPack;
        } catch (Exception e) {
        	resPack.error = true;
        	resPack.data = e.getMessage();
        	return resPack;
        }
    }
}

public class Main {
    
    public static void main(String[] args) {
        System.out.println("Hello, World!");
        SCRT_session ss = new SCRT_session();
        while(ss.getErrorStatus() && ss.getError().equals("server don't trust. try to create a new session")){
        	ss = new SCRT_session();
        }
        System.out.println("server trust, enter data");
        Scanner scanner = new Scanner(System.in);
        while(true){
        	String input = scanner.nextLine();
        	System.out.println(ss.sendData("http://127.0.0.1/test.php", input).data);
        }
        //scanner.close();
    }
}
