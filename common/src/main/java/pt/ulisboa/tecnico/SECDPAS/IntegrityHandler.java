package pt.ulisboa.tecnico.SECDPAS;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Arrays;


public class IntegrityHandler {

	private Mac mac;
	public static final String HMAC_ALGO = "HmacSHA256";

	public IntegrityHandler(SecretKey sharedHMACKey) {
		if(sharedHMACKey == null){
			return;
		}

		try {
			this.mac = Mac.getInstance(HMAC_ALGO);
			this.mac.init(sharedHMACKey);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	public byte[] sign(byte[] message){
		return mac.doFinal(message);
	}

	public boolean verifySignature(byte[] message, byte[] signature){
		byte[] check = mac.doFinal(message);

		return Arrays.equals(check, signature);
	}

}
