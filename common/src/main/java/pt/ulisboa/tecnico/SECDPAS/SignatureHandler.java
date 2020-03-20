package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.List;


public class SignatureHandler {

	private Mac mac;
	public static final String HMAC_ALGO = "HmacSHA256";
	public static final String PUB_SIGN_ALGO = "SHA256withRSA";
	public static final int KEY_SIZE = 256;

	public SignatureHandler(SecretKey sharedHMACKey) {
		System.out.println("\n\n\nIs null\n\n\n");
		if(sharedHMACKey == null){
			return;
		}

		System.out.println("\n\n\nIs not null\n\n\n");

		try {
			this.mac = Mac.getInstance(HMAC_ALGO);
			this.mac.init(sharedHMACKey);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	public byte[] sign(byte[] message){

		byte[] signature = mac.doFinal(message);

		StringBuilder builder = new StringBuilder();
		for(byte b : signature) {
			builder.append(String.format("%02x", b));
		}

		System.out.println("Sent Signature: " + builder.toString());

		builder = new StringBuilder();
		for(byte b : message) {
			builder.append(String.format("%02x", b));
		}

		System.out.println("Sent Complete Message: " + builder.toString());

		return signature;
	}

	public boolean verifySignature(byte[] message, byte[] signature){
		byte[] check = mac.doFinal(message);

		StringBuilder builder = new StringBuilder();
		for(byte b : signature) {
			builder.append(String.format("%02x", b));
		}

		System.out.println("Received Signature: " + builder.toString());

		builder = new StringBuilder();
		for(byte b : check) {
			builder.append(String.format("%02x", b));
		}
		System.out.println("Expected Signature: " + builder.toString());

		builder = new StringBuilder();
		for(byte b : message) {
			builder.append(String.format("%02x", b));
		}
		System.out.println("Received Complete Message: " + builder.toString());

		return Arrays.equals(check, signature);
	}

	public static byte[] publicSign(byte[] message, PrivateKey privateKey){
		Signature signature = null;

		try {
			signature = Signature.getInstance(PUB_SIGN_ALGO);
			signature.initSign(privateKey);
			signature.update(message);

			return signature.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			return null;
		}
	}

	public static boolean verifyPublicSignature(byte[] message, byte[] signature, PublicKey publicKey){
		Signature sign = null;

		try {
			sign = Signature.getInstance(PUB_SIGN_ALGO);
			sign.initVerify(publicKey);
			sign.update(message);

			return sign.verify(signature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			return false;
		}
	}
}
