package pt.ulisboa.tecnico.SECDPAS;

import java.security.*;


public class SignatureHandler {

	public static final String HMAC_ALGO = "HmacSHA256";
	public static final String PUB_SIGN_ALGO = "SHA256withRSA";
	public static final int KEY_SIZE = 256;

	public static byte[] publicSign(byte[] message, PrivateKey privateKey){
		Signature signature;

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
		Signature sign;

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
