package pt.ulisboa.tecnico.SECDPAS;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Consumer;
import java.util.function.Supplier;


public class DiffieHellmanClient {

    private byte[] sharedSecret;
    public static final int KEY_SIZE = 2048;
    private KeyAgreement clientKeyAgreement;


    public SecretKey getSharedHMACKey() {
        return new SecretKeySpec(sharedSecret, 0, SignatureHandler.KEY_SIZE / Byte.SIZE, SignatureHandler.HMAC_ALGO);
    }

    public byte[] prepareAgreement() throws SignatureException {
        try {
            clientKeyAgreement = KeyAgreement.getInstance("DH");
        } catch (NoSuchAlgorithmException e) {
            // This exception depends only on the parameters used, so shouldn't happen
            return null;
        }

        if(clientKeyAgreement == null){
            throw new SignatureException();
        }

        return getPublicKey(clientKeyAgreement);
    }

    public void execute(byte[] serverEncodedKeyAgreement) {

        doPhase(serverEncodedKeyAgreement, clientKeyAgreement);

        /*
         * At this stage, both the Client and the Server have completed the DH key
         * agreement protocol.
         * Both generate the (same) shared secret.
         */
        sharedSecret = clientKeyAgreement.generateSecret();

        StringBuilder builder = new StringBuilder();
        for(byte b : sharedSecret) {
            builder.append(String.format("%02x", b));
        }

        System.out.println("Shared secret: " + builder.toString());
        System.out.println("Length: " + sharedSecret.length);
    }

	// Should be sent over to other party
	private byte[] getPublicKey(KeyAgreement clientKeyAgree) {
		/*
         * Client creates his own DH key pair with 2048-bit key size
         */
        KeyPairGenerator clientKpairGen = null;
        try {
            clientKpairGen = KeyPairGenerator.getInstance("DH");

            clientKpairGen.initialize(KEY_SIZE);
            KeyPair clientKpair = clientKpairGen.generateKeyPair();

            clientKeyAgree.init(clientKpair.getPrivate());

            // Client encodes his public key, to be sent over to the Server.
            return clientKpair.getPublic().getEncoded();

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            // This exception depends only on the parameters used, so shouldn't happen
        }
        return null;
    }

	private void doPhase(byte[] serverPubKeyEnc, KeyAgreement clientKeyAgree) {
        KeyFactory clientKeyFac = null;
        try {
            /*
             * Client uses Server's public key for the first (and only) phase
             * of his version of the DH
             * protocol.
             * Before he can do so, he has to instantiate a DH public key
             * from the Server's encoded key material.
             */
            clientKeyFac = KeyFactory.getInstance("DH");

            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
            PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
            clientKeyAgree.doPhase(serverPubKey, true);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
        }


	}
}