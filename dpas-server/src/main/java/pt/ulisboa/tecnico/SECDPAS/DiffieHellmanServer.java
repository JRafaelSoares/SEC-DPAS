package pt.ulisboa.tecnico.SECDPAS;


import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Consumer;


public class DiffieHellmanServer {

    private byte[] sharedSecret = null;

    private final int KEY_SIZE = 2048;

    public SecretKey getSharedHMACKey() {
        return new SecretKeySpec(sharedSecret, 0, SignatureHandler.KEY_SIZE / 8, SignatureHandler.HMAC_ALGO);
    }

    public byte[] execute(byte[] clientPubKeyEnc) {

        KeyAgreement serverKeyAgree = null;

        try {
            serverKeyAgree = KeyAgreement.getInstance("DH");

        } catch (NoSuchAlgorithmException e) {
            // This exception depends only on the parameters used, so shouldn't happen
            System.out.println("\n\n\n\nWhat is this???\n\n\n\n");
            return null;
        }

        byte[] toSend = getPublicKeyAndDoPhase(clientPubKeyEnc, serverKeyAgree);

        /*
         * At this stage, both the Client and the Server have completed the DH key
         * agreement protocol.
         * Both generate the (same) shared key.
         */
        sharedSecret = serverKeyAgree.generateSecret();

        StringBuilder builder = new StringBuilder();
        for(byte b : sharedSecret) {
            builder.append(String.format("%02x", b));
        }

        System.out.println("Shared secret: " + builder.toString());

        System.out.println("Length: " + sharedSecret.length);

        return toSend;
    }

    private byte[] getPublicKeyAndDoPhase(byte[] clientPubKeyEnc, KeyAgreement serverKeyAgree) {
        try {
            /*
             * Instantiate a DH public key from the encoded key material.
             */
            KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);

            PublicKey clientPubKey = serverKeyFac.generatePublic(x509KeySpec);

            /*
             * Server gets the DH parameters associated with the Client's public key.
             * He must use the same parameters when he generates his own key
             * pair.
             */
            DHParameterSpec dhParamFromClientPubKey = ((DHPublicKey) clientPubKey).getParams();

            // Server creates his own DH key pair
            KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
            serverKpairGen.initialize(dhParamFromClientPubKey);
            KeyPair serverKpair = serverKpairGen.generateKeyPair();

            serverKeyAgree.init(serverKpair.getPrivate());

            /*
             * The Server uses the Client's public key for the first (and only) phase
             * of his version of the DH
             * protocol.
             */
            serverKeyAgree.doPhase(clientPubKey, true);

            // Server encodes his public key, to be sent over to the Client.
            return serverKpair.getPublic().getEncoded();
        } catch(NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException | InvalidKeyException e){
            // This exception depends only on the parameters used, so shouldn't happen
        }

        return null;
    }
}
