package pt.ulisboa.tecnico.SECDPAS;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SignatureHandlerTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void success() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        byte[] sign = SignatureHandler.publicSign(new byte[2], priv);

        assertTrue(SignatureHandler.verifyPublicSignature(new byte[2], sign, pub));

    }

    @Test
    public void failDifferentPublic() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PrivateKey priv = kp.getPrivate();

        byte[] sign = SignatureHandler.publicSign(new byte[2], priv);

        kp = kpg.genKeyPair();
        PublicKey pub = kp.getPublic();

        assertFalse(SignatureHandler.verifyPublicSignature(new byte[2], sign, pub));

    }

}
