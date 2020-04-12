package pt.ulisboa.tecnico.SECDPAS;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class IntegrityHandlerTest {

    private static IntegrityHandler handler;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp() throws SignatureException{
        DiffieHellmanClient client = new DiffieHellmanClient();
        DiffieHellmanServer server = new DiffieHellmanServer();

        byte[] clientAgreement = client.prepareAgreement();

        byte[] serverAgreement = server.execute(clientAgreement);

        client.execute(serverAgreement);
        handler = new IntegrityHandler(client.getSharedHMACKey());
    }

    @Test
    public void success() {
        byte[] sign = handler.calculateHMAC(new byte[2]);

        assertTrue(handler.verifyHMAC(new byte[2], sign));

    }

    @Test
    public void fail() {
        byte[] message = new byte[2];
        byte[] sign = handler.calculateHMAC(message);

        message[0] = Byte.valueOf("1");

        assertFalse(handler.verifyHMAC(message, sign));

    }


}
