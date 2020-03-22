package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.*;

import java.security.SignatureException;
import java.util.Arrays;

public class DiffieHellmanTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp() {
    }

    @Test
    public void success() throws SignatureException {
        DiffieHellmanClient client = new DiffieHellmanClient();
        DiffieHellmanServer server = new DiffieHellmanServer();

        byte[] clientAgreement = client.prepareAgreement();

        byte[] serverAgreement = server.execute(clientAgreement);

        client.execute(serverAgreement);

        assertEquals(server.getSharedHMACKey(), client.getSharedHMACKey());
    }

    @Test
    public void failClientDiff() throws SignatureException {
        DiffieHellmanClient client = new DiffieHellmanClient();
        DiffieHellmanServer server = new DiffieHellmanServer();

        byte[] clientAgreement = client.prepareAgreement();
        clientAgreement[clientAgreement.length-1] = Byte.valueOf("1");

        byte[] serverAgreement = server.execute(clientAgreement);

        client.execute(serverAgreement);

        assertNotEquals(server.getSharedHMACKey(), client.getSharedHMACKey());
    }

    @Test
    public void failServer() throws SignatureException {
        DiffieHellmanClient client = new DiffieHellmanClient();
        DiffieHellmanServer server = new DiffieHellmanServer();

        byte[] clientAgreement = client.prepareAgreement();

        byte[] serverAgreement = server.execute(clientAgreement);
        serverAgreement[serverAgreement.length-1] = Byte.valueOf("1");

        client.execute(serverAgreement);

        assertNotEquals(server.getSharedHMACKey(), client.getSharedHMACKey());
    }

}
