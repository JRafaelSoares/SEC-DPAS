package pt.ulisboa.tecnico.SECDPAS;

import org.junit.*;
import org.junit.rules.ExpectedException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.fail;

public class CloseSessionTest {

    private static ClientLibrary lib;
    private static PublicKey pub;
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp(){

        try{

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            lib = new ClientLibrary("localhost", 8080, pub, priv);

            lib.register();

        }catch (Exception e){
            System.out.println("Unable to obtain public key for testing");
        }
    }

    @AfterClass
    public static void cleanUp(){
        lib.cleanPosts();
        lib.shutDown();
    }

    @Test
    public void success() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
        lib.setupConnection();
        lib.closeConnection();
        lib.setupConnection();
        lib.closeConnection();
    }

    @Test
    public void failAlreadyClosed() throws ClientNotRegisteredException, ComunicationException{
        try{
            lib.closeConnection();
            fail("Invalid argument exception - Session already closed - should have been thrown.");
        }catch (InvalidArgumentException e){
            Assert.assertEquals("Session already closed", e.getMessage());
        }
    }

    @Test
    public void failClientNotRegistered() throws ComunicationException, ClientNotRegisteredException{
        ClientLibrary lib = null;

        try{

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            PublicKey pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            lib = new ClientLibrary("localhost", 8080, pub, priv);

            lib.register();

        }catch (Exception e){
            System.out.println("Unable to obtain public key for testing");
        }

        try{
            lib.closeConnection();
            fail("Invalid argument exception - Session already closed - should have been thrown.");
        }catch (InvalidArgumentException e){
            Assert.assertEquals("Session already closed", e.getMessage());
        }
        lib.shutDown();

    }

}
