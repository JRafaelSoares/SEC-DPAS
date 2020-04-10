package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class FreshnessClientRequestTest {

    private static ClientLibrary lib;
    private static Contract.RegisterRequest registerRequest;
    private static String s = "message";
    private static PublicKey pub;
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp() {

        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            lib = new ClientLibrary("localhost", 8080, pub, priv);

            registerRequest = lib.getRegisterRequest();
            lib.registerRequest(registerRequest);

            lib.setupConnection();

        } catch (Exception e){
            System.out.println("// Exception message: " + e.getMessage());
            System.out.println("Unable to obtain public key for testing");
        }
    }

    @AfterClass
    public static void cleanUp(){
        lib.cleanPosts();
        lib.cleanGeneralPosts();
        lib.shutDown();
    }

    @Test
    public void successPost() throws ComunicationException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        lib.postRequest(request);
    }

    @Test
    public void successPostGeneral() throws ComunicationException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        lib.postGeneralRequest(request);
    }

    @Test
    public void successRead() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        Announcement[] announcement = lib.readRequest(request);

        assertEquals(1, announcement.length);
        assertEquals(s, new String(announcement[0].getPost()));
    }

    @Test
    public void successReadGeneral() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.postGeneral(s.toCharArray());
        Contract.ReadRequest request = lib.getReadGeneralRequest(1);

        Announcement[] announcement = lib.readGeneralRequest(request);

        assertEquals(1, announcement.length);
        assertEquals(s, new String(announcement[0].getPost()));
    }

    @Test
    public void successCloseConnection() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        ClientLibrary lib = null;
        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            PublicKey pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            lib = new ClientLibrary("localhost", 8080, pub, priv);

            lib.register();
            lib.setupConnection();

        } catch (Exception e){
            System.out.println("// Exception message: " + e.getMessage());
            System.out.println("Unable to obtain public key for testing");
        }

        lib.closeConnection();
        lib.shutDown();
    }

    @Test
    public void failRegisterFreshness() throws ClientAlreadyRegisteredException, ComunicationException {
        thrown.expect(ClientAlreadyRegisteredException.class);
        lib.registerRequest(registerRequest);
    }

    @Test
    public void failPostFreshness() throws ComunicationException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        lib.postRequest(request);

        try{
            lib.postRequest(request);
            fail("Communication exception - Server exception not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server exception not fresh", e.getMessage());
        }

    }

    @Test
    public void failPostGeneralFreshness() throws ComunicationException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        lib.postGeneralRequest(request);
        try{
            lib.postGeneralRequest(request);
            fail("Communication exception - Server exception not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server exception not fresh", e.getMessage());
        }

    }

    @Test
    public void failCrossPostFreshness() throws ComunicationException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        lib.postRequest(request);

        try{
            lib.postGeneralRequest(request);
            fail("Communication exception - Server exception not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server exception not fresh", e.getMessage());
        }

    }

    @Test
    public void failReadFreshness() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        Announcement[] announcement = lib.readRequest(request);

        assertEquals(1, announcement.length);
        assertEquals(s, new String(announcement[0].getPost()));

        try{
            lib.readRequest(request);
            fail("Communication exception - Server exception not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server exception not fresh", e.getMessage());
        }

    }

    @Test
    public void failReadGeneralFreshness() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.postGeneral(s.toCharArray());
        Contract.ReadRequest request = lib.getReadGeneralRequest(1);

        Announcement[] announcement = lib.readGeneralRequest(request);

        assertEquals(1, announcement.length);
        assertEquals(s, new String(announcement[0].getPost()));

        try{
            lib.readGeneralRequest(request);
            fail("Communication exception - Server exception not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server exception not fresh", e.getMessage());
        }

    }

    @Test
    public void failCrossReadFreshness() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        Announcement[] announcement = lib.readRequest(request);

        assertEquals(1, announcement.length);
        assertEquals(s, new String(announcement[0].getPost()));

        try{
            lib.readGeneralRequest(request);
            fail("Communication exception - Server exception not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server exception not fresh", e.getMessage());
        }

    }

    @Test
    public void failCloseConnectionFreshness() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        ClientLibrary lib = null;
        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            PublicKey pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            lib = new ClientLibrary("localhost", 8080, pub, priv);

            lib.register();
            lib.setupConnection();

        } catch (Exception e){
            System.out.println("// Exception message: " + e.getMessage());
            System.out.println("Unable to obtain public key for testing");
        }
        Contract.CloseSessionRequest request = lib.getCloseSessionRequest();
        lib.closeConnectionRequest(request);

        try{
            lib.setupConnection();
            lib.closeConnectionRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }
        lib.shutDown();

    }

}
