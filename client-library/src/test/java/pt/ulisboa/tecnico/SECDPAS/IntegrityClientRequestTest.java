package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.protobuf.ByteString;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class IntegrityClientRequestTest {

    private static ClientLibrary lib;
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

            lib.register();

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
    public void successPost() throws ClientNotRegisteredException, ComunicationException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        lib.postRequest(request);
    }

    @Test
    public void successPostGeneral() throws ClientNotRegisteredException, ComunicationException {
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
    public void failRegisterIntegrityCompromiseFreshness() throws ClientAlreadyRegisteredException, CertificateInvalidException {
        PublicKey pub;
        Contract.RegisterRequest registerRequest;
        ClientLibrary lib;
        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            lib = new ClientLibrary("localhost", 8080, pub, priv);
            registerRequest = lib.getRegisterRequest();

        }catch(NoSuchAlgorithmException | InvalidArgumentException e){
            System.out.println("Unable to create public key for testing");
            return;
        }

        byte[] publicKey = SerializationUtils.serialize(pub);

        MessageHandler handler = new MessageHandler(null);
        byte[] freshness = handler.getFreshness();

        registerRequest = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(registerRequest.getSignature().toByteArray())).build();

        try{
            lib.registerRequest( registerRequest);
            fail("Communication exception - The signature of the request wasn't valid - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The signature of the request wasn't valid", e.getMessage());
        }
        lib.shutDown();

    }

    @Test
    public void failRegisterIntegrityCompromisePublicKey() throws ClientAlreadyRegisteredException, CertificateInvalidException {
        PublicKey pub;
        Contract.RegisterRequest registerRequest;
        ClientLibrary lib;
        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            lib = new ClientLibrary("localhost", 8080, pub, priv);
            registerRequest = lib.getRegisterRequest();

            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            kp = kpg.genKeyPair();
            pub = kp.getPublic();

        }catch(NoSuchAlgorithmException | InvalidArgumentException e){
            System.out.println("Unable to create public key for testing");
            return;
        }

        byte[] publicKey = SerializationUtils.serialize(pub);

        registerRequest = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setFreshness(ByteString.copyFrom(registerRequest.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(registerRequest.getSignature().toByteArray())).build();

        try{
            lib.registerRequest( registerRequest);
            fail("Communication exception - The signature of the request wasn't valid - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The signature of the request wasn't valid", e.getMessage());
        }
        lib.shutDown();
    }

    @Test
    public void failIntegrityPostCompromiseFreshness() throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        MessageHandler handler = new MessageHandler(null);
        byte[] freshness = handler.getFreshness();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(request.getPublicKey().toByteArray())).setMessage(request.getMessage()).setMessageSignature(ByteString.copyFrom(request.getMessageSignature().toByteArray())).setAnnouncements(ByteString.copyFrom(request.getAnnouncements().toByteArray())).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityPostCompromisePublicKey() throws ClientNotRegisteredException, ComunicationException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        PublicKey pub = null;

        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            pub = kp.getPublic();
        } catch(NoSuchAlgorithmException e){
            System.out.println("Unable to create public key for testing");
        }

        byte[] publicKey = SerializationUtils.serialize(pub);
        byte[] post = request.getMessage().toByteArray();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.postRequest(request);

    }

    @Test
    public void failIntegrityPostCompromisePublicKeyEmpty() throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        byte[] publicKey = new byte[0];
        byte[] post = request.getMessage().toByteArray();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postRequest(request);
            fail("Communication exception - The public key could not be deserialised on the server - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The public key could not be deserialised on the server", e.getMessage());
        }

    }

    @Test
    public void failIntegrityPostCompromiseMessage() throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);


        byte[] publicKey = request.getPublicKey().toByteArray();
        byte[] post = "".getBytes();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }
    }

    @Test
    public void failIntegrityPostCompromiseAnnouncements() throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[1]);


        byte[] publicKey = request.getPublicKey().toByteArray();
        byte[] post = request.getMessage().toByteArray();
        byte[] announcements = SerializationUtils.serialize(new String[0]);

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityPostCompromiseMessageAnnouncements() throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[1]);

        byte[] publicKey = request.getPublicKey().toByteArray();
        byte[] post = "".getBytes();
        byte[] announcements = SerializationUtils.serialize(new String[0]);

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityPostGeneralCompromiseFreshness() throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        MessageHandler handler = new MessageHandler(null);
        byte[] freshness = handler.getFreshness();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(request.getPublicKey().toByteArray())).setMessage(request.getMessage()).setMessageSignature(ByteString.copyFrom(request.getMessageSignature().toByteArray())).setAnnouncements(ByteString.copyFrom(request.getAnnouncements().toByteArray())).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postGeneralRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityPostGeneralCompromisePublicKey() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        PublicKey pub = null;

        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            pub = kp.getPublic();
        }catch(NoSuchAlgorithmException e){
            System.out.println("Unable to create public key for testing");
        }

        byte[] publicKey = SerializationUtils.serialize(pub);
        byte[] post = request.getMessage().toByteArray();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.postGeneralRequest(request);
    }

    @Test
    public void failIntegrityPostGeneralCompromisePublicKeyEmpty() throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        byte[] publicKey = new byte[0];
        byte[] post = request.getMessage().toByteArray();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postGeneralRequest(request);
            fail("Communication exception - The public key could not be deserialised on the server - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The public key could not be deserialised on the server", e.getMessage());
        }
    }

    @Test
    public void failIntegrityPostGeneralCompromiseMessage() throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);


        byte[] publicKey = request.getPublicKey().toByteArray();
        byte[] post = "".getBytes();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postGeneralRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityPostGeneralCompromiseAnnouncements() throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[1]);


        byte[] publicKey = request.getPublicKey().toByteArray();
        byte[] post = request.getMessage().toByteArray();
        byte[] announcements = SerializationUtils.serialize(new String[0]);

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postGeneralRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }
    }

    @Test
    public void failIntegrityPostGeneralCompromiseMessageAnnouncements()throws ClientNotRegisteredException {
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[1]);

        byte[] publicKey = request.getPublicKey().toByteArray();
        byte[] post = "".getBytes();
        byte[] announcements = SerializationUtils.serialize(new String[0]);

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.postGeneralRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadCompromiseFreshness() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        MessageHandler handler = new MessageHandler(null);
        byte[] freshness = handler.getFreshness();

        request = Contract.ReadRequest.newBuilder().setTargetPublicKey(request.getTargetPublicKey()).setClientPublicKey(request.getClientPublicKey()).setNumber(request.getNumber()).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.readRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadCompromisePublicKey() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        PublicKey pub = null;

        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            pub = kp.getPublic();
        }catch(NoSuchAlgorithmException e){
            System.out.println("Unable to create public key for testing");
        }

        byte[] publicKey = SerializationUtils.serialize(pub);
        int number = -1;

        request = Contract.ReadRequest.newBuilder().setTargetPublicKey(ByteString.copyFrom(publicKey)).setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.readRequest(request);

    }

    @Test
    public void failIntegrityReadCompromisePublicKeyEmpty() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        byte[] publicKey = new byte[0];
        int number = -1;

        request = Contract.ReadRequest.newBuilder().setTargetPublicKey(ByteString.copyFrom(publicKey)).setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.readRequest(request);
            fail("Communication exception - The public key could not be deserialised on the server - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The public key could not be deserialised on the server", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadCompromiseNumber() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        byte[] publicKey = request.getClientPublicKey().toByteArray();
        int number = -1;

        request = Contract.ReadRequest.newBuilder().setTargetPublicKey(ByteString.copyFrom(publicKey)).setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.readRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadGeneralCompromiseFreshness() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.postGeneral(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        MessageHandler handler = new MessageHandler(null);
        byte[] freshness = handler.getFreshness();

        request = Contract.ReadRequest.newBuilder().setTargetPublicKey(request.getTargetPublicKey()).setClientPublicKey(request.getClientPublicKey()).setNumber(request.getNumber()).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.readGeneralRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadGeneralCompromiseNumber() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException {
        lib.postGeneral(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        byte[] publicKey = request.getClientPublicKey().toByteArray();
        int number = -1;

        request = Contract.ReadRequest.newBuilder().setTargetPublicKey(ByteString.copyFrom(publicKey)).setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        try{
            lib.readGeneralRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }

    }

    @Test
    public void failCloseConnectionCompromisePublicKey() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {
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
            fail("Unable to obtain public key for testing");
        }

        PublicKey pub = null;

        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            pub = kp.getPublic();
        }catch(NoSuchAlgorithmException e){
            System.out.println("Unable to create public key for testing");
        }

        byte[] publicKey = SerializationUtils.serialize(pub);

        Contract.CloseSessionRequest request = lib.getCloseSessionRequest();

        request = Contract.CloseSessionRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setFreshness(request.getFreshness()).setSignature(request.getSignature()).build();


        thrown.expect(ClientNotRegisteredException.class);
        lib.closeConnectionRequest(request);
        lib.shutDown();
    }

    @Test
    public void failCloseConnectionCompromisePublicKeyEmpty() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {
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
            fail("Unable to obtain public key for testing");
        }

        byte[] publicKey = new byte[0];

        Contract.CloseSessionRequest request = lib.getCloseSessionRequest();

        request = Contract.CloseSessionRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setFreshness(request.getFreshness()).setSignature(request.getSignature()).build();


        try{
            lib.closeConnectionRequest(request);
            fail("Communication exception - The public key could not be deserialised on the server - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The public key could not be deserialised on the server", e.getMessage());
        }
        lib.shutDown();

    }

    @Test
    public void failCloseConnectionCompromiseFreshness() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {
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
            fail("Unable to obtain public key for testing");
        }

        MessageHandler handler = new MessageHandler(null);
        byte[] freshness = handler.getFreshness();

        Contract.CloseSessionRequest request = lib.getCloseSessionRequest();

        request = Contract.CloseSessionRequest.newBuilder().setPublicKey(request.getPublicKey()).setFreshness(ByteString.copyFrom(freshness)).setSignature(request.getSignature()).build();


        try{
            lib.closeConnectionRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }
        lib.shutDown();

    }

}
