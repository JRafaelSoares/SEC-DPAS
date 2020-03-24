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

public class IntegrityTest {

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

        }catch(Exception e){
            System.out.println("Unable to set up test");
        }
    }

    @AfterClass
    public static void cleanUp(){
        lib.cleanPosts();
        lib.cleanGeneralPosts();
        lib.shutDown();
    }

    @Test
    public void successPost() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        lib.postRequest(request);
    }

    @Test
    public void successPostGeneral() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        lib.postGeneralRequest(request);
    }

    @Test
    public void successRead() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException{
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        Announcement[] announcement = lib.readRequest(request);

        assertEquals(1, announcement.length);
        assertEquals(s, new String(announcement[0].getPost()));
    }

    @Test
    public void successReadGeneral() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException{
        lib.postGeneral(s.toCharArray());
        Contract.ReadRequest request = lib.getReadGeneralRequest(1);

        Announcement[] announcement = lib.readGeneralRequest(request);

        assertEquals(1, announcement.length);
        assertEquals(s, new String(announcement[0].getPost()));
    }

    @Test
    public void failRegisterIntegrityPublicKey() throws ClientAlreadyRegisteredException, MessageNotFreshException{
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

        thrown.expect(ClientAlreadyRegisteredException.class);
        lib.registerRequest(registerRequest);
    }

    @Test
    public void failIntegrityPostCompromisePublicKey() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

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
        String post = request.getMessage();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.postRequest(request);

    }

    @Test
    public void failIntegrityPostCompromisePublicKeyEmpty() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        byte[] publicKey = new byte[0];
        String post = request.getMessage();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.postRequest(request);

    }

    @Test
    public void failIntegrityPostCompromiseMessage() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);


        byte[] publicKey = request.getPublicKey().toByteArray();
        String post = "";
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.postRequest(request);

    }

    @Test
    public void failIntegrityPostCompromiseAnnouncements() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[1]);


        byte[] publicKey = request.getPublicKey().toByteArray();
        String post = request.getMessage();
        byte[] announcements = SerializationUtils.serialize(new Announcement[0]);

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);

        lib.postRequest(request);

    }

    @Test
    public void failIntegrityPostCompromiseMessageAnnouncements() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[1]);

        byte[] publicKey = request.getPublicKey().toByteArray();
        String post = "";
        byte[] announcements = SerializationUtils.serialize(new Announcement[0]);

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);

        lib.postRequest(request);

    }

    @Test
    public void failIntegrityPostGeneralCompromisePublicKey() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

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
        String post = request.getMessage();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.postGeneralRequest(request);

    }

    @Test
    public void failIntegrityPostGeneralCompromisePublicKeyEmpty() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        byte[] publicKey = new byte[0];
        String post = request.getMessage();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.postGeneralRequest(request);

    }

    @Test
    public void failIntegrityPostGeneralCompromiseMessage() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);


        byte[] publicKey = request.getPublicKey().toByteArray();
        String post = "";
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);

        lib.postGeneralRequest(request);

    }

    @Test
    public void failIntegrityPostGeneralCompromiseAnnouncements() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[1]);


        byte[] publicKey = request.getPublicKey().toByteArray();
        String post = request.getMessage();
        byte[] announcements = SerializationUtils.serialize(new Announcement[0]);

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);

        lib.postGeneralRequest(request);

    }

    @Test
    public void failIntegrityPostGeneralCompromiseMessageAnnouncements() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[1]);

        byte[] publicKey = request.getPublicKey().toByteArray();
        String post = "";
        byte[] announcements = SerializationUtils.serialize(new Announcement[0]);

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);

        lib.postGeneralRequest(request);

    }

    @Test
    public void failIntegrityReadCompromisePublicKey() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException{
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

        request = Contract.ReadRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.readRequest(request);

    }

    @Test
    public void failIntegrityReadCompromisePublicKeyEmpty() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException{
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        byte[] publicKey = new byte[0];
        int number = -1;

        request = Contract.ReadRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.readRequest(request);

    }

    @Test
    public void failIntegrityReadCompromiseNumber() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException{
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        byte[] publicKey = request.getPublicKey().toByteArray();
        int number = -1;

        request = Contract.ReadRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.readRequest(request);

    }

    @Test
    public void failIntegrityReadGeneralCompromiseNumber() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException{
        lib.postGeneral(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub,1);

        byte[] publicKey = request.getPublicKey().toByteArray();
        int number = -1;

        request = Contract.ReadRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.readGeneralRequest(request);

    }

}
