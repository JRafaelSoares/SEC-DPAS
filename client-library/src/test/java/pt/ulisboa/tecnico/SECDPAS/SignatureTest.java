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

public class SignatureTest {

    private static ClientLibrary lib;
    private static String s = "message";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp() {

        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            PublicKey pub = kp.getPublic();
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
    public void failSignaturePostCompromisePublicKey() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
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
    public void failSignaturePostCompromisePublicKeyEmpty() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        byte[] publicKey = new byte[0];
        String post = request.getMessage();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.postRequest(request);

    }

    @Test
    public void failSignaturePostGeneralCompromisePublicKey() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
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
    public void failSignaturePostGeneralCompromisePublicKeyEmpty() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        byte[] publicKey = new byte[0];
        String post = request.getMessage();
        byte[] announcements = request.getAnnouncements().toByteArray();

        request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(request.getFreshness().toByteArray())).setSignature(ByteString.copyFrom(request.getSignature().toByteArray())).build();

        thrown.expect(ClientNotRegisteredException.class);
        lib.postGeneralRequest(request);

    }

}
