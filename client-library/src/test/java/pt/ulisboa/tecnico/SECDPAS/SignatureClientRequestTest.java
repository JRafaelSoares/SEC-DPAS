package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.common.primitives.Bytes;
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

public class SignatureClientRequestTest {

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
    public void successPost() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        lib.postRequest(request);
    }

    @Test
    public void successPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new String[0]);

        lib.postGeneralRequest(request);
    }

    @Test
    public void successRead() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
        lib.post(s.toCharArray());
        Contract.ReadRequest request = lib.getReadRequest(pub, 1);

        Announcement[] announcement = lib.readRequest(request);

        assertEquals(1, announcement.length);
        assertEquals(s, new String(announcement[0].getPost()));
    }

    @Test
    public void successReadGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
        lib.postGeneral(s.toCharArray());
        Contract.ReadRequest request = lib.getReadGeneralRequest( 1);

        Announcement[] announcement = lib.readGeneralRequest(request);

        assertEquals(1, announcement.length);
        assertEquals(s, new String(announcement[0].getPost()));
    }

    @Test
    public void failRegisterSignature() throws NoSuchAlgorithmException, ClientAlreadyRegisteredException, InvalidArgumentException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub2 = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        FreshnessHandler handler = new FreshnessHandler(System.currentTimeMillis());
        byte[] publicKey = SerializationUtils.serialize(pub);
        byte[] freshness = handler.getFreshness();
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, freshness), priv);

        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(SerializationUtils.serialize(pub2))).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            lib.registerRequest(request);
            fail("Communication exception - The signature of the request wasn't valid - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The signature of the request wasn't valid", e.getMessage());
        }
    }

    @Test
    public void failPostSignature() throws NoSuchAlgorithmException, ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        Contract.PostRequest request = lib.getPostRequest("message".toCharArray(), new String[0]);

        byte[] publicKey = SerializationUtils.serialize(pub);
        byte[] freshness = request.getFreshness().toByteArray();
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, freshness), priv);

        request = Contract.PostRequest.newBuilder().setPublicKey(request.getPublicKey()).setMessage(request.getMessage()).setAnnouncements(request.getAnnouncements()).setFreshness(request.getFreshness()).setSignature(ByteString.copyFrom(signature)).build();

        try{
            lib.postRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }
    }

    @Test
    public void failPostGeneralSignature() throws NoSuchAlgorithmException, ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        Contract.PostRequest request = lib.getPostRequest("message".toCharArray(), new String[0]);

        byte[] publicKey = SerializationUtils.serialize(pub);
        byte[] freshness = request.getFreshness().toByteArray();
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, freshness), priv);

        request = Contract.PostRequest.newBuilder().setPublicKey(request.getPublicKey()).setMessage(request.getMessage()).setAnnouncements(request.getAnnouncements()).setFreshness(request.getFreshness()).setSignature(ByteString.copyFrom(signature)).build();

        try{
            lib.postGeneralRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }
    }

    @Test
    public void failReadSignature() throws NoSuchAlgorithmException, ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub1 = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        Contract.ReadRequest request = lib.getReadRequest(pub, 1);

        byte[] publicKey = SerializationUtils.serialize(pub1);
        byte[] freshness = request.getFreshness().toByteArray();
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, freshness), priv);

        request = Contract.ReadRequest.newBuilder().setTargetPublicKey(request.getTargetPublicKey()).setClientPublicKey(request.getClientPublicKey()).setNumber(request.getNumber()).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            lib.readRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }
    }

    @Test
    public void failReadGeneralSignature() throws NoSuchAlgorithmException, ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub1 = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        Contract.ReadRequest request = lib.getReadRequest(pub, 1);

        byte[] publicKey = SerializationUtils.serialize(pub1);
        byte[] freshness = request.getFreshness().toByteArray();
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, freshness), priv);

        request = Contract.ReadRequest.newBuilder().setClientPublicKey(request.getClientPublicKey()).setNumber(request.getNumber()).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            lib.readGeneralRequest(request);
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the request was violated", e.getMessage());
        }
    }

}
