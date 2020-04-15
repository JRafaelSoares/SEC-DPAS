package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runners.MethodSorters;

import java.security.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ExceptionVerificationTest {


    private static FreshnessHandler freshnessHandler;
    private static PublicKey pubClient;
    private static PrivateKey privServer;
    private static PrivateKey privClient;
    private static ClientLibrary lib;
    private static DPASServiceGrpc.DPASServiceFutureStub stub;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp(){

        try{
            freshnessHandler = new FreshnessHandler();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            pubClient = kp.getPublic();
            privClient = kp.getPrivate();

            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            kp = kpg.genKeyPair();
            PublicKey pubServer = kp.getPublic();
            privServer = kp.getPrivate();

            stub = mock(DPASServiceGrpc.DPASServiceFutureStub.class);

            lib = new ClientLibrary(stub, pubClient, privClient, pubServer);

        }catch (Exception e){
            System.out.println(e.getMessage());
            System.out.println("Unable to obtain public key for testing");
        }
    }

    @Test
    public void successInvalidArgumentPublicKey() throws ClientAlreadyRegisteredException{

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = new byte[0];
        StatusRuntimeException exception = buildException(Status.Code.INVALID_ARGUMENT, "PublicKey", serializedPubKey, freshness);

        when(stub.register(isA(Contract.RegisterRequest.class))).thenThrow(exception);

        try{
            lib.register();
            fail("Communication exception - The public key could not be deserialised on the server - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The public key could not be deserialised on the server", e.getMessage() );
        }

    }

    @Test
    public void successInvalidArgumentClientAlreadyRegistered() throws ClientAlreadyRegisteredException, ComunicationException{

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = new byte[0];

        StatusRuntimeException exception = buildException(Status.Code.INVALID_ARGUMENT, "ClientAlreadyRegistered", serializedPubKey, freshness);

        when(stub.register(isA(Contract.RegisterRequest.class))).thenThrow(exception);

        thrown.expect(ClientAlreadyRegisteredException.class);
        lib.register();

    }

    @Test
    public void successInvalidArgumentNonExistentAnnouncementReference() throws ClientNotRegisteredException, InvalidArgumentException{

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());

        StatusRuntimeException exception = buildException(Status.Code.INVALID_ARGUMENT, "NonExistentAnnouncementReference", serializedPubKey, freshness);

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("Communication exception - There is a non-existent announcement referenced in this post - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("There is a non-existent announcement referenced in this post", e.getMessage() );
        }

    }

    @Test
    public void successPermissionDeniedClientRequestNotFresh() throws InvalidArgumentException, ClientNotRegisteredException{

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "ClientRequestNotFresh", serializedPubKey, freshness);

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("Communication exception - The request received from the client wasn't fresh - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The request received from the client wasn't fresh", e.getMessage() );
        }
    }

    @Test
    public void successPermissionDeniedClientSignatureInvalid() throws ClientAlreadyRegisteredException{

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = new byte[0];

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "ClientSignatureInvalid", serializedPubKey, freshness);

        when(stub.register(isA(Contract.RegisterRequest.class))).thenThrow(exception);

        try{
            lib.register();
            fail("Communication exception - The signature of the request wasn't valid - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The signature of the request wasn't valid", e.getMessage() );
        }

    }

    @Test
    public void successPermissionDeniedClientNotRegistered() throws ComunicationException, InvalidArgumentException{

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "ClientNotRegistered", serializedPubKey, freshness);

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("ClientNotRegisteredException - should have been thrown.");

        }catch(ClientNotRegisteredException e){
        }

    }

    @Test
    public void successPermissionDeniedClientIntegrityViolation() throws InvalidArgumentException, ClientNotRegisteredException{


        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "ClientIntegrityViolation", serializedPubKey, freshness);

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The integrity of the request was violated", e.getMessage() );
        }

    }

    @Test
    public void successPermissionDeniedAnnouncementSignatureInvalid() throws InvalidArgumentException, ClientNotRegisteredException{

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "AnnouncementSignatureInvalid", serializedPubKey, freshness);

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("Communication exception - An announcement was not properly signed - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("An announcement was not properly signed", e.getMessage() );
        }

    }

    @Test
    public void successPermissionDeniedTargetClientNotRegistered() throws InvalidArgumentException, ClientNotRegisteredException{

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "TargetClientNotRegistered", serializedPubKey, freshness);

        when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenThrow(exception);

        try{
            lib.readGeneral(0);
            fail("Communication exception - The read target client wasn't registered yet - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The read target client wasn't registered yet", e.getMessage() );
        }

    }

    @Test
    public void failSignature() throws NoSuchAlgorithmException, InvalidArgumentException, ClientNotRegisteredException, ComunicationException{

        // preparing exception

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        Status.Code code = Status.Code.INVALID_ARGUMENT;
        String description = "PublicKey";
        byte[] serializedClientKey = SerializationUtils.serialize(pub);
        byte[] clientFreshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        Status status = Status.fromCode(code).withDescription(description);

        Metadata metadata = buildMetadata(serializedClientKey, clientFreshness);

        Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);
        metadata.put(signatureKey, SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(code.value()), description.getBytes(), serializedClientKey, clientFreshness, clientFreshness), priv));

        StatusRuntimeException exception = status.asRuntimeException(metadata);

        // end preparation

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("message".toCharArray());
            fail("Communication exception - Server exception signature invalid - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("Server exception signature invalid", e.getMessage() );
        }

    }

    @Test
    public void failType() throws NoSuchAlgorithmException, InvalidArgumentException, ClientNotRegisteredException{

        // preparing exception

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        Status.Code code = Status.Code.INVALID_ARGUMENT;
        String description = "PublicKey";
        byte[] serializedClientKey = SerializationUtils.serialize(pub);
        byte[] clientFreshness = Longs.toByteArray(freshnessHandler.getNextFreshness());


        Status status = Status.fromCode(Status.Code.PERMISSION_DENIED).withDescription("ClientRequestNotFresh");

        Metadata metadata = buildMetadata(serializedClientKey, clientFreshness);

        Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);
        metadata.put(signatureKey, SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(code.value()), description.getBytes(), serializedClientKey, clientFreshness, clientFreshness), priv));

        StatusRuntimeException exception = status.asRuntimeException(metadata);

        // end preparation

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("message".toCharArray());
            fail("Communication exception - Server exception signature invalid - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("Server exception signature invalid", e.getMessage() );
        }

    }

    @Test
    public void zfailFreshness() throws InvalidArgumentException, ClientNotRegisteredException{

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);
        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "ClientIntegrityViolation", serializedPubKey, freshness);

        // end preparation

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);


        try{
            lib.post("hi".toCharArray());
        }catch (ComunicationException e){

            try{
                lib.post("hi".toCharArray());
                fail("Communication exception - Server exception not fresh - should have been thrown.");

            }catch (ComunicationException e2){
                Assert.assertEquals("Server exception not fresh", e2.getMessage() );
            }
        }

    }

    private StatusRuntimeException buildException(Status.Code code, String description, byte[] serializedClientKey, byte[] clientFreshness){
        Status status = Status.fromCode(code).withDescription(description);

        Metadata metadata = buildMetadata(serializedClientKey, clientFreshness);


        Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);
        metadata.put(signatureKey, SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(code.value()), description.getBytes(), serializedClientKey, clientFreshness), privServer));

        return status.asRuntimeException(metadata);
    }

    private Metadata buildMetadata(byte[] serializedClientKey, byte[] clientFreshness){
        Metadata metadata = new Metadata();

        Metadata.Key<byte[]> clientKey = Metadata.Key.of("clientKey-bin", Metadata.BINARY_BYTE_MARSHALLER);
        Metadata.Key<byte[]> clientFreshnessKey = Metadata.Key.of("clientFreshness-bin", Metadata.BINARY_BYTE_MARSHALLER);

        metadata.put(clientKey, serializedClientKey);
        metadata.put(clientFreshnessKey, clientFreshness);

        return metadata;
    }

}
