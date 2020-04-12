package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.security.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ExceptionVerificationTest {


    private static MessageHandler messageHandler;
    private static PublicKey pubClient;
    private static PrivateKey privServer;
    private static PrivateKey privClient;
    private static ClientLibrary lib;
    private static DPASServiceGrpc.DPASServiceFutureStub stub;
    private static byte[] messageSignaturePost;
    private static byte[] messageSignaturePostGeneral;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp(){

        try{
            messageHandler = new MessageHandler(null);

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
/*
    @Test
    public void successInvalidArgumentPublicKey() throws ClientAlreadyRegisteredException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);

        StatusRuntimeException exception = buildException(Status.Code.INVALID_ARGUMENT, "PublicKey", serializedPubKey, messageHandler.getFreshness(), messageHandler.getFreshness());

        when(stub.register(isA(Contract.RegisterRequest.class))).thenThrow(exception);

        try{
            lib.register();
            fail("Communication exception - The public key could not be deserialised on the server - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The public key could not be deserialised on the server", e.getMessage() );
        }

    }

    @Test
    public void successInvalidArgumentClientAlreadyRegistered() throws ClientAlreadyRegisteredException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);

        StatusRuntimeException exception = buildException(Status.Code.INVALID_ARGUMENT, "ClientAlreadyRegistered", serializedPubKey, messageHandler.getFreshness(), messageHandler.getFreshness());

        when(stub.register(isA(Contract.RegisterRequest.class))).thenThrow(exception);

        thrown.expect(ClientAlreadyRegisteredException.class);
        lib.register();

    }

    @Test
    public void successInvalidArgumentNonExistentAnnouncementReference() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);

        StatusRuntimeException exception = buildException(Status.Code.INVALID_ARGUMENT, "NonExistentAnnouncementReference", serializedPubKey, messageHandler.getFreshness(), messageHandler.getFreshness());

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("Communication exception - There is a non-existent announcement referenced in this post - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("There is a non-existent announcement referenced in this post", e.getMessage() );
        }

    }

    @Test
    public void successPermissionDeniedClientRequestNotFresh() throws InvalidArgumentException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "ClientRequestNotFresh", serializedPubKey, messageHandler.getFreshness(), messageHandler.getFreshness());

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("Communication exception - The request received from the client wasn't fresh - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The request received from the client wasn't fresh", e.getMessage() );
        }
    }

    @Test
    public void successPermissionDeniedClientSignatureInvalid() throws ClientAlreadyRegisteredException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "ClientSignatureInvalid", serializedPubKey, messageHandler.getFreshness(), messageHandler.getFreshness());

        when(stub.register(isA(Contract.RegisterRequest.class))).thenThrow(exception);

        try{
            lib.register();
            fail("Communication exception - The signature of the request wasn't valid - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The signature of the request wasn't valid", e.getMessage() );
        }

    }

    @Test
    public void successPermissionDeniedClientNotRegistered() throws ClientNotRegisteredException, ComunicationException, InvalidArgumentException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "ClientNotRegistered", serializedPubKey, messageHandler.getFreshness(), messageHandler.getFreshness());

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("Communication exception - Received invalid exception, please try again. - should have been thrown.");

        }catch(ComunicationException e){
            assertEquals("Received invalid exception, please try again.", e.getMessage());
        }

    }

    @Test
    public void successPermissionDeniedClientIntegrityViolation() throws InvalidArgumentException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "ClientIntegrityViolation", serializedPubKey, messageHandler.getFreshness(), messageHandler.getFreshness());

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("Communication exception - The integrity of the request was violated - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The integrity of the request was violated", e.getMessage() );
        }

    }

    @Test
    public void successPermissionDeniedAnnouncementSignatureInvalid() throws InvalidArgumentException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "AnnouncementSignatureInvalid", serializedPubKey, messageHandler.getFreshness(), messageHandler.getFreshness());

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            fail("Communication exception - An announcement was not properly signed - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("An announcement was not properly signed", e.getMessage() );
        }

    }

    @Test
    public void successPermissionDeniedTargetClientNotRegistered() throws InvalidArgumentException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] serializedPubKey = SerializationUtils.serialize(pubClient);

        StatusRuntimeException exception = buildException(Status.Code.PERMISSION_DENIED, "TargetClientNotRegistered", serializedPubKey, messageHandler.getFreshness(), messageHandler.getFreshness());

        when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenThrow(exception);

        try{
            lib.readGeneral(0);
            fail("Communication exception - The read target client wasn't registered yet - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("The read target client wasn't registered yet", e.getMessage() );
        }

    }

    @Test
    public void failSignature() throws NoSuchAlgorithmException, ClientAlreadyRegisteredException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        // preparing exception

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        Status.Code code = Status.Code.INVALID_ARGUMENT;
        String description = "PublicKey";
        byte[] serializedClientKey = SerializationUtils.serialize(pub);
        byte[] clientFreshness = messageHandler.getFreshness();
        byte[] serverFreshness = messageHandler.getFreshness();

        Status status = Status.fromCode(code).withDescription(description);

        Metadata metadata = buildMetadata(serializedClientKey, clientFreshness, serverFreshness);

        Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);
        metadata.put(signatureKey, SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(code.value()), description.getBytes(), serializedClientKey, clientFreshness, serverFreshness), priv));

        StatusRuntimeException exception = status.asRuntimeException(metadata);

        // end preparation

        when(stub.register(isA(Contract.RegisterRequest.class))).thenThrow(exception);

        try{
            lib.register();
            fail("Communication exception - Server exception signature invalid - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("Server exception signature invalid", e.getMessage() );
        }

    }

    @Test
    public void failType() throws NoSuchAlgorithmException, ClientAlreadyRegisteredException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        // preparing exception

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();

        Status.Code code = Status.Code.INVALID_ARGUMENT;
        String description = "PublicKey";
        byte[] serializedClientKey = SerializationUtils.serialize(pub);
        byte[] clientFreshness = messageHandler.getFreshness();
        byte[] serverFreshness = messageHandler.getFreshness();


        Status status = Status.fromCode(Status.Code.PERMISSION_DENIED).withDescription("ClientRequestNotFresh");

        Metadata metadata = buildMetadata(serializedClientKey, clientFreshness, serverFreshness);

        Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);
        metadata.put(signatureKey, SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(code.value()), description.getBytes(), serializedClientKey, clientFreshness, serverFreshness), priv));

        StatusRuntimeException exception = status.asRuntimeException(metadata);

        // end preparation

        when(stub.register(isA(Contract.RegisterRequest.class))).thenThrow(exception);

        try{
            lib.register();
            fail("Communication exception - Server exception signature invalid - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("Server exception signature invalid", e.getMessage() );
        }

    }

    @Test
    public void failFreshness() throws InvalidArgumentException, ClientNotRegisteredException, ComunicationException{
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        // preparing exception

        Status.Code code = Status.Code.INVALID_ARGUMENT;
        String description = "PublicKey";
        byte[] serializedClientKey = SerializationUtils.serialize(pubClient);
        byte[] clientFreshness = messageHandler.getFreshness();
        byte[] serverFreshness = new byte[0];


        Status status = Status.fromCode(code).withDescription(description);

        Metadata metadata = buildMetadata(serializedClientKey, clientFreshness, serverFreshness);

        Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);
        metadata.put(signatureKey, SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(code.value()), description.getBytes(), serializedClientKey, clientFreshness, serverFreshness), privServer));

        StatusRuntimeException exception = status.asRuntimeException(metadata);
        
        // end preparation

        when(stub.post(isA(Contract.PostRequest.class))).thenThrow(exception);

        try{
            lib.post("hi".toCharArray());
            lib.post("hi".toCharArray());
            fail("Communication exception - Server exception not fresh - should have been thrown.");
        }catch (ComunicationException e){
            Assert.assertEquals("Server exception not fresh", e.getMessage() );
        }

    }

    private StatusRuntimeException buildException(Status.Code code, String description, byte[] serializedClientKey, byte[] clientFreshness, byte[] serverFreshness){
        Status status = Status.fromCode(code).withDescription(description);

        Metadata metadata = buildMetadata(serializedClientKey, clientFreshness, serverFreshness);


        Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);
        metadata.put(signatureKey, SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(code.value()), description.getBytes(), serializedClientKey, clientFreshness, serverFreshness), privServer));

        return status.asRuntimeException(metadata);
    }

    private Metadata buildMetadata(byte[] serializedClientKey, byte[] clientFreshness, byte[] serverFreshness){
        Metadata metadata = new Metadata();

        Metadata.Key<byte[]> clientKey = Metadata.Key.of("clientKey-bin", Metadata.BINARY_BYTE_MARSHALLER);
        Metadata.Key<byte[]> clientFreshnessKey = Metadata.Key.of("clientFreshness-bin", Metadata.BINARY_BYTE_MARSHALLER);
        Metadata.Key<byte[]> serverFreshnessKey = Metadata.Key.of("serverFreshness-bin", Metadata.BINARY_BYTE_MARSHALLER);

        metadata.put(clientKey, serializedClientKey);
        metadata.put(clientFreshnessKey, clientFreshness);
        metadata.put(serverFreshnessKey, serverFreshness);

        return metadata;
    }

    private void setUpConnection(){

        when(stub.diffieHellmanExchange(isA(Contract.DHExchangeRequest.class))).thenAnswer(new Answer<ListenableFuture<Contract.DHExchangeResponse>>() {
            @Override
            public ListenableFuture<Contract.DHExchangeResponse> answer(InvocationOnMock invocation) throws Throwable {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                PrivateKey priv = kp.getPrivate();

                Object[] args = invocation.getArguments();
                Contract.DHExchangeRequest request =  (Contract.DHExchangeRequest) args[0];

                DiffieHellmanServer dhServer = new DiffieHellmanServer();
                byte[] serverAgreement = dhServer.execute(request.getClientAgreement().toByteArray());
                byte[] clientChallenge = request.getClientChallenge().toByteArray();

                messageHandler.resetHMAC(dhServer.getSharedHMACKey());

                byte[] challenge = FreshnessHandler.generateRandomBytes(8);
                byte[] signature = SignatureHandler.publicSign(Bytes.concat(serverAgreement, clientChallenge, challenge), priv);

                Contract.DHExchangeResponse setUpResponse = Contract.DHExchangeResponse.newBuilder().setServerAgreement(ByteString.copyFrom(serverAgreement)).setServerResponse(request.getClientChallenge()).setServerChallenge(ByteString.copyFrom(clientChallenge)).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.DHExchangeResponse> setUpListener = mock(ListenableFuture.class);

                try{
                    when(setUpListener.get()).thenReturn(setUpResponse);
                }catch (Exception e){
                    fail(e.getMessage());
                }
                return setUpListener;
            }
        });
    }*/

}
