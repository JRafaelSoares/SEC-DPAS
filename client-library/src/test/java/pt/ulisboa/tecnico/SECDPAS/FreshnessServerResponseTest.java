package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runners.MethodSorters;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.ArrayList;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FreshnessServerResponseTest {

    private static MessageHandler messageHandler;
    private static PublicKey pubClient;
    private static PrivateKey privServer;
    private static PrivateKey privClient;
    private static ClientLibrary lib;
    private static DPASServiceGrpc.DPASServiceFutureStub stub;
    private static SecretKey hmacKey = null;
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

    @Test
    public void successRegister(){
        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);

            when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(listenableFuture);

            lib.register();

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPost() throws ClientNotRegisteredException, InvalidArgumentException, ServerResponseNotFreshException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ServerConnectionException, ClientSignatureInvalidException, ClientIntegrityViolationException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientSessionNotInitiatedException, NonExistentAnnouncementReferenceException {
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] publicKey = SerializationUtils.serialize(pubClient);
        byte[] postBytes = "message".getBytes();
        byte[] announcements = SerializationUtils.serialize(new String[0]);
        messageSignaturePost = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, announcements), privClient);

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.sign(new byte[0], freshness);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.post(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        lib.post("message".toCharArray());
    }

    @Test
    public void successPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ServerResponseNotFreshException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ServerConnectionException, ClientSignatureInvalidException, ClientIntegrityViolationException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientSessionNotInitiatedException, NonExistentAnnouncementReferenceException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] publicKey = SerializationUtils.serialize(pubClient);
        byte[] postBytes = "message".getBytes();
        byte[] announcements = SerializationUtils.serialize(new String[0]);
        messageSignaturePostGeneral = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, announcements), privClient);

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.sign(new byte[0], freshness);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        lib.postGeneral("message".toCharArray());
    }

    @Test
    public void successRead() throws InvalidArgumentException, ClientNotRegisteredException, ServerResponseNotFreshException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ServerConnectionException, ClientSignatureInvalidException, ClientIntegrityViolationException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientSessionNotInitiatedException, TargetClientNotRegisteredException, NonExistentAnnouncementReferenceException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.sign(responseAnnouncements, responseFreshness);

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        Announcement[] a = lib.read(pubClient, 0);

        Assert.assertEquals(1, a.length);

    }

    @Test
    public void successReadGeneral() throws InvalidArgumentException, ClientNotRegisteredException, ServerResponseNotFreshException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ServerConnectionException, ClientSignatureInvalidException, ClientIntegrityViolationException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientSessionNotInitiatedException, TargetClientNotRegisteredException, NonExistentAnnouncementReferenceException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePostGeneral));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.sign(responseAnnouncements, responseFreshness);

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        Announcement[] a = lib.readGeneral(0);

        Assert.assertEquals(1, a.length);

    }


    @Test
    public void failFreshnessRegister()throws ClientAlreadyRegisteredException, InvalidArgumentException, ServerConnectionException, ClientRequestNotFreshException, ServerResponseNotFreshException, ClientSignatureInvalidException, ServerSignatureInvalidException {
        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(listenableFuture);

        lib.register();
        thrown.expect(ServerResponseNotFreshException.class);
        lib.register();
    }

    @Test
    public void failFreshnessPost() throws ClientNotRegisteredException, InvalidArgumentException, ServerResponseNotFreshException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ServerConnectionException, ClientSignatureInvalidException, ClientIntegrityViolationException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientSessionNotInitiatedException, NonExistentAnnouncementReferenceException {
        setUpConnection();
        lib.setupConnection();

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.sign(new byte[0], freshness);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.post(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        lib.post("message".toCharArray());
        thrown.expect(ServerResponseNotFreshException.class);
        lib.post("message".toCharArray());
    }

    @Test
    public void failFreshnessPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ServerResponseNotFreshException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ServerConnectionException, ClientSignatureInvalidException, ClientIntegrityViolationException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientSessionNotInitiatedException, NonExistentAnnouncementReferenceException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.sign(new byte[0], freshness);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        lib.postGeneral("message".toCharArray());
        thrown.expect(ServerResponseNotFreshException.class);
        lib.postGeneral("message".toCharArray());
    }

    @Test
    public void failFreshnessCrossPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ServerResponseNotFreshException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ServerConnectionException, ClientSignatureInvalidException, ClientIntegrityViolationException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientSessionNotInitiatedException, NonExistentAnnouncementReferenceException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.sign(new byte[0], freshness);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);
        when(stub.post(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        lib.postGeneral("message".toCharArray());
        thrown.expect(ServerResponseNotFreshException.class);
        lib.post("message".toCharArray());
    }

    @Test
    public void zfailFreshnessRead() throws InvalidArgumentException, ClientNotRegisteredException, ServerResponseNotFreshException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ServerConnectionException, ClientSignatureInvalidException, ClientIntegrityViolationException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientSessionNotInitiatedException, TargetClientNotRegisteredException, NonExistentAnnouncementReferenceException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.sign(responseAnnouncements, responseFreshness);

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        lib.read(pubClient, 0);
        thrown.expect(ServerResponseNotFreshException.class);
        lib.read(pubClient, 0);
    }

    @Test
    public void zfailFreshnessReadGeneral() throws InvalidArgumentException, ClientNotRegisteredException, ServerResponseNotFreshException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ServerConnectionException, ClientSignatureInvalidException, ClientIntegrityViolationException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientSessionNotInitiatedException, TargetClientNotRegisteredException, NonExistentAnnouncementReferenceException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePostGeneral));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.sign(responseAnnouncements, responseFreshness);

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        lib.readGeneral(0);
        thrown.expect(ServerResponseNotFreshException.class);
        lib.readGeneral(0);
    }

    private void setUpConnection(){

        when(stub.setupConnection(isA(Contract.DHRequest.class))).thenAnswer(new Answer<ListenableFuture<Contract.DHResponse>>() {
            @Override
            public ListenableFuture<Contract.DHResponse> answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                Contract.DHRequest request =  (Contract.DHRequest) args[0];

                DiffieHellmanServer dhServer = new DiffieHellmanServer();
                byte[] serverAgreement = dhServer.execute(request.getClientAgreement().toByteArray());

                hmacKey = dhServer.getSharedHMACKey();
                messageHandler.resetSignature(hmacKey);

                byte[] freshness = messageHandler.getFreshness();
                byte[] signature = SignatureHandler.publicSign(freshness, privServer);

                Contract.DHResponse setUpResponse = Contract.DHResponse.newBuilder().setServerAgreement(ByteString.copyFrom(serverAgreement)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.DHResponse> setUpListener = mock(ListenableFuture.class);

                try{
                    when(setUpListener.get()).thenReturn(setUpResponse);
                }catch (Exception e){
                    fail(e.getMessage());
                }
                return setUpListener;
            }
        });
    }
}
