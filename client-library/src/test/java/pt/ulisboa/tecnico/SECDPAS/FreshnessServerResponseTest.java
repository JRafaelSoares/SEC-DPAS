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

import java.security.*;
import java.util.ArrayList;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FreshnessServerResponseTest {

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
    public void successRegister(){
        byte[] freshness = new byte[0];
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
    public void successPost() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {
        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] publicKey = SerializationUtils.serialize(pubClient);
        byte[] postBytes = "message".getBytes();
        byte[] announcements = SerializationUtils.serialize(new String[0]);
        messageSignaturePost = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, announcements), privClient);

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.calculateHMAC(new byte[0], freshness);

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
    public void successPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] publicKey = SerializationUtils.serialize(pubClient);
        byte[] postBytes = "message".getBytes();
        byte[] announcements = SerializationUtils.serialize(new String[0]);
        messageSignaturePostGeneral = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, announcements), privClient);

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.calculateHMAC(new byte[0], freshness);

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
    public void successRead() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.calculateHMAC(responseAnnouncements, responseFreshness);

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
    public void successReadGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePostGeneral));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.calculateHMAC(responseAnnouncements, responseFreshness);

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
    public void successCloseSession() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.calculateHMAC(new byte[0], freshness);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.closeSession(isA(Contract.CloseSessionRequest.class))).thenReturn(listenableFuture);

        lib.closeConnection();

        messageHandler.resetHMAC(null);
        assertFalse(messageHandler.isInSession());

    }

    @Test
    public void failFreshnessPost() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {
        setUpConnection();
        lib.setupConnection();

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.calculateHMAC(new byte[0], freshness);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.post(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        lib.post("message".toCharArray());
        try{
            lib.post("message".toCharArray());
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }

    @Test
    public void failFreshnessPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.calculateHMAC(new byte[0], freshness);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        lib.postGeneral("message".toCharArray());
        try{
            lib.postGeneral("message".toCharArray());
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }

    @Test
    public void failFreshnessCrossPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.calculateHMAC(new byte[0], freshness);

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
        try{
            lib.post("message".toCharArray());
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }

    @Test
    public void zfailFreshnessRead() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.calculateHMAC(responseAnnouncements, responseFreshness);

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        lib.read(pubClient, 0);
        try{
            lib.read(pubClient, 0);
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }

    @Test
    public void zfailFreshnessReadGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePostGeneral));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.calculateHMAC(responseAnnouncements, responseFreshness);

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        lib.readGeneral(0);
        try{
            lib.readGeneral( 0);
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }

    @Test
    public void failFreshnessCloseSession() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException {

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = messageHandler.calculateHMAC(new byte[0], freshness);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.closeSession(isA(Contract.CloseSessionRequest.class))).thenReturn(listenableFuture);

        lib.closeConnection();

        lib.setupConnection();

        try{
            lib.closeConnection();
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
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
