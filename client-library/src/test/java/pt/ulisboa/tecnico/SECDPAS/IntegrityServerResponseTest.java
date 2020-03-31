package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IntegrityServerResponseTest {

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
    public void successPost() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
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
    public void successPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

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
    public void successRead() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

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
    public void successReadGeneral() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

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
    public void failIntegrityRegisterCompromiseFreshness() throws ClientAlreadyRegisteredException, InvalidArgumentException{
        byte[] freshness = messageHandler.getFreshness();
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);
        freshness = messageHandler.getFreshness();

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);


        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

        when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(listenableFuture);

        try{
            lib.register();
            fail("Communication exception - Server signature was invalid - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server signature was invalid", e.getMessage());
        }

    }

    @Test
    public void failIntegrityPostCompromiseFreshness() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{
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
        freshness = messageHandler.getFreshness();

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.post(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        try{
            lib.post("message".toCharArray());
            fail("Communication exception - The integrity of the server response was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the server response was violated", e.getMessage());
        }
    }

    @Test
    public void failIntegrityPostGeneralCompromiseFreshness() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

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
        freshness = messageHandler.getFreshness();

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        try{
            lib.postGeneral("message".toCharArray());
            fail("Communication exception - The integrity of the server response was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the server response was violated", e.getMessage());
        }
    }

    @Test
    public void failIntegrityReadCompromiseFreshness() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.sign(responseAnnouncements, responseFreshness);
        responseFreshness = messageHandler.getFreshness();

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        try{
            lib.read(pubClient, 0);
            fail("Communication exception - The integrity of the server response was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the server response was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadCompromiseAnnouncementsMessage() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("wrong message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

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

        try{
            lib.read(pubClient, 0);
            fail("Communication exception - An announcement was not properly signed - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("An announcement was not properly signed", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadCompromiseAnnouncementsReferences() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[1], 0, messageSignaturePost));

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

        try{
            lib.read(pubClient, 0);
            fail("Communication exception - An announcement was not properly signed - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("An announcement was not properly signed", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadCompromiseAnnouncementsID() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.sign(responseAnnouncements, responseFreshness);

        announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 1, messageSignaturePost));

        responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        try{
            lib.read(pubClient, 0);
            fail("Communication exception - The integrity of the server response was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the server response was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadGeneralCompromiseFreshness() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.sign(responseAnnouncements, responseFreshness);
        responseFreshness = messageHandler.getFreshness();

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        try{
            lib.readGeneral(0);
            fail("Communication exception - The integrity of the server response was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the server response was violated", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadGeneralCompromiseAnnouncementsMessage() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("wrong message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

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

        try{
            lib.readGeneral(0);
            fail("Communication exception - An announcement was not properly signed - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("An announcement was not properly signed", e.getMessage());
        }

    }

    @Test
    public void failIntegrityReadGeneralCompromiseAnnouncementsReferences() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[1], 0, messageSignaturePost));

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

        try{
            lib.readGeneral(0);
            fail("Communication exception - An announcement was not properly signed - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("An announcement was not properly signed", e.getMessage());
        }
    }

    @Test
    public void failIntegrityReadGeneralCompromiseAnnouncementsID() throws ClientNotRegisteredException, InvalidArgumentException, ComunicationException{

        if(!messageHandler.isInSession()){
            setUpConnection();
            lib.setupConnection();
        }

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 0, messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = messageHandler.getFreshness();
        byte[] responseSignature = messageHandler.sign(responseAnnouncements, responseFreshness);

        announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], 1, messageSignaturePost));

        responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        try{
            lib.readGeneral(0);
            fail("Communication exception - The integrity of the server response was violated - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("The integrity of the server response was violated", e.getMessage());
        }

    }


    private void setUpConnection(){

        when(stub.setupConnection(isA(Contract.DHRequest.class))).thenAnswer(new Answer<ListenableFuture<Contract.DHResponse>>() {
            @Override
            public ListenableFuture<Contract.DHResponse> answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                Contract.DHRequest request =  (Contract.DHRequest) args[0];

                DiffieHellmanServer dhServer = new DiffieHellmanServer();
                byte[] serverAgreement = dhServer.execute(request.getClientAgreement().toByteArray());

                messageHandler.resetSignature(dhServer.getSharedHMACKey());

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
