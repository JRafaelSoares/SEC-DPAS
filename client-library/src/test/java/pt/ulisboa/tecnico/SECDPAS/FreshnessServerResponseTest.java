package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
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

    private static FreshnessHandler freshnessHandler;
    private static PublicKey pubClient;
    private static PrivateKey privServer;
    private static PrivateKey privClient;
    private static ClientLibrary lib;
    private static DPASServiceGrpc.DPASServiceFutureStub stub;
    private static byte[] messageSignaturePost;
    private static byte[] messageSignaturePostGeneral;

    @Rule
    public ExpectedException thrown = ExpectedException.none();
/*
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

        byte[] publicKey = SerializationUtils.serialize(pubClient);
        byte[] postBytes = "message".getBytes();
        byte[] announcements = SerializationUtils.serialize(new String[0]);
        messageSignaturePost = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, announcements), privClient);

        freshnessHandler.getNextFreshness();
        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

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

        byte[] publicKey = SerializationUtils.serialize(pubClient);
        byte[] postBytes = "message".getBytes();
        byte[] announcements = SerializationUtils.serialize(new String[0]);
        messageSignaturePostGeneral = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, announcements), privClient);

        freshnessHandler.getNextFreshness();

        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

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

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], "0", messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        freshnessHandler.getNextFreshness();

        byte[] responseFreshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        byte[] responseSignature = SignatureHandler.publicSign(Bytes.concat(responseAnnouncements, responseFreshness), privServer);

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

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], "0", messageSignaturePostGeneral));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        freshnessHandler.getNextFreshness();

        byte[] responseFreshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        byte[] responseSignature = SignatureHandler.publicSign(Bytes.concat(responseAnnouncements, responseFreshness), privServer);

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
    public void failFreshnessPost() throws ClientNotRegisteredException, InvalidArgumentException {

        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

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
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }

    @Test
    public void failFreshnessPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException {

        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

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
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }

    @Test
    public void failFreshnessCrossPostGeneral() throws ClientNotRegisteredException, InvalidArgumentException {

        byte[] freshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

        Contract.ACK response = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);
        when(stub.post(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

        try{
            lib.post("message".toCharArray());
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }

    @Test
    public void zfailFreshnessRead() throws ClientNotRegisteredException, InvalidArgumentException {

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], "0", messageSignaturePost));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        byte[] responseSignature = SignatureHandler.publicSign(Bytes.concat(responseAnnouncements, responseFreshness), privServer);

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
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }

    @Test
    public void zfailFreshnessReadGeneral() throws ClientNotRegisteredException, InvalidArgumentException {

        ArrayList<Announcement> announcementList = new ArrayList<>();
        announcementList.add(new Announcement("message".toCharArray(), pubClient, new String[0], "0", messageSignaturePostGeneral));

        byte[] responseAnnouncements = SerializationUtils.serialize(announcementList.toArray(new Announcement[0]));

        byte[] responseFreshness = Longs.toByteArray(freshnessHandler.getNextFreshness());
        byte[] responseSignature = SignatureHandler.publicSign(Bytes.concat(responseAnnouncements, responseFreshness), privServer);

        Contract.ReadResponse response = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(responseAnnouncements)).setFreshness(ByteString.copyFrom(responseFreshness)).setSignature(ByteString.copyFrom(responseSignature)).build();

        ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);

        try{
            when(listenableFuture.get()).thenReturn(response);
        }catch (Exception e){
            fail(e.getMessage());
        }

        when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

        try{
            lib.readGeneral( 0);
            fail("Communication exception - Server response was not fresh - should have been thrown.");
        }catch (ComunicationException e){
            assertEquals("Server response was not fresh", e.getMessage());
        }
    }
*/
}
