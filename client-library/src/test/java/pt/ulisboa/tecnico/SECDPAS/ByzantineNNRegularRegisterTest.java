package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import io.grpc.CallOptions;
import io.grpc.Deadline;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

public class ByzantineNNRegularRegisterTest {

    private static ByzantineNNRegularRegister regularRegister;
    private static int numServers;
    private static int numFaults;
    private static DPASServiceGrpc.DPASServiceFutureStub[] futureStubs;
    private static PublicKey[] serverPublicKeys;
    private static FreshnessHandler readFreshnessHandler;
    private static FreshnessHandler writeFreshnessHandler;
    private static PublicKey clientPublicKey;
    private static PrivateKey clientPrivateKey;
    private static Deadline deadline;

    @BeforeClass
    public static void setUp(){

        try{
            numFaults = 1;
            numServers = 3*numFaults + 1;
            deadline = Deadline.after(5, TimeUnit.SECONDS);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            clientPublicKey = kp.getPublic();
            clientPrivateKey = kp.getPrivate();

            futureStubs = new DPASServiceGrpc.DPASServiceFutureStub[numServers];
            serverPublicKeys = new PublicKey[numServers];
            readFreshnessHandler = new FreshnessHandler();
            writeFreshnessHandler = new FreshnessHandler();

        }catch (Exception e){
            System.out.println("Unable to step up test");
        }
    }

    private static String getAnnouncementId(PublicKey user, long freshness, String id){
        return user.toString() + freshness + id;
    }

    @Test
    public void successReadTest(){
        try{

            //set up test

            for(int i = 0; i < numServers; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);

                //read response
                Contract.ReadResponse correctReadResponse = buildReadResponse("Message", readFreshnessHandler.getFreshness(), "1", privServer);

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);
            }

            int minQuorumResponses = numServers-numFaults;

            regularRegister = new ByzantineNNRegularRegister(futureStubs, serverPublicKeys, clientPublicKey, clientPrivateKey, minQuorumResponses, readFreshnessHandler);

            //end of set up

            Announcement[] announcements = regularRegister.read(0);

            Assert.assertEquals(1, announcements.length);
            Assert.assertEquals("Message", new String(announcements[0].getPost()));
            Assert.assertEquals(0, announcements[0].getFreshness());

            for(int i=0; i < numServers; i++){
                verify(futureStubs[i], times(1)).readGeneral(any());
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void failReadTest(){
        try{

            //set up test
            readFreshnessHandler = new FreshnessHandler();

            for(int i = 0; i < numServers-numFaults; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);

                //read response
                Contract.ReadResponse correctReadResponse = buildReadResponse("Message", readFreshnessHandler.getFreshness(), "1", privServer);

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);
            }

            for(int i = numServers-numFaults; i < numServers; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);
                when(futureStubs[i].getCallOptions()).thenReturn(CallOptions.DEFAULT.withDeadline(deadline));

                //read response
                Contract.ReadResponse correctReadResponse = buildReadResponse("Message", readFreshnessHandler.getFreshness()-1, "1", privServer);

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);
            }

            int minQuorumResponses = numServers-numFaults;

            regularRegister = new ByzantineNNRegularRegister(futureStubs, serverPublicKeys, clientPublicKey, clientPrivateKey, minQuorumResponses, readFreshnessHandler);

            //end of set up

            Announcement[] announcements = regularRegister.read(0);

            Assert.assertEquals(1, announcements.length);
            Assert.assertEquals("Message", new String(announcements[0].getPost()));
            Assert.assertEquals(0, announcements[0].getFreshness());

            for(int i=0; i < numServers-numFaults; i++){
                verify(futureStubs[i], times(1)).readGeneral(any());
            }

            for(int i=numServers-numFaults; i < numServers; i++){
                verify(futureStubs[i], atLeast(1)).readGeneral(any());
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void successByzantineReadTest(){
        try{

            //set up test
            readFreshnessHandler = new FreshnessHandler();

            for(int i = 0; i < numServers-numFaults; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);

                //read response
                Contract.ReadResponse correctReadResponse = buildReadResponse("Message", readFreshnessHandler.getFreshness(), "1", privServer);

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);
            }

            for(int i = numServers-numFaults; i < numServers; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);
                when(futureStubs[i].getCallOptions()).thenReturn(CallOptions.DEFAULT.withDeadline(deadline));

                //read response
                long freshness = readFreshnessHandler.getFreshness();
                String post = "post";
                String typeBoard = "1";

                Announcement[] announcements = new Announcement[0];
                byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);

                byte[] message = Bytes.concat(SerializationUtils.serialize(clientPublicKey), serializedAnnouncements, Longs.toByteArray(freshness), typeBoard.getBytes());
                byte[] signature = SignatureHandler.publicSign(message, privServer);

                Contract.ReadResponse correctReadResponse = Contract.ReadResponse.newBuilder().setPublicKey(ByteString.copyFrom(SerializationUtils.serialize(clientPublicKey))).setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);
            }

            int minQuorumResponses = numServers-numFaults;

            regularRegister = new ByzantineNNRegularRegister(futureStubs, serverPublicKeys, clientPublicKey, clientPrivateKey, minQuorumResponses, readFreshnessHandler);

            //end of set up

            Announcement[] announcements = regularRegister.read(0);

            Assert.assertEquals(1, announcements.length);
            Assert.assertEquals("Message", new String(announcements[0].getPost()));
            Assert.assertEquals(0, announcements[0].getFreshness());

            for(int i=0; i < numServers; i++){
                verify(futureStubs[i], times(1)).readGeneral(any());
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void successByzantineCopyOfPostsReadTest(){
        try{

            //set up test
            readFreshnessHandler = new FreshnessHandler();

            for(int i = 0; i < numServers-numFaults; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);

                //read response
                Contract.ReadResponse correctReadResponse = buildReadResponse("Message", readFreshnessHandler.getFreshness(), "1", privServer);

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);
            }

            for(int i = numServers-numFaults; i < numServers; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);
                when(futureStubs[i].getCallOptions()).thenReturn(CallOptions.DEFAULT.withDeadline(deadline));

                //read response
                long freshness = readFreshnessHandler.getFreshness();
                String post = "post";
                String typeBoard = "1";
                byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(SerializationUtils.serialize(clientPublicKey), post.getBytes(), SerializationUtils.serialize(new String[0]), Longs.toByteArray(freshness), typeBoard.getBytes()), clientPrivateKey);

                int num = 5;
                Announcement[] announcements = new Announcement[num];

                for(int j=0; j < num; j++){
                    announcements[j] = new Announcement(post.toCharArray(), clientPublicKey, new String[0], getAnnouncementId(clientPublicKey, freshness, typeBoard), messageSignature, freshness, typeBoard);
                }

                byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);

                byte[] message = Bytes.concat(SerializationUtils.serialize(clientPublicKey), serializedAnnouncements, Longs.toByteArray(freshness), typeBoard.getBytes());
                byte[] signature = SignatureHandler.publicSign(message, privServer);

                Contract.ReadResponse correctReadResponse = Contract.ReadResponse.newBuilder().setPublicKey(ByteString.copyFrom(SerializationUtils.serialize(clientPublicKey))).setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);
            }

            int minQuorumResponses = numServers-numFaults;

            regularRegister = new ByzantineNNRegularRegister(futureStubs, serverPublicKeys, clientPublicKey, clientPrivateKey, minQuorumResponses, readFreshnessHandler);

            //end of set up

            Announcement[] announcements = regularRegister.read(0);

            Assert.assertEquals(1, announcements.length);
            Assert.assertEquals("Message", new String(announcements[0].getPost()));
            Assert.assertEquals(0, announcements[0].getFreshness());

            for(int i=0; i < numServers; i++){
                verify(futureStubs[i], times(1)).readGeneral(any());
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void successByzantineOrderReadTest(){
        try{

            //set up test
            readFreshnessHandler = new FreshnessHandler();
            String typeBoard = "1";
            long freshness = readFreshnessHandler.getFreshness();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            KeyPair kp = kpg.generateKeyPair();
            PublicKey newClientKey = kp.getPublic();
            PrivateKey newClientPrivateKey = kp.getPrivate();

            byte[] messageSignature1 = SignatureHandler.publicSign(Bytes.concat(SerializationUtils.serialize(clientPublicKey), "post0".getBytes(), SerializationUtils.serialize(new String[0]), Longs.toByteArray(freshness), typeBoard.getBytes()), clientPrivateKey);
            byte[] messageSignature2 = SignatureHandler.publicSign(Bytes.concat(SerializationUtils.serialize(clientPublicKey), "post1".getBytes(), SerializationUtils.serialize(new String[0]), Longs.toByteArray(freshness+1), typeBoard.getBytes()), clientPrivateKey);
            byte[] messageSignature3 = SignatureHandler.publicSign(Bytes.concat(SerializationUtils.serialize(clientPublicKey), "post2".getBytes(), SerializationUtils.serialize(new String[0]), Longs.toByteArray(freshness+2), typeBoard.getBytes()), clientPrivateKey);
            byte[] messageSignature4 = SignatureHandler.publicSign(Bytes.concat(SerializationUtils.serialize(newClientKey), "post3".getBytes(), SerializationUtils.serialize(new String[0]), Longs.toByteArray(freshness+2), typeBoard.getBytes()), newClientPrivateKey);

            for(int i = 0; i < numServers-numFaults; i++){
                kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);

                //read response
                Announcement[] announcements = new Announcement[4];

                announcements[0] = new Announcement("post0".toCharArray(), clientPublicKey, new String[0], getAnnouncementId(clientPublicKey, freshness, typeBoard), messageSignature1, freshness, typeBoard);
                announcements[1] = new Announcement("post1".toCharArray(), clientPublicKey, new String[0], getAnnouncementId(clientPublicKey, freshness+1, typeBoard), messageSignature2, freshness+1, typeBoard);
                announcements[2] = new Announcement("post2".toCharArray(), clientPublicKey, new String[0], getAnnouncementId(clientPublicKey, freshness+2, typeBoard), messageSignature3, freshness+2, typeBoard);
                announcements[3] = new Announcement("post3".toCharArray(), newClientKey, new String[0], getAnnouncementId(newClientKey, freshness+2, typeBoard), messageSignature4, freshness+2, typeBoard);

                long responseFreshness = readFreshnessHandler.getFreshness();

                byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);

                byte[] message = Bytes.concat(SerializationUtils.serialize(clientPublicKey), serializedAnnouncements, Longs.toByteArray(responseFreshness), typeBoard.getBytes());
                byte[] signature = SignatureHandler.publicSign(message, privServer);

                Contract.ReadResponse correctReadResponse = Contract.ReadResponse.newBuilder().setPublicKey(ByteString.copyFrom(SerializationUtils.serialize(clientPublicKey))).setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(responseFreshness).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);
            }

            for(int i = numServers-numFaults; i < numServers; i++){
                kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);
                when(futureStubs[i].getCallOptions()).thenReturn(CallOptions.DEFAULT.withDeadline(deadline));

                //read response
                Announcement[] announcements = new Announcement[4];

                announcements[2] = new Announcement("post0".toCharArray(), clientPublicKey, new String[0], getAnnouncementId(clientPublicKey, freshness, typeBoard), messageSignature1, freshness, typeBoard);
                announcements[1] = new Announcement("post1".toCharArray(), clientPublicKey, new String[0], getAnnouncementId(clientPublicKey, freshness+1, typeBoard), messageSignature2, freshness+1, typeBoard);
                announcements[0] = new Announcement("post2".toCharArray(), clientPublicKey, new String[0], getAnnouncementId(clientPublicKey, freshness+2, typeBoard), messageSignature3, freshness+2, typeBoard);
                announcements[3] = new Announcement("post3".toCharArray(), newClientKey, new String[0], getAnnouncementId(newClientKey, freshness+2, typeBoard), messageSignature4, freshness+2, typeBoard);

                byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);

                byte[] message = Bytes.concat(SerializationUtils.serialize(clientPublicKey), serializedAnnouncements, Longs.toByteArray(freshness), typeBoard.getBytes());
                byte[] signature = SignatureHandler.publicSign(message, privServer);

                Contract.ReadResponse correctReadResponse = Contract.ReadResponse.newBuilder().setPublicKey(ByteString.copyFrom(SerializationUtils.serialize(clientPublicKey))).setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);
            }

            int minQuorumResponses = numServers-numFaults;

            regularRegister = new ByzantineNNRegularRegister(futureStubs, serverPublicKeys, clientPublicKey, clientPrivateKey, minQuorumResponses, readFreshnessHandler);

            //end of set up

            Announcement[] announcements = regularRegister.read(0);

            Assert.assertEquals(4, announcements.length);
            Assert.assertEquals("post0", new String(announcements[0].getPost()));
            Assert.assertEquals("post1", new String(announcements[1].getPost()));

           if(!(new String(announcements[2].getPost()).equals("post2") && new String(announcements[3].getPost()).equals("post3")) && !(new String(announcements[2].getPost()).equals("post3") && new String(announcements[3].getPost()).equals("post2"))){

               System.out.println("1: " + new String(announcements[2].getPost()) + " freshness " + announcements[2].getFreshness());
               System.out.println("2: " + new String(announcements[3].getPost()) + " freshness " + announcements[3].getFreshness());
               fail();
           }

            Assert.assertEquals(0, announcements[0].getFreshness());
            Assert.assertEquals(1, announcements[1].getFreshness());
            Assert.assertEquals(2, announcements[2].getFreshness());
            Assert.assertEquals(2, announcements[3].getFreshness());

            for(int i=0; i < numServers; i++){
                verify(futureStubs[i], times(1)).readGeneral(any());
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void successWriteTest(){
        try{

            //set up

            for(int i = 0; i < numServers; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);

                //read response
                String typeBoard = "1";

                Contract.ReadResponse correctReadResponse = buildReadResponse("Message", readFreshnessHandler.getFreshness(), typeBoard, privServer);

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);

                //post response

                Contract.ACK correctPostResponse = buildACKResponse(typeBoard, privServer, readFreshnessHandler.getFreshness()+1);

                ListenableFuture<Contract.ACK> successFuturePostAnswer = Futures.immediateFuture(correctPostResponse);
                when(futureStubs[i].postGeneral(isA(Contract.PostRequest.class))).thenReturn(successFuturePostAnswer);

           }

            int minQuorumResponses = numServers-numFaults;

            regularRegister = new ByzantineNNRegularRegister(futureStubs, serverPublicKeys, clientPublicKey, clientPrivateKey, minQuorumResponses, readFreshnessHandler);

            //end of set up

            regularRegister.write("hi there".toCharArray(), new String[0]);

            for(int i=0; i < numServers; i++){
                verify(futureStubs[i], times(1)).readGeneral(any());
                verify(futureStubs[i], times(1)).postGeneral(any());
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void successByzantineWriteTest(){
        try{

            //set up

            for(int i=0; i<10; i++){
                readFreshnessHandler.incrementFreshness();
            }

            for(int i = 0; i < numServers-numFaults; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);

                //read response
                String typeBoard = "1";

                Contract.ReadResponse correctReadResponse = buildReadResponse("Message", readFreshnessHandler.getFreshness(), typeBoard, privServer);

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);

                //post response

                Contract.ACK correctPostResponse = buildACKResponse(typeBoard, privServer, readFreshnessHandler.getFreshness()+1);

                ListenableFuture<Contract.ACK> successFuturePostAnswer = Futures.immediateFuture(correctPostResponse);
                when(futureStubs[i].postGeneral(isA(Contract.PostRequest.class))).thenReturn(successFuturePostAnswer);

            }

            for(int i = numServers-numFaults; i < numServers; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                serverPublicKeys[i] = kp.getPublic();
                PrivateKey privServer = kp.getPrivate();

                futureStubs[i] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);
                when(futureStubs[i].getCallOptions()).thenReturn(CallOptions.DEFAULT.withDeadline(deadline));

                //read response
                String typeBoard = "1";

                Contract.ReadResponse correctReadResponse = buildReadResponse("Message", readFreshnessHandler.getFreshness()-1, typeBoard, privServer);

                ListenableFuture<Contract.ReadResponse> successFutureReadAnswer = Futures.immediateFuture(correctReadResponse);
                when(futureStubs[i].readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureReadAnswer);

                //post response

                Contract.ACK correctPostResponse = buildACKResponse(typeBoard, privServer, readFreshnessHandler.getFreshness());

                ListenableFuture<Contract.ACK> successFuturePostAnswer = Futures.immediateFuture(correctPostResponse);
                when(futureStubs[i].postGeneral(isA(Contract.PostRequest.class))).thenReturn(successFuturePostAnswer);



            }

            int minQuorumResponses = numServers-numFaults;

            regularRegister = new ByzantineNNRegularRegister(futureStubs, serverPublicKeys, clientPublicKey, clientPrivateKey, minQuorumResponses, readFreshnessHandler);

            //end of set up

            regularRegister.write("hi there".toCharArray(), new String[0]);

            for(int i=0; i < numServers-numFaults; i++){
                verify(futureStubs[i], times(1)).readGeneral(any());
                verify(futureStubs[i], times(1)).postGeneral(any());
            }

            for(int i=numServers-numFaults; i < numServers; i++){
                verify(futureStubs[i], atLeast(1)).readGeneral(any());
                verify(futureStubs[i], atLeast(1)).postGeneral(any());
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    private Contract.ReadResponse buildReadResponse(String post, long freshness, String typeBoard, PrivateKey privServer){
        byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(SerializationUtils.serialize(clientPublicKey), post.getBytes(), SerializationUtils.serialize(new String[0]), Longs.toByteArray(freshness), typeBoard.getBytes()), clientPrivateKey);

        Announcement[] announcements = new Announcement[1];
        announcements[0] = new Announcement(post.toCharArray(), clientPublicKey, new String[0], getAnnouncementId(clientPublicKey, freshness, typeBoard), messageSignature, freshness, typeBoard);
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);

        byte[] message = Bytes.concat(SerializationUtils.serialize(clientPublicKey), serializedAnnouncements, Longs.toByteArray(freshness), typeBoard.getBytes());
        byte[] signature = SignatureHandler.publicSign(message, privServer);

        return Contract.ReadResponse.newBuilder().setPublicKey(ByteString.copyFrom(SerializationUtils.serialize(clientPublicKey))).setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();
    }

    private Contract.ACK buildACKResponse(String typeBoard, PrivateKey privServer, long freshness){
        byte[] message = Bytes.concat(SerializationUtils.serialize(clientPublicKey), Longs.toByteArray(freshness), typeBoard.getBytes());
        byte[] signature = SignatureHandler.publicSign(message, privServer);

        return Contract.ACK.newBuilder().setPublicKey(ByteString.copyFrom(SerializationUtils.serialize(clientPublicKey))).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();
    }

}
