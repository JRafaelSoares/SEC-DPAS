package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.DPASServiceGrpc;
import SECDPAS.grpc.Contract;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

public class QuorumTest {

    private static AuthenticatedPerfectLink link;
    private static ArrayList<DPASServiceGrpc.DPASServiceFutureStub> stubs = new ArrayList<>();
    private static ArrayList<PrivateKey> privServer = new ArrayList<>();
    private static ArrayList<PublicKey> publicKey = new ArrayList<>();
    private static FreshnessHandler freshnessHandler = new FreshnessHandler();
    private static Map<PublicKey, AuthenticatedPerfectLink> calls = new HashMap<>();
    private static PublicKey clientPublicKey;
    private static final int faults = 1;

    private static String privateBoardId = "0";
    private static String generalBoardId = "1";
    @BeforeClass
    public static void setUp(){

        try{
            for(int i = 0; i < 3*faults+1; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                privServer.add(kp.getPrivate());
                publicKey.add(kp.getPublic());

                kp = kpg.generateKeyPair();
                clientPublicKey = kp.getPublic();

                stubs.add(mock(DPASServiceGrpc.DPASServiceFutureStub.class));
                link = new AuthenticatedPerfectLink(stubs.get(i), freshnessHandler.getFreshness(), publicKey.get(i), clientPublicKey);
                calls.put(publicKey.get(i), link);
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void successRegister(){
        //request
        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] publicKey = new byte[0];

        try{
            int numServer = 0;

            for(DPASServiceGrpc.DPASServiceFutureStub stub : stubs){
                byte[] signature = SignatureHandler.publicSign(publicKey, privServer.get(numServer));
                Contract.ACK correctResponse = Contract.ACK.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(successFutureRightAnswer);

                numServer++;
            }

            Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new RegisterRequest(request), faults*2+1);

            qr.waitForQuorum();

            if(qr.getSuccesses().size() < faults*2+1){
                fail(qr.getSuccesses().size() + " should be bigger or equal than " + (faults*2 + 1));
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void successPost(){
        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage("").setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(0).build();

        //response
        byte[] freshness = Longs.toByteArray(0);

        try{
            int numServer = 0;

            for(DPASServiceGrpc.DPASServiceFutureStub stub : stubs){
                byte[] signature = SignatureHandler.publicSign(freshness, privServer.get(numServer));
                Contract.ACK correctResponse = Contract.ACK.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setFreshness(0).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                when(stub.post(isA(Contract.PostRequest.class))).thenReturn(successFutureRightAnswer);

                numServer++;
            }

            Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new PostRequest(request, "PostRequest"), faults*2+1);

            qr.waitForQuorum();

            if(qr.getSuccesses().size() < faults*2+1){
                fail(qr.getSuccesses().size() + " should be bigger or equal than " + (faults*2 + 1));
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void successPostGeneral(){
        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage("").setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(0).build();

        //response
        long freshness = 0;

        try{
            int numServer = 0;

            for(DPASServiceGrpc.DPASServiceFutureStub stub : stubs){
                byte[] signature = SignatureHandler.publicSign(Bytes.concat(Longs.toByteArray(freshness), privateBoardId.getBytes()), privServer.get(numServer));
                Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(successFutureRightAnswer);

                numServer++;
            }

            Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new PostRequest(request, "PostGeneralRequest"), faults*2+1);

            qr.waitForQuorum();

            if(qr.getSuccesses().size() < faults*2+1){
                fail(qr.getSuccesses().size() + " should be bigger or equal than " + (faults*2 + 1));
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void successRead(){
        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(0).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(0);

        try{
            int numServer = 0;

            for(DPASServiceGrpc.DPASServiceFutureStub stub : stubs){
                Announcement[] announcements = new Announcement[0];
                byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
                byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer.get(numServer));
                Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(0).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(successFutureRightAnswer);

                numServer++;
            }

            Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new ReadRequest(request, "ReadRequest"), faults*2+1);

            qr.waitForQuorum();

            if(qr.getSuccesses().size() < faults*2+1){
                fail(qr.getSuccesses().size() + " should be bigger or equal than " + (faults*2 + 1));
            }

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }
}