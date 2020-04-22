package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.DPASServiceGrpc;
import SECDPAS.grpc.Contract;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
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
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

public class QuorumTest {

    private static AuthenticatedPerfectLink link;
    private static ArrayList<DPASServiceGrpc.DPASServiceFutureStub> stubs = new ArrayList<>();
    private static ArrayList<PrivateKey> privServer = new ArrayList<>();
    private static ArrayList<PublicKey> publicKey = new ArrayList<>();
    private static ArrayList<FreshnessHandler> freshnessHandler = new ArrayList<>();
    private static Map<PublicKey, AuthenticatedPerfectLink> calls = new HashMap<>();

    private static final int faults = 1;

    @BeforeClass
    public static void setUp(){

        try{
            for(int i = 0; i < 3*faults+1; i++){
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                privServer.add(kp.getPrivate());
                publicKey.add(kp.getPublic());
                freshnessHandler.add(new FreshnessHandler());

                stubs.add(mock(DPASServiceGrpc.DPASServiceFutureStub.class));//.withDeadlineAfter(1, TimeUnit.MILLISECONDS);
                link = new AuthenticatedPerfectLink(stubs.get(i), freshnessHandler.get(i), publicKey.get(i));
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
        byte[] freshness = new byte[0];

        try{
            int numServer = 0;

            for(DPASServiceGrpc.DPASServiceFutureStub stub : stubs){
                byte[] signature = SignatureHandler.publicSign(freshness, privServer.get(numServer));
                Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(successFutureRightAnswer);

                numServer++;
            }

            Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new RegisterRequest(request), faults*2+1);

            boolean result = qr.waitForQuorum();

            assertTrue(result);
            assertEquals(numServer, qr.getSuccesses().size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }
/*
    @Test
    public void successRegisterOneFailure(){
        //request
        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = new byte[0];

        try{

            for(int i = 0; i < faults*3+1; i++){
                if(i == faults*3){
                    byte[] newFreshness = Longs.toByteArray(10);
                    byte[] signature = SignatureHandler.publicSign(newFreshness, privServer.get(i));
                    Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(newFreshness)).setSignature(ByteString.copyFrom(signature)).build();

                    ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                    when(stubs.get(i).register(isA(Contract.RegisterRequest.class))).thenReturn(successFutureRightAnswer);
                }
                else{
                    byte[] signature = SignatureHandler.publicSign(freshness, privServer.get(i));
                    Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

                    ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                    when(stubs.get(i).register(isA(Contract.RegisterRequest.class))).thenReturn(successFutureRightAnswer);
                }
            }

            Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new RegisterRequest(request), faults*2+1);

            boolean result = qr.waitForQuorum();

            assertTrue(result);
            assertEquals(faults*3, qr.getSuccesses().size());
        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void failuresRegister(){
        //request
        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = new byte[0];

        try{

            for(int i = 0; i < faults*3-1; i++){
                System.out.println(1);
                byte[] signature = SignatureHandler.publicSign(freshness, privServer.get(i));
                Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                when(stubs.get(i).register(isA(Contract.RegisterRequest.class))).thenReturn(successFutureRightAnswer);
            }
            for(int i = faults*3-1; i < faults*3+1; i++){
                System.out.println(2);
                byte[] newFreshness = Longs.toByteArray(10);
                byte[] signature = SignatureHandler.publicSign(newFreshness, privServer.get(i));
                Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(newFreshness)).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                when(stubs.get(i).register(isA(Contract.RegisterRequest.class))).thenReturn(successFutureRightAnswer);
            }

            Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new RegisterRequest(request), faults*2+1);

            boolean result = qr.waitForQuorum();

            assertFalse(result);
            assertEquals(faults*2, qr.getSuccesses().size());
        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }
*/

}