package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.DPASServiceGrpc;
import SECDPAS.grpc.Contract;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
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

            int result = qr.waitForQuorum();

            assertEquals(0, result);
        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    @Test
    public void successRegisterOneFailure(){
        //request
        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = new byte[0];

        try{

            for(int i = 0; i < faults*3+1; i++){
                if(i == faults*3){
                    byte[] serializedPubKey = SerializationUtils.serialize(publicKey.get(i));
                    StatusRuntimeException correctException = buildException(Status.Code.INVALID_ARGUMENT, "PublicKey", serializedPubKey, freshness, i);
                    ListenableFuture<Contract.ACK> failedFutureWrongAnswer = Futures.immediateFailedFuture(correctException);
                    when(stubs.get(i).register(isA(Contract.RegisterRequest.class))).thenReturn(failedFutureWrongAnswer);
                }
                else{
                    byte[] signature = SignatureHandler.publicSign(freshness, privServer.get(i));
                    Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

                    ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                    when(stubs.get(i).register(isA(Contract.RegisterRequest.class))).thenReturn(successFutureRightAnswer);
                }
            }

            Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new RegisterRequest(request), faults*2+1);

            int result = qr.waitForQuorum();

            assertEquals(0, result);
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
                byte[] signature = SignatureHandler.publicSign(freshness, privServer.get(i));
                Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

                ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);
                when(stubs.get(i).register(isA(Contract.RegisterRequest.class))).thenReturn(successFutureRightAnswer);
            }
            for(int i = faults*3-1; i < faults*3+1; i++){
                byte[] serializedPubKey = SerializationUtils.serialize(publicKey.get(i));
                StatusRuntimeException correctException = buildException(Status.Code.INVALID_ARGUMENT, "PublicKey", serializedPubKey, freshness, i);
                ListenableFuture<Contract.ACK> failedFutureWrongAnswer = Futures.immediateFailedFuture(correctException);
                when(stubs.get(i).register(isA(Contract.RegisterRequest.class))).thenReturn(failedFutureWrongAnswer);
            }

            Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new RegisterRequest(request), faults*2+1);

            int result = qr.waitForQuorum();

            assertEquals(-1, result);
        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }
    }

    private StatusRuntimeException buildException(Status.Code code, String description, byte[] serializedClientKey, byte[] clientFreshness, int numServer){
        Status status = Status.fromCode(code).withDescription(description);

        Metadata metadata = buildMetadata(serializedClientKey, clientFreshness);


        Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);
        metadata.put(signatureKey, SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(code.value()), description.getBytes(), serializedClientKey, clientFreshness), privServer.get(numServer)));

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
/*

    @Test
    public void successPost(){
        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        try{
            ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);
            ExecutionException exception = new ExecutionException("test", new Throwable());

            when(listenableFuture.get()).thenThrow(exception).thenThrow(exception).thenThrow(exception).thenReturn(correctResponse);

            when(stub.post(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

            link.post(request);

            verify(stub, times(4)).post(isA(Contract.PostRequest.class));
        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostGeneral(){
        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        try{
            ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);
            ExecutionException exception = new ExecutionException("test", new Throwable());

            when(listenableFuture.get()).thenThrow(exception).thenThrow(exception).thenThrow(exception).thenReturn(correctResponse);

            when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(listenableFuture);

            link.postGeneral(request);

            verify(stub, times(4)).postGeneral(isA(Contract.PostRequest.class));
        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successRead(){
        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        try{
            ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);
            ExecutionException exception = new ExecutionException("test", new Throwable());

            when(listenableFuture.get()).thenThrow(exception).thenThrow(exception).thenThrow(exception).thenReturn(correctResponse);

            when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

            link.read(request);

            verify(stub, times(4)).read(isA(Contract.ReadRequest.class));
        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadGeneral(){
        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        try{
            ListenableFuture<Contract.ReadResponse> listenableFuture = mock(ListenableFuture.class);
            ExecutionException exception = new ExecutionException("test", new Throwable());

            when(listenableFuture.get()).thenThrow(exception).thenThrow(exception).thenThrow(exception).thenReturn(correctResponse);

            when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(listenableFuture);

            link.readGeneral(request);

            verify(stub, times(4)).readGeneral(isA(Contract.ReadRequest.class));
        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }
*/
}