package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.SerializationUtils;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

public class AuthenticatedPerfectLinkTest {

    private static AuthenticatedPerfectLink link;
    private static DPASServiceGrpc.DPASServiceFutureStub stub;
    private static PrivateKey privServer;
    private static PublicKey publicKey;
    private static FreshnessHandler freshnessHandler;

    @BeforeClass
    public static void setUp(){

        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            publicKey = kp.getPublic();
            privServer = kp.getPrivate();

            stub = mock(DPASServiceGrpc.DPASServiceFutureStub.class);
            freshnessHandler = new FreshnessHandler();

            link = new AuthenticatedPerfectLink(stub, freshnessHandler, publicKey);

        }catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void successRegisterACK(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = new byte[0];
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> failedFuture = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(failedFuture).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

            link.process(new RegisterRequest(request), new FutureCallback<Contract.ACK>() {
                @Override
                public void onSuccess(Contract.@Nullable ACK ack) {
                    successes.add(ack);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(1, successes.size());
            assertEquals(0, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successRegisterException(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = new byte[0];

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        byte[] serializedPubKey = SerializationUtils.serialize(publicKey);
        StatusRuntimeException correctException = buildException(Status.Code.INVALID_ARGUMENT, "PublicKey", serializedPubKey, freshness);

        try{
            ListenableFuture<Contract.ACK> failedFutureWrongAnswer = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> failedFutureRightAnswer = Futures.immediateFailedFuture(correctException);

            when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(failedFutureWrongAnswer).thenReturn(successFutureWrongAnswer).thenReturn(failedFutureRightAnswer);

            link.process(new RegisterRequest(request), new FutureCallback<Contract.ACK>() {
                @Override
                public void onSuccess(Contract.@Nullable ACK ack) {
                    successes.add(ack);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(0, successes.size());
            assertEquals(1, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostACK(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(4);
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(Longs.toByteArray(1000))).setSignature(ByteString.copyFrom(new byte[0])).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> failedFuture = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.post(isA(Contract.PostRequest.class))).thenReturn(failedFuture).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

            link.process(new PostRequest(request, "PostRequest"), new FutureCallback<Contract.ACK>() {
                @Override
                public void onSuccess(Contract.@Nullable ACK ack) {
                    successes.add(ack);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(1, successes.size());
            assertEquals(0, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostException(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(6);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(Longs.toByteArray(1000))).setSignature(ByteString.copyFrom(new byte[0])).build();

        byte[] serializedPubKey = SerializationUtils.serialize(publicKey);
        StatusRuntimeException correctException = buildException(Status.Code.INVALID_ARGUMENT, "PublicKey", serializedPubKey, freshness);

        try{
            ListenableFuture<Contract.ACK> failedFutureWrongAnswer = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> failedFutureRightAnswer = Futures.immediateFailedFuture(correctException);

            when(stub.post(isA(Contract.PostRequest.class))).thenReturn(failedFutureWrongAnswer).thenReturn(successFutureWrongAnswer).thenReturn(failedFutureRightAnswer);

            link.process(new PostRequest(request, "PostRequest"), new FutureCallback<Contract.ACK>() {
                @Override
                public void onSuccess(Contract.@Nullable ACK ack) {
                    successes.add(ack);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(0, successes.size());
            assertEquals(1, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostGeneralACK(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(5);
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(Longs.toByteArray(1000))).setSignature(ByteString.copyFrom(new byte[0])).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> failedFuture = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(failedFuture).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

            link.process(new PostRequest(request, "PostGeneralRequest"), new FutureCallback<Contract.ACK>() {
                @Override
                public void onSuccess(Contract.@Nullable ACK ack) {
                    successes.add(ack);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(1, successes.size());
            assertEquals(0, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostGeneralException(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(3);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(Longs.toByteArray(1000))).setSignature(ByteString.copyFrom(new byte[0])).build();

        byte[] serializedPubKey = SerializationUtils.serialize(publicKey);
        StatusRuntimeException correctException = buildException(Status.Code.INVALID_ARGUMENT, "PublicKey", serializedPubKey, freshness);

        try{
            ListenableFuture<Contract.ACK> failedFutureWrongAnswer = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> failedFutureRightAnswer = Futures.immediateFailedFuture(correctException);

            when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(failedFutureWrongAnswer).thenReturn(successFutureWrongAnswer).thenReturn(failedFutureRightAnswer);

            link.process(new PostRequest(request, "PostGeneralRequest"), new FutureCallback<Contract.ACK>() {
                @Override
                public void onSuccess(Contract.@Nullable ACK ack) {
                    successes.add(ack);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(0, successes.size());
            assertEquals(1, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successRead(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(3);
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(Longs.toByteArray(-1))).setSignature(ByteString.copyFrom(new byte[0])).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> failedFuture = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(failedFuture).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

            link.process(new ReadRequest(request, "ReadRequest"), new FutureCallback<Contract.ReadResponse>() {
                @Override
                public void onSuccess(Contract.@Nullable ReadResponse result) {
                    successes.add(result);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(1, successes.size());
            assertEquals(0, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadException(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(6);
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(Longs.toByteArray(-1))).setSignature(ByteString.copyFrom(new byte[0])).build();

        byte[] serializedPubKey = SerializationUtils.serialize(publicKey);
        StatusRuntimeException correctException = buildException(Status.Code.INVALID_ARGUMENT, "PublicKey", serializedPubKey, freshness);

        try{
            ListenableFuture<Contract.ReadResponse> failedFutureWrongAnswer = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> failedFutureRightAnswer = Futures.immediateFailedFuture(correctException);

            when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(failedFutureWrongAnswer).thenReturn(successFutureWrongAnswer).thenReturn(failedFutureRightAnswer);

            link.process(new ReadRequest(request, "ReadRequest"), new FutureCallback<Contract.ReadResponse>() {
                @Override
                public void onSuccess(Contract.@Nullable ReadResponse result) {
                    successes.add(result);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(0, successes.size());
            assertEquals(1, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadGeneral(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(6);
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(Longs.toByteArray(-1))).setSignature(ByteString.copyFrom(new byte[0])).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> failedFuture = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(failedFuture).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

            link.process(new ReadRequest(request, "ReadGeneralRequest"), new FutureCallback<Contract.ReadResponse>() {
                @Override
                public void onSuccess(Contract.@Nullable ReadResponse result) {
                    successes.add(result);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(1, successes.size());
            assertEquals(0, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadGeneralException(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(3);
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(Longs.toByteArray(-1))).setSignature(ByteString.copyFrom(new byte[0])).build();

        byte[] serializedPubKey = SerializationUtils.serialize(publicKey);
        StatusRuntimeException correctException = buildException(Status.Code.INVALID_ARGUMENT, "PublicKey", serializedPubKey, freshness);

        try{
            ListenableFuture<Contract.ReadResponse> failedFutureWrongAnswer = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> failedFutureRightAnswer = Futures.immediateFailedFuture(correctException);

            when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(failedFutureWrongAnswer).thenReturn(successFutureWrongAnswer).thenReturn(failedFutureRightAnswer);

            link.process(new ReadRequest(request, "ReadGeneralRequest"), new FutureCallback<Contract.ReadResponse>() {
                @Override
                public void onSuccess(Contract.@Nullable ReadResponse result) {
                    successes.add(result);
                }

                @Override
                public void onFailure(Throwable t) {
                    failures.add(t);
                }
            });

            assertEquals(0, successes.size());
            assertEquals(1, failures.size());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
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