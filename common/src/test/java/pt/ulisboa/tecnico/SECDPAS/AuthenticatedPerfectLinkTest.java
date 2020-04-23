package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
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
    private static PrivateKey wrongPrivServer;
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

            kp = kpg.genKeyPair();
            wrongPrivServer = kp.getPrivate();

            stub = mock(DPASServiceGrpc.DPASServiceFutureStub.class);
            freshnessHandler = new FreshnessHandler();

            link = new AuthenticatedPerfectLink(stub, freshnessHandler.getFreshness(), publicKey);

        }catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void successRegisterSimple(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = new byte[0];
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> failedFuture = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(failedFuture).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successRegisterSignatureCompromise(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = new byte[0];
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);
        byte[] incorrectSignature = SignatureHandler.publicSign(freshness, wrongPrivServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostSimple(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> failedFuture = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.post(isA(Contract.PostRequest.class))).thenReturn(failedFuture).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostSignatureCompromise(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);
        byte[] incorrectSignature = SignatureHandler.publicSign(freshness, wrongPrivServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.post(isA(Contract.PostRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostFreshnessCompromise(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        byte[] wrongFreshness = Longs.toByteArray(-1);
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);
        byte[] incorrectSignature = SignatureHandler.publicSign(wrongFreshness, privServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(wrongFreshness)).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.post(isA(Contract.PostRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostIntegrityFreshnessCompromise(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);
        byte[] incorrectSignature = SignatureHandler.publicSign(Longs.toByteArray(2), privServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(Longs.toByteArray(-1))).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.post(isA(Contract.PostRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostGeneralSimple(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(3, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostGeneralSignatureCompromise(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);
        byte[] incorrectSignature = SignatureHandler.publicSign(freshness, wrongPrivServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostGeneralFreshnessCompromise(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        byte[] wrongFreshness = Longs.toByteArray(-1);
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);
        byte[] incorrectSignature = SignatureHandler.publicSign(wrongFreshness, privServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(wrongFreshness)).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successPostGeneralIntegrityFreshnessCompromise(){
        ArrayList<Contract.ACK> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.PostRequest request = Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setMessage(ByteString.copyFrom(new byte[0])).setMessageSignature(ByteString.copyFrom(new byte[0])).setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        byte[] signature = SignatureHandler.publicSign(freshness, privServer);
        byte[] incorrectSignature = SignatureHandler.publicSign(Longs.toByteArray(2), privServer);

        Contract.ACK incorrectResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(Longs.toByteArray(-1))).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ACK> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ACK> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.postGeneral(isA(Contract.PostRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadSimple(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> failedFuture = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(failedFuture).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadSignatureCompromise(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        byte[] incorrectSignature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), wrongPrivServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadFreshnessCompromise(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        byte[] incorrectFreshness = Longs.toByteArray(-1);
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);
        byte[] incorrectSignature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, incorrectFreshness), privServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(incorrectFreshness)).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadIntegrityAnnouncementsCompromise(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadIntegrityFreshnessCompromise(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(Longs.toByteArray(1000))).setSignature(ByteString.copyFrom(signature)).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.read(isA(Contract.ReadRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }


    @Test
    public void successReadGeneralSimple(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> failedFuture = Futures.immediateFailedFuture(new ExecutionException("test", new Throwable()));
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(failedFuture).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadGeneralSignatureCompromise(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        byte[] incorrectSignature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), wrongPrivServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadGeneralFreshnessCompromise(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        byte[] incorrectFreshness = Longs.toByteArray(-1);
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);
        byte[] incorrectSignature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, incorrectFreshness), privServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(incorrectFreshness)).setSignature(ByteString.copyFrom(incorrectSignature)).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadGeneralIntegrityAnnouncementsCompromise(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(new byte[0])).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

    @Test
    public void successReadGeneralIntegrityFreshnessCompromise(){
        ArrayList<Contract.ReadResponse> successes = new ArrayList<>();
        ArrayList<Throwable> failures = new ArrayList<>();

        //request
        Contract.ReadRequest request = Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(new byte[0])).setTargetPublicKey(ByteString.copyFrom(new byte[0])).setNumber(0).setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        byte[] freshness = Longs.toByteArray(freshnessHandler.getFreshness());
        Announcement[] announcements = new Announcement[0];
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcements);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(serializedAnnouncements, freshness), privServer);

        Contract.ReadResponse incorrectResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(Longs.toByteArray(1000))).setSignature(ByteString.copyFrom(signature)).build();

        Contract.ReadResponse correctResponse = Contract.ReadResponse.newBuilder().setAnnouncements(ByteString.copyFrom(serializedAnnouncements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

        try{
            ListenableFuture<Contract.ReadResponse> successFutureWrongAnswer = Futures.immediateFuture(incorrectResponse);
            ListenableFuture<Contract.ReadResponse> successFutureRightAnswer = Futures.immediateFuture(correctResponse);

            when(stub.readGeneral(isA(Contract.ReadRequest.class))).thenReturn(successFutureWrongAnswer).thenReturn(successFutureRightAnswer);

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

            int timeout = 50;
            while(successes.size() != 1){
                if(timeout-- == 0) break;
                Thread.sleep(100);
            }

            assertNotEquals(0, timeout);
            assertEquals(1, successes.size());
            assertEquals(0, failures.size());
            assertEquals(2, link.getNumIterations());

        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }
}