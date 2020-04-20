package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

public class AuthenticatedPerfectLinkTest {

    private static AuthenticatedPerfectLink link;
    private static DPASServiceGrpc.DPASServiceFutureStub stub;
    private static PrivateKey privServer;
/*
    @BeforeClass
    public static void setUp(){

        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            privServer = kp.getPrivate();

            stub = mock(DPASServiceGrpc.DPASServiceFutureStub.class);//.withDeadlineAfter(1, TimeUnit.MILLISECONDS);
            link = new AuthenticatedPerfectLink(stub);

        }catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

    @Test
    public void successRegister(){
        //request
        Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        //response
        Contract.ACK correctResponse = Contract.ACK.newBuilder().setFreshness(ByteString.copyFrom(new byte[0])).setSignature(ByteString.copyFrom(new byte[0])).build();

        try{
            ListenableFuture<Contract.ACK> listenableFuture = mock(ListenableFuture.class);
            ExecutionException exception = new ExecutionException("test", new Throwable());

            when(listenableFuture.get()).thenThrow(exception).thenThrow(exception).thenThrow(exception).thenReturn(correctResponse);

            when(stub.register(isA(Contract.RegisterRequest.class))).thenReturn(listenableFuture);

            link.register(request);

            verify(stub, times(4)).register(isA(Contract.RegisterRequest.class));
        }catch (Exception e){
            System.out.println(e.getMessage());
            fail();
        }

    }

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