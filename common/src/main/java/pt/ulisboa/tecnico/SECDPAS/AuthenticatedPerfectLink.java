package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import io.grpc.Context;
import io.grpc.Deadline;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.SerializationUtils;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.security.PublicKey;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

public class AuthenticatedPerfectLink {

    private DPASServiceGrpc.DPASServiceFutureStub futureStub;
    private long freshness;
    private PublicKey serverPublicKey;
    private PublicKey clientPublicKey;

    private String privateBoardId = "0";
    private String generalBoardId = "1";

    //for tests
    private int numIterations = 0;

    private boolean debug = false;

    AuthenticatedPerfectLink(DPASServiceGrpc.DPASServiceFutureStub futureStub, long freshness, PublicKey serverPublicKey, PublicKey clientKey){
        this.futureStub = futureStub;
        this.freshness = freshness;
        this.serverPublicKey = serverPublicKey;
        this.clientPublicKey = clientKey;
    }

    public void process(RequestType request, FutureCallback<?> listenableFuture){
        switch (request.getId()){
            case "RegisterRequest":
                register((Contract.RegisterRequest) request.getRequest(), (FutureCallback<Contract.ACK>) listenableFuture);
                break;
            case "PostRequest":
                post((Contract.PostRequest) request.getRequest(), (FutureCallback<Contract.ACK>) listenableFuture, "PostRequest");
                break;
            case "PostGeneralRequest":
                post((Contract.PostRequest) request.getRequest(), (FutureCallback<Contract.ACK>) listenableFuture, "PostGeneralRequest");
                break;
            case "ReadRequest":
                read((Contract.ReadRequest) request.getRequest(), (FutureCallback<Contract.ReadResponse>) listenableFuture, "ReadRequest");
                break;
            case "ReadGeneralRequest":
                read((Contract.ReadRequest) request.getRequest(), (FutureCallback<Contract.ReadResponse>) listenableFuture, "ReadGeneralRequest");
                break;
            case "Echo":
                echo((Contract.EchoRequest) request.getRequest(), (FutureCallback<Contract.ACK>) listenableFuture, "Echo");
                break;
            case "Ready":
                echo((Contract.EchoRequest) request.getRequest(), (FutureCallback<Contract.ACK>) listenableFuture, "Ready");
                break;
        }
    }

    private void register(Contract.RegisterRequest request, FutureCallback<Contract.ACK> listenableFuture) {
        numIterations++;
        ListenableFuture<Contract.ACK> listenable = futureStub.register(request);

        Futures.addCallback(listenable, new FutureCallback<>() {
            @Override
            public void onSuccess(Contract.@Nullable ACK ack) {
                if(ack != null && verifySignature(serverPublicKey, request.getPublicKey().toByteArray(), ack.getSignature().toByteArray())){
                    if(debug) System.out.println("[APL][REGISTER] Passed check");
                    listenableFuture.onSuccess(ack);
                }else{
                    if(debug) System.out.println("[APL][REGISTER] Failed check");
                    Deadline deadline = futureStub.getCallOptions().getDeadline();
                    if(deadline == null || !deadline.isExpired()){
                        register(request, listenableFuture);
                    }else{
                        listenableFuture.onFailure(new TimeoutException());
                    }
                }
            }

            @Override
            public void onFailure(Throwable t) {
                if(debug) System.out.println("[APL][REGISTER] Exception thrown: " + t.getClass());
                Deadline deadline = futureStub.getCallOptions().getDeadline();
                if(deadline == null || !deadline.isExpired()){
                    register(request, listenableFuture);
                }else{
                    listenableFuture.onFailure(new TimeoutException());
                }
            }
        }, Executors.newSingleThreadExecutor());
    }

    private void post(Contract.PostRequest request, FutureCallback<Contract.ACK> listenableFuture, String type) throws StatusRuntimeException {
        numIterations++;
        ListenableFuture<Contract.ACK> listenable;
        String board;
        if(type.equals("PostRequest")){
            listenable = futureStub.post(request);
            board = this.privateBoardId;
        }else{
            listenable = futureStub.postGeneral(request);
            board = this.generalBoardId;
        }

        Futures.addCallback(listenable, new FutureCallback<>() {
            @Override
            public void onSuccess(Contract.@Nullable ACK ack) {
                if(verifyPost(ack, board)){
                    if(debug) System.out.println("[APL][POST] Passed check");
                    listenableFuture.onSuccess(ack);
                }else{
                    if(debug) System.out.println("[APL][POST] Failed check");
                    Deadline deadline = futureStub.getCallOptions().getDeadline();
                    if(deadline == null || !deadline.isExpired()){
                        if(type.equals("PostRequest")){
                            post(request, listenableFuture, "PostRequest");
                        }else{
                            post(request, listenableFuture, "PostGeneralRequest");
                        }
                    }else{
                        listenableFuture.onFailure(new TimeoutException());
                    }

                }
            }

            @Override
            public void onFailure(Throwable t) {
                if(debug) System.out.println("[APL][POST] Exception Thrown");

                Deadline deadline = futureStub.getCallOptions().getDeadline();
                if(deadline == null || !deadline.isExpired()){
                    if(type.equals("PostRequest")){
                        post(request, listenableFuture, "PostRequest");
                    }else{
                        post(request, listenableFuture, "PostGeneralRequest");
                    }
                }else{
                    listenableFuture.onFailure(new TimeoutException());
                }
            }
        }, Executors.newSingleThreadExecutor());

    }

    private void read(Contract.ReadRequest request, FutureCallback<Contract.ReadResponse> listenableFuture, String type) throws StatusRuntimeException {
        numIterations++;
        ListenableFuture<Contract.ReadResponse> listenable;
        String board;
        if(type.equals("ReadRequest")){
            listenable = futureStub.read(request);
            board = this.privateBoardId;
        }else{
            listenable = futureStub.readGeneral(request);
            board = this.generalBoardId;
        }

        Futures.addCallback(listenable, new FutureCallback<>() {
            @Override
            public void onSuccess(Contract.@Nullable ReadResponse response) {
                if(verifyRead(response, board)){
                    if(debug) System.out.println("[APL][READ] Passed check");

                    listenableFuture.onSuccess(response);
                }else{
                    if(debug) System.out.println("[APL][READ] Failed check");
                    Deadline deadline = futureStub.getCallOptions().getDeadline();
                    if(deadline == null || !deadline.isExpired()){
                        if(type.equals("ReadRequest")){
                            read(request, listenableFuture, "ReadRequest");
                        }else{
                            read(request, listenableFuture, "ReadGeneralRequest");
                        }
                    }else{
                        listenableFuture.onFailure(new TimeoutException());
                    }
                }
            }

            @Override
            public void onFailure(Throwable t) {
                if(debug) System.out.println("[APL][READ] Exception Thrown");

                Deadline deadline = futureStub.getCallOptions().getDeadline();
                if(deadline == null || !deadline.isExpired()){
                    if(type.equals("ReadRequest")){
                        read(request, listenableFuture, "ReadRequest");
                    }else{
                        read(request, listenableFuture, "ReadGeneralRequest");
                    }
                }else{
                    listenableFuture.onFailure(new TimeoutException());
                }
            }
        }, Executors.newSingleThreadExecutor());

    }

    private void echo(Contract.EchoRequest request, FutureCallback<Contract.ACK> listenableFuture, String type) throws StatusRuntimeException {
        numIterations++;

        Context ctx = Context.current().fork();
        ctx.run(() -> {
            ListenableFuture<Contract.ACK> listenable;

            if(type.equals("Echo")){
                listenable = futureStub.echo(request);
            } else{
                listenable = futureStub.ready(request);
            }

            Futures.addCallback(listenable, new FutureCallback<>() {
                @Override
                public void onSuccess(Contract.@Nullable ACK ack) {
                    if(verifyEcho(ack)){
                        if(debug) System.out.println("[APL][" + type.toUpperCase() + "] Passed check");
                        listenableFuture.onSuccess(ack);
                    } else{
                        if(debug) System.out.println("[APL][" + type.toUpperCase() + "] Failed check");

                        Deadline deadline = futureStub.getCallOptions().getDeadline();
                        if(deadline == null || !deadline.isExpired()){
                            echo(request, listenableFuture, type);
                        }else{
                            listenableFuture.onFailure(new TimeoutException());
                        }
                    }
                }

                @Override
                public void onFailure(Throwable t) {
                    if(debug) System.out.println("[APL][" + type.toUpperCase() + "] Exception Thrown");

                    Deadline deadline = futureStub.getCallOptions().getDeadline();
                    if(deadline == null || !deadline.isExpired()){
                        echo(request, listenableFuture, type);
                    } else{
                        listenableFuture.onFailure(new TimeoutException());
                    }
                }
            }, Executors.newSingleThreadExecutor());
        });
    }


    /*********************/
    /** RESPONSE CHECKS **/
    /*********************/

    private boolean verifyPost(Contract.ACK response, String board){
        return response != null &&
                verifySignature(this.serverPublicKey, getPostSignature(response, board), response.getSignature().toByteArray()) &&
                verifyClient(response.getPublicKey()) &&
                verifyFreshness(response.getFreshness());
    }

    private byte[] getPostSignature(Contract.ACK response, String board){
        return Bytes.concat(response.getPublicKey().toByteArray(), Longs.toByteArray(response.getFreshness()), board.getBytes());
    }

    private boolean verifyClient(ByteString clientResponse){

        boolean clientCheck = clientResponse != null && this.clientPublicKey.equals(SerializationUtils.deserialize(clientResponse.toByteArray()));
        if(!clientCheck){
            if(debug) System.out.println("[APL][CLIENT] Failed Client Check");
        }
        return clientCheck;
    }

    private boolean verifyRead(Contract.ReadResponse response, String board){
        return response != null &&
                verifySignature(this.serverPublicKey, getReadSignature(response, board), response.getSignature().toByteArray()) &&
                verifyFreshness(response.getFreshness()) &&
                verifyAnnouncementsSignature(response.getAnnouncements().toByteArray(), board);

    }

    private boolean verifyEcho(Contract.ACK response){
        // TODO- Properly check if Echo response is correct (Signature)
        return true;
    }

    private byte[] getReadSignature(Contract.ReadResponse response, String board){
        return Bytes.concat(response.getPublicKey().toByteArray(), response.getAnnouncements().toByteArray(), Longs.toByteArray(response.getFreshness()), board.getBytes());
    }

    private boolean verifySignature(PublicKey k, byte[] m, byte[] s){
        boolean signatureCheck = s != null && m != null && SignatureHandler.verifyPublicSignature(m, s, k);
        if(!signatureCheck){
            if(debug) System.out.println("[APL][SIGNATURE] Failed Signature Check");
        }
        return signatureCheck;
    }

    private boolean verifyFreshness(long f){
        boolean freshnessCheck = this.freshness == f;
        if(!freshnessCheck){
            if(debug) System.out.println("[APL][FRESHNESS] Failed Freshness Check");
        }
        return freshnessCheck;
    }

    private boolean verifyAnnouncementsSignature(byte[] announcementBytes, String board){

        Announcement[] announcements = SerializationUtils.deserialize(announcementBytes);

        for(Announcement announcement : announcements){
            byte[] serializedAnnouncements = SerializationUtils.serialize(announcement.getAnnouncements());
            byte[] serializedPublicKey = SerializationUtils.serialize(announcement.getPublicKey());
            byte[] messageBytes = new String(announcement.getPost()).getBytes();
            byte[] freshness = Longs.toByteArray(announcement.getFreshness());
            byte[] boardType = announcement.getBoard().getBytes();

            byte[] signature = Bytes.concat(serializedPublicKey, messageBytes, serializedAnnouncements, freshness, boardType);

            if(!verifySignature(announcement.getPublicKey(), signature, announcement.getSignature()) || !announcement.getBoard().equals(board)){
                if(debug) System.out.println("[APL][ANNOUNCEMENT] Failed Announcement Signature Check");
                return false;
            }
            //Extra checks - If from correct type of board and if private board, from my own

            if(board.equals(this.privateBoardId)){
                if(!announcement.getPublicKey().equals(this.clientPublicKey)){
                    if(debug) System.out.println("[APL][ANNOUNCEMENT] Failed Board Check");

                    return false;
                }
            }
        }
        return true;
    }

    public int getNumIterations(){
        int aux = numIterations;
        numIterations = 0;
        return aux;
    }

    //TODO - Add timeout from too much trying (use numIterations?)
}
