package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.SerializationUtils;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.security.PublicKey;
import java.util.concurrent.Executors;

public class AuthenticatedPerfectLink {

    private DPASServiceGrpc.DPASServiceFutureStub futureStub;
    private long freshness;
    private PublicKey serverPublicKey;
    private PublicKey clientPublicKey;

    private String privateBoardId = "0";
    private String generalBoardId = "1";

    //for tests
    private int numIterations = 0;

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

        }
    }

    private void register(Contract.RegisterRequest request, FutureCallback<Contract.ACK> listenableFuture){
        numIterations++;
        ListenableFuture<Contract.ACK> listenable = futureStub.register(request);

        Futures.addCallback(listenable, new FutureCallback<>() {
            @Override
            public void onSuccess(Contract.@Nullable ACK ack) {
                if(ack != null && verifySignature(serverPublicKey, request.getPublicKey().toByteArray(), ack.getSignature().toByteArray())){
                    listenableFuture.onSuccess(ack);
                }else{
                    register(request, listenableFuture);
                }
            }

            @Override
            public void onFailure(Throwable t) {
                register(request, listenableFuture);
            }
        }, Executors.newSingleThreadExecutor());

    }

    private void post(Contract.PostRequest request, FutureCallback<Contract.ACK> listenableFuture, String type) throws StatusRuntimeException{
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
                    listenableFuture.onSuccess(ack);
                }else{
                    if(type.equals("PostRequest")){
                        post(request, listenableFuture, "PostRequest");
                    }else{
                        post(request, listenableFuture, "PostGeneralRequest");
                    }
                }
            }

            @Override
            public void onFailure(Throwable t) {
                if(type.equals("PostRequest")){
                    post(request, listenableFuture, "PostRequest");
                }else{
                    post(request, listenableFuture, "PostGeneralRequest");
                }
            }
        }, Executors.newSingleThreadExecutor());

    }

    private void read(Contract.ReadRequest request, FutureCallback<Contract.ReadResponse> listenableFuture, String type) throws StatusRuntimeException{
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
                    listenableFuture.onSuccess(response);
                }else{
                    if(type.equals("ReadRequest")){
                        read(request, listenableFuture, "ReadRequest");
                    }else{
                        read(request, listenableFuture, "ReadGeneralRequest");
                    }
                }
            }

            @Override
            public void onFailure(Throwable t) {
                if(type.equals("ReadRequest")){
                    read(request, listenableFuture, "ReadRequest");
                }else{
                    read(request, listenableFuture, "ReadGeneralRequest");
                }
            }
        }, Executors.newSingleThreadExecutor());

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

    private byte[] getReadSignature(Contract.ReadResponse response, String board){
        return Bytes.concat(response.getPublicKey().toByteArray(), response.getAnnouncements().toByteArray(), Longs.toByteArray(response.getFreshness()), board.getBytes());
    }

    private byte[] getPostSignature(Contract.ACK response, String board){
        return Bytes.concat(response.getPublicKey().toByteArray(), Longs.toByteArray(response.getFreshness()), board.getBytes());
    }

    private boolean verifyRead(Contract.ReadResponse response, String board){
        return response != null &&
                verifySignature(this.serverPublicKey, getReadSignature(response, board), response.getSignature().toByteArray()) &&
                verifyFreshness(response.getFreshness()) &&
                verifyAnnouncementsSignature(response.getAnnouncements().toByteArray(), board);

    }

    private boolean verifyClient(ByteString clientResponse){
        return clientResponse != null && this.clientPublicKey.equals(SerializationUtils.deserialize(clientResponse.toByteArray()));
    }

    private boolean verifySignature(PublicKey k, byte[] m, byte[] s){
        return s != null && m != null && SignatureHandler.verifyPublicSignature(m, s, k);
    }

    private boolean verifyFreshness(long f){
        return this.freshness == f;
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
                return false;
            }
            //Extra checks - If from correct type of board and if private board, from my own

            if(board.equals(this.privateBoardId)){
                if(announcement.getPublicKey() != this.clientPublicKey){
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
}
