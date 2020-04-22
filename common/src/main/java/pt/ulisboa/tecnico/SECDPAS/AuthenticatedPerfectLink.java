package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.SerializationUtils;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.security.PublicKey;
import java.util.concurrent.Executors;

public class AuthenticatedPerfectLink {

    private DPASServiceGrpc.DPASServiceFutureStub futureStub;
    private FreshnessHandler freshnessHandler;
    private PublicKey serverPublicKey;

    //for tests
    private int numIterations = 0;

    AuthenticatedPerfectLink(DPASServiceGrpc.DPASServiceFutureStub futureStub, FreshnessHandler freshnessHandler, PublicKey serverPublicKey){
        this.futureStub = futureStub;
        this.freshnessHandler = freshnessHandler;
        this.serverPublicKey = serverPublicKey;
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
                if(ack != null && verifySignature(serverPublicKey, ack.getFreshness().toByteArray(), ack.getSignature().toByteArray())){
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

        if(type.equals("PostRequest")){
            listenable = futureStub.post(request);
        }else{
            listenable = futureStub.postGeneral(request);
        }

        Futures.addCallback(listenable, new FutureCallback<>() {
            @Override
            public void onSuccess(Contract.@Nullable ACK ack) {
                if(ack != null && verifySignature(serverPublicKey, ack.getFreshness().toByteArray(), ack.getSignature().toByteArray()) && verifyFreshness(Longs.fromByteArray(ack.getFreshness().toByteArray()))){
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

        if(type.equals("ReadRequest")){
            listenable = futureStub.read(request);
        }else{
            listenable = futureStub.readGeneral(request);
        }

        Futures.addCallback(listenable, new FutureCallback<>() {
            @Override
            public void onSuccess(Contract.@Nullable ReadResponse response) {
                if(response != null && verifySignature(serverPublicKey, Bytes.concat(response.getAnnouncements().toByteArray(),response.getFreshness().toByteArray()), response.getSignature().toByteArray()) && verifyFreshness(Longs.fromByteArray(response.getFreshness().toByteArray())) && verifyAnnouncementsSignature(response.getAnnouncements().toByteArray())){
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

    private boolean verifySignature(PublicKey k, byte[] m, byte[] s){
        return SignatureHandler.verifyPublicSignature(m, s, k);
    }

    private boolean verifyFreshness(long f){
        return freshnessHandler.verifyFreshness(f);
    }

    private boolean verifyAnnouncementsSignature(byte[] announcementBytes){
        Announcement[] announcements = SerializationUtils.deserialize(announcementBytes);
        for(Announcement announcement : announcements){
            byte[] serializedAnnouncements = SerializationUtils.serialize(announcement.getAnnouncements());
            byte[] serializedPublicKey = SerializationUtils.serialize(announcement.getPublicKey());
            byte[] messageBytes = new String(announcement.getPost()).getBytes();

            if(!SignatureHandler.verifyPublicSignature(Bytes.concat(serializedPublicKey, messageBytes, serializedAnnouncements), announcement.getSignature(), announcement.getPublicKey())){
                return false;
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
