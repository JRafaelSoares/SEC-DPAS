package pt.ulisboa.tecnico.SECDPAS;


import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.util.concurrent.FutureCallback;
import com.google.protobuf.ByteString;
import org.apache.commons.lang3.SerializationUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public class AuthenticatedDoubleEchoBroadcast {
    private Consumer<RequestType> executor;
    private DPASServiceGrpc.DPASServiceFutureStub[] futureStubs;
    private RequestType clientRequest;
    private PublicKey[] serverPublicKeys;
    private PrivateKey serverPrivateKey;
    private int numFaults;
    private int numServers;
    private int minResponses;
    private int serverID;
    private AtomicBoolean sentEcho;
    private AtomicBoolean sentReady;
    private AtomicBoolean hasDelivered;
    private final HashSet<Integer> echos;
    private final HashSet<Integer> readys;
    private final CountDownLatch readyCountDownLatch;

    public AuthenticatedDoubleEchoBroadcast(RequestType clientRequest, int serverID, int numServers, int numFaults, DPASServiceGrpc.DPASServiceFutureStub[] futureStubs, PublicKey[] serverPublicKeys, PrivateKey serverPrivateKey, Consumer<RequestType> executor){
        this.serverID = serverID;
        this.futureStubs = futureStubs;
        this.clientRequest = clientRequest;
        this.serverPublicKeys = serverPublicKeys;
        this.serverPrivateKey = serverPrivateKey;
        this.numFaults = numFaults;
        this.numServers = numServers;
        this.sentEcho = new AtomicBoolean(false);
        this.sentReady = new AtomicBoolean(false);
        this.hasDelivered = new AtomicBoolean(false);
        this.minResponses = (int)Math.ceil(((double)numServers + numFaults)/2);
        this.echos = new HashSet<>(numServers);
        this.readys = new HashSet<>(numServers);
        this.readyCountDownLatch = new CountDownLatch(1);
        this.executor = executor;
    }

    public synchronized void addECHO(int serverID){
        echos.add(serverID);

        if(echos.size() >= minResponses && !sentReady.get()){
            addReady(this.serverID);

            broadcast("Ready");
        }
    }

    public synchronized void addReady(int serverID){
        readys.add(serverID);

        // If we have received more than f readys, than at least one correct server has received 2f + 1 echos
        if(readys.size() > numFaults && !sentReady.get()){
            readys.add(this.serverID);

            broadcast("Ready");
        }

        if(readys.size() >= minResponses && !hasDelivered.get()){
            hasDelivered.set(true);
            executor.accept(this.clientRequest);
            readyCountDownLatch.countDown();
        }
    }

    public void broadcast(String type){
        switch(type){
            case "Echo":
                synchronized (sentEcho){
                    if(sentEcho.get()) return;
                    sentEcho.set(true);
                }
                break;
            case "Ready":
                synchronized (sentReady){
                    if(sentReady.get()) return;
                    sentReady.set(true);
                }
                break;
        }

        //TODO- Build signature into echo request
        Contract.EchoRequest echoRequest = Contract.EchoRequest.newBuilder().setServerID(this.serverID).setRequest(ByteString.copyFrom(SerializationUtils.serialize(clientRequest))).setSignature(ByteString.copyFrom(new byte[0])).build();

        RequestType request = new EchoRequest(echoRequest, type);

        // broadcast to servers other than me with signature
        for (int i = 0; i < numServers; i++) {
            if(i == this.serverID) continue;
            AuthenticatedPerfectLink perfectLink = new AuthenticatedPerfectLink(futureStubs[i], 0, serverPublicKeys[i], serverPublicKeys[this.serverID]);

            FutureCallback<Contract.ACK> futureCallback = new FutureCallback<>() {
                @Override
                public void onSuccess(Contract.ACK res) {

                }

                @Override
                public void onFailure(Throwable t) {

                }
            };

            perfectLink.process(request, futureCallback);
        }
    }

    public boolean hasDelivered(){
        return hasDelivered.get();
    }

    public void waitForReadys() throws InterruptedException {
        readyCountDownLatch.await();
    }
}
