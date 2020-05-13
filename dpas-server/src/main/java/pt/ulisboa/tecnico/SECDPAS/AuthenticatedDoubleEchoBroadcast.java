package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.FutureCallback;
import com.google.protobuf.ByteString;
import io.grpc.Context;
import org.apache.commons.lang3.SerializationUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

public class AuthenticatedDoubleEchoBroadcast {
    private BiConsumer<RequestType, HashMap<Integer, byte[]>> executor;
    private AuthenticatedPerfectLink[] perfectLinks;
    private RequestType clientRequest;
    private PublicKey[] serverPublicKeys;
    private PrivateKey serverPrivateKey;
    private int numFaults;
    private int numServers;
    private int minResponses;
    private int serverID;
    private final AtomicBoolean sentEcho;
    private final AtomicBoolean sentReady;
    private AtomicBoolean hasDelivered;
    private final HashSet<Integer> echos;
    private final HashMap<Integer, byte[]> readys;
    private final CountDownLatch readyCountDownLatch;

    private boolean debug = false;

    public AuthenticatedDoubleEchoBroadcast(RequestType clientRequest, int serverID, int numServers, int numFaults, AuthenticatedPerfectLink[] perfectLinks, PublicKey[] serverPublicKeys, PrivateKey serverPrivateKey, BiConsumer<RequestType, HashMap<Integer, byte[]>> executor){
        this.serverID = serverID;
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
        this.readys = new HashMap<>(numServers);
        this.readyCountDownLatch = new CountDownLatch(1);
        this.executor = executor;
        this.perfectLinks = perfectLinks;
    }

    public synchronized void addECHO(int serverID){
        echos.add(serverID);

        if(debug) System.out.println("[" + this.serverID + "]" + "[ADEB] Adding echo from server " + serverID);

        if(echos.size() >= minResponses && !sentReady.get()){
            if(debug) System.out.println("[" + this.serverID + "]" + "[ADEB] Received required number of echos: " + Arrays.toString(echos.toArray()));
            addReady(this.serverID, getAnnouncementSignature());

            broadcastReady();
        }
    }

    public synchronized void addReady(int serverID, byte[] announcementSignature){
        readys.put(serverID, announcementSignature);

        // If we have received more than f readys, than at least one correct server has received 2f + 1 echos
        if(readys.size() > numFaults && !sentReady.get()){
            if(debug) System.out.println("[" + this.serverID + "]" + "[ADEB] Received more than f readys, sending ready: " + Arrays.toString(echos.toArray()));
            readys.put(this.serverID, getAnnouncementSignature());

            broadcastReady();
        }

        if(readys.size() >= minResponses && !hasDelivered.get()){
            hasDelivered.set(true);
            executor.accept(this.clientRequest, readys);
            if(debug) System.out.println("[" + this.serverID + "]" + "[ADEB] Received required readys: " + Arrays.toString(readys.keySet().toArray()));
            readyCountDownLatch.countDown();
        }
    }

    public void broadcastEcho(){
        synchronized (sentEcho){
            if(sentEcho.get()) return;
            sentEcho.set(true);
        }

        byte[] serializedClientRequest = SerializationUtils.serialize(clientRequest);

        byte[] signature = SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(serverID), serializedClientRequest), serverPrivateKey);

        //System.out.println(String.format("\nPreparing ECHO: \n\tServerID = %d\n\tServerID Byte Array = %s\n\tSerialized Client Request = %s\n\tSignature = %s\n", serverID, Arrays.toString(Ints.toByteArray(serverID)), Arrays.toString(serializedClientRequest), Arrays.toString(signature)));

        Contract.EchoRequest echoRequest = Contract.EchoRequest.newBuilder().setServerID(serverID).setRequest(ByteString.copyFrom(serializedClientRequest)).setSignature(ByteString.copyFrom(signature)).build();

        RequestType request = new EchoRequest(echoRequest);

        broadcast(request);
    }

    public void broadcastReady(){

        synchronized (sentReady){
            if(sentReady.get()) return;
            sentReady.set(true);
        }

        byte[] serializedClientRequest = SerializationUtils.serialize(clientRequest);
        byte[] announcementSignature = getAnnouncementSignature();
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(Ints.toByteArray(serverID), announcementSignature, serializedClientRequest), serverPrivateKey);

        Contract.ReadyRequest readyRequest = Contract.ReadyRequest.newBuilder().setServerID(this.serverID).setRequest(ByteString.copyFrom(SerializationUtils.serialize(clientRequest))).setAnnouncementSignature(ByteString.copyFrom(announcementSignature)).setSignature(ByteString.copyFrom(signature)).build();

        RequestType request = new ReadyRequest(readyRequest);
        broadcast(request);
    }

    private void broadcast(RequestType request){
        // broadcast to servers other than me with signature
        for (int i = 0; i < numServers; i++) {
            if(i == this.serverID) continue;

            AuthenticatedPerfectLink perfectLink = this.perfectLinks[i];

            FutureCallback<Contract.EchoReadyACK> futureCallback = new FutureCallback<>() {
                @Override
                public void onSuccess(Contract.EchoReadyACK res) {

                }

                @Override
                public void onFailure(Throwable t) {

                }
            };

            Context ctx = Context.current().fork();
            ctx.run(() -> perfectLink.process(request, futureCallback));
        }
    }

    private byte[] getAnnouncementSignature(){
        if(clientRequest.getId().equals("PostRequest") || clientRequest.getId().equals("PostGeneralRequest")){
            Contract.PostRequest postRequest = (Contract.PostRequest) clientRequest.getRequest();
            return SignatureHandler.publicSign(Bytes.concat(postRequest.getPublicKey().toByteArray(), postRequest.getMessage().getBytes(), postRequest.getAnnouncements().toByteArray(), Longs.toByteArray(postRequest.getFreshness()), postRequest.getBoard().getBytes()), this.serverPrivateKey);
        }
        else{
            return new byte[0];
        }
    }

    public boolean hasDelivered(){
        return hasDelivered.get();
    }

    public void waitForReadys() throws InterruptedException {
        readyCountDownLatch.await();
    }

    public int getNumEchos() {
        return echos.size();
    }

    public int getNumReadys() {
        return readys.size();
    }
}