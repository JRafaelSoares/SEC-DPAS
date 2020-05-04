package pt.ulisboa.tecnico.SECDPAS;


import SECDPAS.grpc.DPASServiceGrpc;

import java.util.HashSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

public class AuthenticatedDoubleEchoBroadcast {
    private DPASServiceGrpc.DPASServiceFutureStub[] futureStub;
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

    public AuthenticatedDoubleEchoBroadcast(int serverID, int numServers, int numFaults, DPASServiceGrpc.DPASServiceFutureStub[] futureStub){
        this.serverID = serverID;
        this.futureStub = futureStub;
        this.numFaults = numFaults;
        this.numServers = numServers;
        this.sentEcho = new AtomicBoolean(false);
        this.sentReady = new AtomicBoolean(false);
        this.hasDelivered = new AtomicBoolean(false);
        this.minResponses = (int)Math.ceil(((double)numServers + numFaults)/2);
        this.echos = new HashSet<>(numServers);
        this.readys = new HashSet<>(numServers);
        this.readyCountDownLatch = new CountDownLatch(1);
    }

    public synchronized void addECHO(int serverID, RequestType request){
        echos.add(serverID);

        if(echos.size() > minResponses && !sentReady.get()){
            addReady(this.serverID, request);
            // broadcast to servers other than me with signature
            sentReady.set(true);
        }
    }

    public synchronized void addReady(int serverID, RequestType request){
        readys.add(serverID);

        // If we have received more than f readys, than at least one correct server has received 2f + 1 echos
        if(readys.size() > numFaults && !sentReady.get()){
            readys.add(this.serverID);
            // broadcast to servers other than me with signature
            sentReady.set(true);
        }

        if(readys.size() > minResponses && !hasDelivered.get()){
            // post announcement
            readyCountDownLatch.countDown();
        }
    }

    public boolean hasDelivered(){
        return hasDelivered.get();
    }

    public void waitForReadys() throws InterruptedException {
        readyCountDownLatch.await();
    }
}
