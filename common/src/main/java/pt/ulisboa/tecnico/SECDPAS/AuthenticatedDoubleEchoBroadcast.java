package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.protobuf.ByteString;
import org.apache.commons.lang3.SerializationUtils;

import java.util.HashMap;
import java.util.concurrent.CountDownLatch;

enum TypeMessage{
    SEND,
    ECHO,
    READY
}

public class AuthenticatedDoubleEchoBroadcast {
    private DPASServiceGrpc.DPASServiceFutureStub[] futureStub;
    private int numFaults;
    private int numServers;
    private boolean sentEcho;
    private boolean sentReady;
    private boolean delivered;
    private HashMap<Integer, Contract.RegisterRequest> echos;
    private HashMap<Integer, Contract.RegisterRequest> readys;

    public AuthenticatedDoubleEchoBroadcast(int numServers, int numFaults, DPASServiceGrpc.DPASServiceFutureStub[] futureStub){
        this.futureStub = futureStub;
        this.numFaults = numFaults;
        this.numServers = numServers;
        this.sentEcho = false;
        this.sentReady = false;
        this.delivered = false;
        this.echos = new HashMap<>(numServers);
        this.readys = new HashMap<>(numServers);
    }
/*
    public void deliver(int serverId, Contract.RegisterRequest request){
        TypeMessage typeMessageReceived = SerializationUtils.deserialize(request.getTypeMessage().toByteArray());

        switch (typeMessageReceived){
            case SEND:
                if(!sentEcho){
                    sentEcho = true;
                    byte[] typeMessage = SerializationUtils.serialize(TypeMessage.ECHO);

                    CountDownLatch latch = new CountDownLatch((numServers + numFaults)/2);

                    for(DPASServiceGrpc.DPASServiceFutureStub stub : this.futureStub){
                        //communicate
                    }

                    try{
                        latch.await();

                    }catch (InterruptedException e){

                    }
                }
                break;
            case ECHO:
                if(!echos.containsKey(serverId)){
                    echos.put(serverId, request);
                    if(!sentReady && getNumEqualMessageECHOs(request) > (numFaults + numServers)/2){
                        sentReady = true;
                        byte[] typeMessage = SerializationUtils.serialize(TypeMessage.READY);

                        for(DPASServiceGrpc.DPASServiceFutureStub stub : this.futureStub){
                            //communicate
                        }
                        wait()
                    }
                }
                break;
            case READY:
                if(!readys.containsKey(serverId)) {
                    readys.put(serverId, request);
                    if(!delivered && getNumEqualMessageREADYs(request) > 2*numFaults){
                        delivered = true;
                        //deliiiiiiiiiiiiiiiiiiiiiiver
                        return;
                    }
                }
                break;
        }
    }

    private int getNumEqualMessageECHOs(Contract.RegisterRequest request){
        int num = 0;
        for(Contract.RegisterRequest r : echos.values()){
            if(r.equals(request)){
                num++;
            }
        }
        return num;
    }

    private int getNumEqualMessageREADYs(Contract.RegisterRequest request){
        int num = 0;
        for(Contract.RegisterRequest r : echos.values()){
            if(r.equals(request)){
                num++;
            }
        }
        return num;
    }

*/
}
