package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.FutureCallback;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.SerializationUtils;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

public class Quorum<Key, Result> {

    private final Map<Key, Result> successes = new ConcurrentHashMap<>();
    private CountDownLatch latch;

    private Quorum(int minResponses){
        latch = new CountDownLatch(minResponses);
    }

    static <Key, Result> Quorum<Key, Result> create(Map<Key, AuthenticatedPerfectLink> calls, RequestType request, int minResponses) {
        final Quorum<Key, Result> qr = new Quorum<>(minResponses);

        for (Map.Entry<Key, AuthenticatedPerfectLink> e : calls.entrySet()) {
            FutureCallback<Result> futureCallback = new FutureCallback<>() {
                @Override
                public void onSuccess(Result res) {
                    qr.addResult(e.getKey(), res);
                    qr.countDownLatch();
                }

                @Override
                public void onFailure(Throwable t) {
                    qr.countDownLatch();
                }
            };

            e.getValue().process(request, futureCallback);
        }

        return qr;
    }

    public boolean waitForQuorum() throws InterruptedException {
        latch.await();
        return true;
    }

    private void countDownLatch(){
        latch.countDown();
    }

    private synchronized boolean equalitySuccesses(int numResponses){
        Iterator<Result> iter = successes.values().iterator();

        Result value = iter.next();

        for (int i = 1; i < numResponses; i++) {
            Result entry = iter.next();
            if(value instanceof Contract.ACK){
                if(!(entry instanceof Contract.ACK)){
                    System.out.println("not both ack");
                    return false;
                }
            }
            if(value instanceof Contract.ReadResponse){
                if(!(entry instanceof Contract.ReadResponse)){
                    System.out.println("not both read response");
                    return false;
                }else{
                    Contract.ReadResponse v = (Contract.ReadResponse) value;
                    Contract.ReadResponse e = (Contract.ReadResponse) entry;
                    Announcement[] announcementsValues = SerializationUtils.deserialize(v.getAnnouncements().toByteArray());
                    Announcement[] announcementsEntry = SerializationUtils.deserialize(e.getAnnouncements().toByteArray());

                    if(announcementsEntry.length != announcementsValues.length){
                        System.out.println("size different: " + announcementsEntry.length + " vs " + announcementsValues.length);
                        return false;
                    }
                    for(int j = 0; j < announcementsValues.length; j++){
                        if(!announcementsEntry[j].equals(announcementsValues[j])){
                            System.out.println("announcements different: " + announcementsEntry[j] + " vs " + announcementsValues[j]);
                            System.out.println("\n\n\n" + new String(announcementsEntry[j].getPost()) + " vs " + new String(announcementsValues[j].getPost()) + "\n\n\n");
                            return false;
                        }
                    }
                }
            }
        }

        return true;
    }

    private void addResult(Key k, Result res) {
        synchronized (successes){
            successes.put(k, res);
        }

    }

    public HashMap<Key, Result> getSuccesses() {
        synchronized (successes){
            return new HashMap<>(successes);
        }
    }
}