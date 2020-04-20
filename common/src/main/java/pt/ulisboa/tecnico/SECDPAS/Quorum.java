package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.common.util.concurrent.FutureCallback;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.SerializationUtils;

import java.util.*;

public class Quorum<Key, Result> {

    private final Map<Key, Result> successes = new HashMap<>();
    private final Map<Key, Throwable> clientExceptions = new HashMap<>();

    static <Key, Result> Quorum<Key, Result> create(Map<Key, AuthenticatedPerfectLink> calls, RequestType request) {
        final Quorum<Key, Result> qr = new Quorum<>();

        Iterator<Map.Entry<Key, AuthenticatedPerfectLink>> iterator = calls.entrySet().iterator();

        for (int i=0; i<calls.size(); i++) {
            final Map.Entry<Key, AuthenticatedPerfectLink> e = iterator.next();

            FutureCallback<Result> futureCallback = new FutureCallback<>() {
                @Override
                public void onSuccess(Result res) {
                    qr.addResult(e.getKey(), res);
                }

                @Override
                public void onFailure(Throwable t) {
                    qr.addException(e.getKey(), t);
                }
            };

            e.getValue().process(request, futureCallback);
        }
        return qr;
    }

    public synchronized int waitForQuorum(int minResponses) throws InterruptedException {
        while (true) {
            if (countResponses() >= minResponses){
                return checkResults(minResponses);
            }
            wait(1);
        }
    }

    private synchronized int checkResults(int numResponses){
        if(successes.size() >= numResponses && equalitySuccesses(numResponses)){
            return 0;
        }
        if(clientExceptions.size() >= numResponses && equalityExceptions(numResponses)){
            return 1;
        }
        return -1;
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

    private synchronized boolean equalityExceptions(int numResponses){
        Iterator<Throwable> iter = clientExceptions.values().iterator();

        StatusRuntimeException value = (StatusRuntimeException) iter.next();

        for (int i = 1; i < numResponses; i++) {
            StatusRuntimeException entry = (StatusRuntimeException) iter.next();
            if (!value.getStatus().getDescription().equals(entry.getStatus().getDescription()) || !value.getStatus().getCode().equals(entry.getStatus().getCode())) {
                return false;
            }
        }
        return true;
    }

    private synchronized void addResult(Key k, Result res) {
        successes.put(k, res);
    }

    private synchronized void addException(Key k, Throwable t) {
        clientExceptions.put(k, t);
    }

    private synchronized int countResponses() {
        return successes.size() + clientExceptions.size();
    }

    public synchronized HashMap<Key, Result> getSuccesses() {
        return new HashMap<>(successes);
    }

    public synchronized HashMap<Key, Throwable> getExceptions() {
        return new HashMap<>(clientExceptions);
    }

    public synchronized Throwable getException() {
        return clientExceptions.values().iterator().next();
    }

    public synchronized Result getResult() {
        return successes.values().iterator().next();
    }
}