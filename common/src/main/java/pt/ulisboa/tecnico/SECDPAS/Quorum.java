package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.util.concurrent.FutureCallback;

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

                }
            };

            e.getValue().process(request, futureCallback);
        }

        return qr;
    }

    public void waitForQuorum() throws InterruptedException {
        latch.await();
    }

    private void countDownLatch(){
        latch.countDown();
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