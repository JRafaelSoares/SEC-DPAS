package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;

public class FreshnessHandler {

    // A cryptographically secure random number generator.
    private final SecureRandom secureRandom = new SecureRandom();

    public long NONCE_REFRESH = 20 * 60 * 1000;
    public static final int NONCE_SIZE = 8;

    private long initialTime;
    private HashMap<ByteBuffer, Long> usedNonces;
    private long garbageCollectorTime;

    public FreshnessHandler(long initTime){
        this.usedNonces = new HashMap<>();

        this.initialTime = initTime;
        this.garbageCollectorTime = initTime;
    }

    public boolean verifyFreshness(byte[] freshness) {
        synchronized (this){
            if(freshness == null || freshness.length != NONCE_SIZE + Long.BYTES){
                return false;
            }

            byte[] nonce = Arrays.copyOfRange(freshness, 0, NONCE_SIZE);
            long messageTimestamp = Longs.fromByteArray(Arrays.copyOfRange(freshness, NONCE_SIZE, NONCE_SIZE + Long.BYTES));

            long delta = System.currentTimeMillis() - messageTimestamp;

            if(delta > NONCE_REFRESH || messageTimestamp < initialTime){
                checkGarbageColletor();
                return false;
            }

            ByteBuffer wrappedNonce = ByteBuffer.wrap(nonce);
            Long timestamp = usedNonces.get(wrappedNonce);

            if(timestamp == null){
                usedNonces.put(wrappedNonce, messageTimestamp);
            }
            else if(System.currentTimeMillis() - timestamp > NONCE_REFRESH){
                // old nonce to be replaced
                usedNonces.replace(wrappedNonce, messageTimestamp);
            }
            else{
                checkGarbageColletor();
                return false;
            }

            checkGarbageColletor();
            return true;
        }
    }

    public byte[] getFreshness() {
        synchronized (this){

        Long timestamp;
        byte[] nonce;

        do{
            // Generate nonce
            nonce = generateRandomBytes(NONCE_SIZE);
            timestamp = System.currentTimeMillis();
        } while(usedNonces.putIfAbsent(ByteBuffer.wrap(nonce), timestamp) != null);

        return Bytes.concat(nonce, Longs.toByteArray(timestamp));
        }

    }

    // Generate a random byte array for cryptographic use.
    private byte[] generateRandomBytes(final int size) {
        final byte[] rB = new byte[size];
        secureRandom.nextBytes(rB);
        return rB;
    }

    private void noncesGarbageCollector(){
        HashMap<ByteBuffer, Long> validNonces = new HashMap<>();

        for(ByteBuffer nonce : usedNonces.keySet()){
            long delta = System.currentTimeMillis() - usedNonces.get(nonce);

            if(delta < NONCE_REFRESH*2){
                validNonces.put(nonce, usedNonces.get(nonce));
            }
        }

        this.usedNonces = validNonces;
    }

    private void checkGarbageColletor(){
        if(System.currentTimeMillis() - this.garbageCollectorTime > NONCE_REFRESH*2){
            noncesGarbageCollector();
        }
    }

    /************************/
    /**  Testing Purposes  **/
    /************************/

    public void setNonceRefresh(long nonceRefresh){
        this.NONCE_REFRESH = nonceRefresh;

    }

    public HashMap<ByteBuffer, Long> getUsedNonces(){
        synchronized (this){
            return this.usedNonces;
        }
    }

}
