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

    public static final long NONCE_REFRESH = 20 * 60 * 1000;
    public static final int NONCE_SIZE = 8;

    private long initialTime;
    private HashMap<ByteBuffer, Long> usedNonces;


    public FreshnessHandler(){
        this.usedNonces = new HashMap<>();

        this.initialTime = System.currentTimeMillis();
    }

    public boolean verifyFreshness(byte[] freshness) {
        if(freshness == null || freshness.length != NONCE_SIZE + Long.BYTES){
            return false;
        }

        byte[] nonce = Arrays.copyOfRange(freshness, 0, NONCE_SIZE);
        long messageTimestamp = Longs.fromByteArray(Arrays.copyOfRange(freshness, NONCE_SIZE, NONCE_SIZE + Long.BYTES));

        long delta = System.currentTimeMillis() - messageTimestamp;

        if(delta > NONCE_REFRESH || messageTimestamp < initialTime){
            System.out.println("2");
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
            return false;
        }

        return true;
    }

    public byte[] getFreshness() {
        Long timestamp;
        byte[] nonce;

        do{
            // Generate nonce
            nonce = generateRandomBytes(NONCE_SIZE);
            timestamp = System.currentTimeMillis();
        } while(usedNonces.putIfAbsent(ByteBuffer.wrap(nonce), timestamp) != null);

        return Bytes.concat(nonce, Longs.toByteArray(timestamp));
    }

    // Generate a random byte array for cryptographic use.
    private byte[] generateRandomBytes(final int size) {
        final byte[] rB = new byte[size];
        secureRandom.nextBytes(rB);
        return rB;
    }
}
