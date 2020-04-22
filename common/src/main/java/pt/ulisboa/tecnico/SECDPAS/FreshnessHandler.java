package pt.ulisboa.tecnico.SECDPAS;

import java.security.SecureRandom;

public class FreshnessHandler {

    // A cryptographically secure random number generator.
    private static final SecureRandom secureRandom = new SecureRandom();
    private long sequenceNumber;

    public FreshnessHandler(){
        this.sequenceNumber = 0;
    }

    public boolean verifyFreshness(long freshness) {
        if(freshness >= this.sequenceNumber){
            sequenceNumber = freshness + 1;
            return true;
        }else{
            return false;
        }
    }

    // Generate a random byte array for cryptographic use.
    public static byte[] generateRandomBytes(final int size) {
        final byte[] rB = new byte[size];
        secureRandom.nextBytes(rB);
        return rB;
    }

    public boolean verifyExceptionFreshness(long freshness){
        return (freshness == this.sequenceNumber-1);
    }

    public long getNextFreshness() {
        return sequenceNumber++;
    }

}
