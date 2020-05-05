package pt.ulisboa.tecnico.SECDPAS;

import java.io.Serializable;

public class FreshnessHandler implements Serializable {

    // A cryptographically secure random number generator.
    private long sequenceNumber;

    public FreshnessHandler(){
        this.sequenceNumber = 0;
    }

    public boolean verifyFreshness(long freshness) {
        return freshness == this.sequenceNumber;
    }

    public boolean verifyPostFreshness(long freshness) {
        return freshness < sequenceNumber;
    }

    public long getFreshness() {
        return this.sequenceNumber;
    }

    public void incrementFreshness() {
        this.sequenceNumber++;
    }

}
