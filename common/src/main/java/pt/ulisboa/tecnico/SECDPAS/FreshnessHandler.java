package pt.ulisboa.tecnico.SECDPAS;

public class FreshnessHandler {

    // A cryptographically secure random number generator.
    private long sequenceNumber;

    public FreshnessHandler(){
        this.sequenceNumber = 0;
    }

    public boolean verifyFreshness(long freshness) {
        return freshness==this.sequenceNumber;
    }

    public long getFreshness() {return this.sequenceNumber; }

    public void incrementFreshness() {this.sequenceNumber++;}

    public void setFreshness(long f){
        this.sequenceNumber = f;
    }
}
