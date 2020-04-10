package pt.ulisboa.tecnico.SECDPAS;

public class FreshnessHandler {

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

    public boolean verifyExceptionFreshness(long freshness){
        return (freshness == this.sequenceNumber-1);
    }

    public long getNextFreshness() {
        return sequenceNumber++;
    }

}
