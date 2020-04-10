package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;

import javax.crypto.*;


public class MessageHandler {
    private FreshnessHandler freshnessHandler;
    private IntegrityHandler integrityHandler;
    private boolean inSession = false;

    private static final long integrityTimeout = 24 * 60 * 60 * 1000;
    private long lastSessionTime;

    public MessageHandler(SecretKey sharedHMACKey) {
        if(sharedHMACKey != null){
            lastSessionTime = System.currentTimeMillis();
        }

        this.freshnessHandler = new FreshnessHandler();
        this.integrityHandler = new IntegrityHandler(sharedHMACKey);
    }

    public long getFreshness() {
        return freshnessHandler.getNextFreshness();
    }

    public byte[] sign(byte[] message, byte[] freshness) {
        return integrityHandler.sign(Bytes.concat(message, freshness));
    }

    public void verifyMessage(byte[] message, long freshness, byte[] signature) throws SignatureNotValidException, MessageNotFreshException/*, SessionInvalidException*/ {
        verifySignature(message, Longs.toByteArray(freshness), signature);
        verifyFreshness(freshness);
    }

    public void verifyFreshness(long freshness) throws MessageNotFreshException {
        if(!freshnessHandler.verifyFreshness(freshness)){
            throw new MessageNotFreshException();
        }
    }

    public void verifyExceptionFreshness(long freshness) throws MessageNotFreshException {
        if(!freshnessHandler.verifyExceptionFreshness(freshness)){
            throw new MessageNotFreshException();
        }
    }

    public void verifySignature(byte[] message, byte[] freshness, byte[] signature) throws SignatureNotValidException/*, SessionInvalidException*/ {
        if(System.currentTimeMillis() - lastSessionTime > integrityTimeout){
            resetSignature(null);
            //throw new SessionInvalidException();
        }

        if(!integrityHandler.verifySignature(Bytes.concat(message, freshness), signature)){
            throw new SignatureNotValidException();
        }
    }

    public void resetSignature(SecretKey sharedHMACKey){
        this.integrityHandler = new IntegrityHandler(sharedHMACKey);

        if(sharedHMACKey != null) {
            this.inSession = true;
            this.lastSessionTime = System.currentTimeMillis();
        }
        else{
            this.inSession = false;
        }
    }

    public void resetFreshness(){
        this.freshnessHandler = new FreshnessHandler();
    }

    public boolean isInSession(){
        if(System.currentTimeMillis() - lastSessionTime > integrityTimeout){
            resetSignature(null);
        }

        return inSession;
    }
}
