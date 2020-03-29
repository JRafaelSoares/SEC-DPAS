package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;

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

        this.freshnessHandler = new FreshnessHandler(System.currentTimeMillis());
        this.integrityHandler = new IntegrityHandler(sharedHMACKey);
    }

    public MessageHandler(SecretKey sharedHMACKey, long initTime) {
        if(sharedHMACKey != null){
            lastSessionTime = System.currentTimeMillis();
        }

        this.freshnessHandler = new FreshnessHandler(initTime);
        this.integrityHandler = new IntegrityHandler(sharedHMACKey);
    }

    public byte[] getFreshness() {
        return freshnessHandler.getFreshness();
    }

    public byte[] sign(byte[] message, byte[] freshness) {
        return integrityHandler.sign(Bytes.concat(message, freshness));
    }

    public void verifyMessage(byte[] message, byte[] freshness, byte[] signature) throws SignatureNotValidException, MessageNotFreshException/*, SessionInvalidException*/ {
        verifyFreshness(freshness);
        verifySignature(message, freshness, signature);
    }

    public void verifyFreshness(byte[] freshness) throws MessageNotFreshException {
        if(!freshnessHandler.verifyFreshness(freshness)){
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
        this.freshnessHandler = new FreshnessHandler(System.currentTimeMillis());
    }

    public boolean isInSession(){
        if(System.currentTimeMillis() - lastSessionTime > integrityTimeout){
            resetSignature(null);
        }

        return inSession;
    }
}
