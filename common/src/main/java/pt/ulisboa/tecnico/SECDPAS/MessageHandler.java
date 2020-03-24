package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;

import javax.crypto.*;


public class MessageHandler {
    private FreshnessHandler freshnessHandler;
    private SignatureHandler signatureHandler;
    private IntegrityHandler integrityHandler;
    private boolean inSession = false;

    public MessageHandler(SecretKey sharedHMACKey) {
        this.freshnessHandler = new FreshnessHandler(System.currentTimeMillis());
        this.signatureHandler = new SignatureHandler();
        this.integrityHandler = new IntegrityHandler(sharedHMACKey);
    }

    public MessageHandler(SecretKey sharedHMACKey, long initTime) {
        this.freshnessHandler = new FreshnessHandler(initTime);
        this.signatureHandler = new SignatureHandler();
        this.integrityHandler = new IntegrityHandler(sharedHMACKey);
    }

    public byte[] getFreshness() {
        return freshnessHandler.getFreshness();
    }

    public byte[] sign(byte[] message, byte[] freshness) {
        return integrityHandler.sign(Bytes.concat(message, freshness));
    }

    public void verifyMessage(byte[] message, byte[] freshness, byte[] signature) throws SignatureNotValidException, MessageNotFreshException {
        verifyFreshness(freshness);
        verifySignature(message, freshness, signature);
    }

    public void verifyFreshness(byte[] freshness) throws MessageNotFreshException {
        if(!freshnessHandler.verifyFreshness(freshness)){
            throw new MessageNotFreshException();
        }
    }

    public void verifySignature(byte[] message, byte[] freshness, byte[] signature) throws SignatureNotValidException {
        if(!integrityHandler.verifySignature(Bytes.concat(message, freshness), signature)){
            throw new SignatureNotValidException();
        }
    }

    public void resetSignature(SecretKey sharedHMACKey){
        this.integrityHandler = new IntegrityHandler(sharedHMACKey);

        if(sharedHMACKey != null) {
            this.inSession = true;
        }
    }

    public void resetFreshness(){
        this.freshnessHandler = new FreshnessHandler(System.currentTimeMillis());
    }

    public boolean isInSession(){
        return inSession;
    }
}
