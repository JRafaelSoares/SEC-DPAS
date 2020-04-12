package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;

import javax.crypto.*;
import java.util.Arrays;


public class MessageHandler {
    private FreshnessHandler freshnessHandler;
    private IntegrityHandler integrityHandler;
    private IntegrityHandler preparingHandler;

    private byte[] challenge = null;

    private boolean inSession = false;
    private boolean inPreparation = false;

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

    public byte[] calculateHMAC(byte[] message, byte[] freshness) {
        return integrityHandler.calculateHMAC(Bytes.concat(message, freshness));
    }

    public void verifyMessage(byte[] message, long freshness, byte[] hmac) throws SignatureNotValidException, MessageNotFreshException/*, SessionInvalidException*/ {
        verifyIntegrity(message, Longs.toByteArray(freshness), hmac);
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

    public void verifyIntegrity(byte[] message, byte[] freshness, byte[] hmac) throws SignatureNotValidException/*, SessionInvalidException*/ {
        if(System.currentTimeMillis() - lastSessionTime > integrityTimeout){
            resetHMAC(null);
            //throw new SessionInvalidException();
        }

        if(!integrityHandler.verifyHMAC(Bytes.concat(message, freshness), hmac)){
            throw new SignatureNotValidException();
        }
    }

    public void verifyPreparingIntegrity(byte[] message, byte[] freshness, byte[] hmac) throws SignatureNotValidException/*, SessionInvalidException*/ {
        if(!preparingHandler.verifyHMAC(Bytes.concat(message, freshness), hmac)){
            throw new SignatureNotValidException();
        }
    }

    public void prepareNewIntegrityHandler(SecretKey sharedHMACKey, byte[] serverChallenge){
        this.preparingHandler = new IntegrityHandler(sharedHMACKey);
        this.challenge = serverChallenge;

        this.inPreparation = true;
    }

    public boolean completePreparation(byte[] clientResponse){
        if(!inPreparation || !Arrays.equals(clientResponse, challenge)){
            this.inPreparation = false;
            return false;
        }

        this.integrityHandler = this.preparingHandler;
        this.lastSessionTime = System.currentTimeMillis();
        this.inPreparation = false;
        this.inSession = true;
        this.preparingHandler = null;

        return true;
    }

    public void resetHMAC(SecretKey sharedHMACKey){
        this.integrityHandler = new IntegrityHandler(sharedHMACKey);

        if(sharedHMACKey != null) {
            this.inSession = true;
            this.lastSessionTime = System.currentTimeMillis();
        }
        else{
            this.inSession = false;
            this.inPreparation = false;
        }
    }

    public void resetFreshness(){
        this.freshnessHandler = new FreshnessHandler();
    }

    public boolean isInSession(){
        if(System.currentTimeMillis() - lastSessionTime > integrityTimeout){
            this.inPreparation = false;
            resetHMAC(null);
        }

        return inSession;
    }
}
