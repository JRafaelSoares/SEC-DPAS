package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;

import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class MessageHandler {
    private FreshnessHandler freshnessHandler;
    private SignatureHandler signatureHandler;
    private boolean inSession = false;

    public MessageHandler(SecretKey sharedHMACKey) {
        this.freshnessHandler = new FreshnessHandler();
        this.signatureHandler = new SignatureHandler(sharedHMACKey);
    }

    public byte[] getFreshness() {
        return freshnessHandler.getFreshness();
    }

    public byte[] sign(byte[] message, byte[] freshness) {
        return signatureHandler.sign(Bytes.concat(message, freshness));
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
        if(!signatureHandler.verifySignature(Bytes.concat(message, freshness), signature)){
            throw new SignatureNotValidException();
        }
    }

    public void resetSignature(SecretKey sharedHMACKey){
        System.out.println("\tHello");
        this.signatureHandler = new SignatureHandler(sharedHMACKey);

        if(sharedHMACKey != null) {
            this.inSession = true;
        }
    }

    public void resetFreshness(){
        this.freshnessHandler = new FreshnessHandler();
    }

    public boolean isInSession(){
        return inSession;
    }
}
