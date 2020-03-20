package pt.ulisboa.tecnico.SECDPAS;

public class SignatureNotValidException extends Exception {
    public SignatureNotValidException(){
        super("Signature not valid");
    }
}
