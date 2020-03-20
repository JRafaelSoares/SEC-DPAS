package pt.ulisboa.tecnico.SECDPAS;

public class ServerInvalidSignatureException extends Exception {
    public ServerInvalidSignatureException() {
        super();
    }

    public ServerInvalidSignatureException(String message) {
        super(message);
    }
}
